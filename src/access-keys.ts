/**
 * Access-key login gate.
 *
 * The operator hands out one key per person. Before the Telegram QR is shown,
 * `/oauth/authorize` asks for that key; the first Telegram account that finishes
 * QR login with it is bound to the key's label, and every later login, token
 * exchange, token refresh and MCP request re-checks that the binding is still
 * backed by a key listed in `ACCESS_KEYS`.
 *
 * What the server holds:
 *  - `ACCESS_KEYS` env: `label:sha256hex` pairs. Plain keys never reach the server.
 *  - `access_key_bindings` table: label, numeric Telegram user id, and the
 *    SHA-256 of the key that was bound (the same public value already listed in
 *    `ACCESS_KEYS`). Keeping the hash lets the gate notice a label that was
 *    re-issued with a NEW key: the old person is cut off and the new key can bind.
 *  - In-memory, short-lived "key tickets" that carry a verified label from the
 *    key form to the QR stream (HttpOnly cookie, 15 min).
 *
 * Revocation: remove the label from `ACCESS_KEYS` and redeploy. The next MCP
 * request or token refresh of that user fails, and their stored Telegram session
 * and OAuth tokens are deleted on that contact.
 */
import type { Database } from "bun:sqlite";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** Labels: lowercase, digits, `-`/`_`, max 64 chars (e.g. `person-1`). */
export const ACCESS_LABEL_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/** How long a verified key stays usable for the QR step. */
export const KEY_TICKET_TTL_MS = 15 * 60_000;
/** Cookie that carries the key ticket from the key form to the QR stream. */
export const KEY_TICKET_COOKIE = "ak_ticket";
/** Double-submit CSRF cookie for the key form. */
export const KEY_CSRF_COOKIE = "ak_csrf";

/** Failed key attempts allowed per IP per window before the IP is blocked. */
export const KEY_FAIL_LIMIT = 5;
export const KEY_FAIL_WINDOW_MS = 15 * 60_000;

/**
 * Normalize what a person typed: case-insensitive, and spaces / dashes are
 * decoration (keys are printed as `abcd-efgh-jkmn-pqrs`). The generator script
 * hashes the same normalized form.
 */
export function normalizeAccessKey(input: string): string {
  return input.toLowerCase().replace(/[\s-]+/g, "");
}

/** SHA-256 hex of the normalized key — the value listed in `ACCESS_KEYS`. */
export function hashAccessKey(plain: string): string {
  return createHash("sha256").update(normalizeAccessKey(plain), "utf8").digest("hex");
}

/**
 * Parse `ACCESS_KEYS` (`label:sha256hex,label:sha256hex,…`). Whitespace and
 * empty entries are ignored. Malformed entries throw at boot: a typo must not
 * silently lock someone out or, worse, leave the gate half-configured. Error
 * messages name the entry position and label, never the hash.
 */
export function parseAccessKeys(raw: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!raw?.trim()) return out;
  const entries = raw
    .split(/[,\n]/)
    .map((e) => e.trim())
    .filter(Boolean);
  entries.forEach((entry, i) => {
    const sep = entry.indexOf(":");
    if (sep <= 0) throw new Error(`ACCESS_KEYS entry #${i + 1} is not in label:sha256hex form.`);
    const label = entry.slice(0, sep).trim();
    const hash = entry
      .slice(sep + 1)
      .trim()
      .toLowerCase();
    if (!ACCESS_LABEL_RE.test(label)) {
      throw new Error(`ACCESS_KEYS entry #${i + 1}: label must match ${ACCESS_LABEL_RE} (lowercase, digits, - or _).`);
    }
    if (!SHA256_HEX_RE.test(hash)) {
      throw new Error(`ACCESS_KEYS entry #${i + 1} (${label}): hash must be 64 lowercase hex characters (SHA-256).`);
    }
    if (out.has(label)) throw new Error(`ACCESS_KEYS lists label "${label}" twice.`);
    out.set(label, hash);
  });
  return out;
}

/**
 * Boot-time guard. With no keys configured the server would let ANY Telegram
 * account sign in, so production refuses to start unless the operator opted
 * in to that explicitly with `ALLOW_OPEN_SIGNUP=1`.
 */
export function assertAccessGateConfig(opts: {
  nodeEnv: string | undefined;
  keyCount: number;
  allowOpenSignup: boolean;
}) {
  if (opts.keyCount > 0 || opts.allowOpenSignup) return;
  if (opts.nodeEnv === "production") {
    throw new Error(
      "ACCESS_KEYS is empty: refusing to start in production because anyone could sign in. " +
        "Generate keys with `bun scripts/make-access-keys.ts --count 30 --prefix person` and set ACCESS_KEYS, " +
        "or set ALLOW_OPEN_SIGNUP=1 to run an open server on purpose.",
    );
  }
}

export type BindResult = "ok" | "conflict" | "revoked";

interface BindingRow {
  label: string;
  telegram_id: string;
  key_hash: string;
}

/** What the gate needs from SessionManager (kept narrow for tests). */
export interface AccessSessions {
  getPrimaryTelegramId(userId: string): string | null;
}

export class AccessGate {
  private readonly keys: Map<string, Buffer>;
  private readonly tickets = new Map<string, { label: string; expiresAt: number }>();
  private readonly failures = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly db: Database,
    keys: Map<string, string>,
    private readonly opts: { allowOpenSignup?: boolean } = {},
  ) {
    this.keys = new Map([...keys].map(([label, hex]) => [label, Buffer.from(hex, "hex")]));
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS access_key_bindings (
        label TEXT PRIMARY KEY,
        telegram_id TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        bound_at TEXT DEFAULT (datetime('now'))
      )
    `);
  }

  /**
   * Gate active? Keys configured ⇒ yes. No keys ⇒ only off when open signup was
   * chosen explicitly; otherwise the gate stays on and nobody can get in
   * (fail closed — production refuses to boot in that state anyway).
   */
  get enabled(): boolean {
    return this.keys.size > 0 || !this.opts.allowOpenSignup;
  }

  get labelCount(): number {
    return this.keys.size;
  }

  /**
   * Label for a typed key, or null. Compares the SHA-256 against EVERY listed
   * hash with `timingSafeEqual` and never exits early, so timing reveals neither
   * which label matched nor how many characters did.
   */
  verify(plain: string): string | null {
    const candidate = createHash("sha256").update(normalizeAccessKey(plain), "utf8").digest();
    let match: string | null = null;
    for (const [label, hash] of this.keys) {
      if (timingSafeEqual(candidate, hash) && match === null) match = label;
    }
    return match;
  }

  /**
   * Bind `label` to the Telegram account that just proved itself with a QR scan.
   * - label no longer listed ⇒ "revoked";
   * - label already bound to another account under the CURRENT key ⇒ "conflict"
   *   (the key was shared);
   * - unbound, bound to this account, or bound under an older key (re-issued) ⇒ "ok".
   */
  bind(label: string, telegramId: string): BindResult {
    const hash = this.keys.get(label);
    if (!hash) return "revoked";
    const hex = hash.toString("hex");
    const tx = this.db.transaction((): BindResult => {
      const row = this.db
        .prepare("SELECT label, telegram_id, key_hash FROM access_key_bindings WHERE label = ?")
        .get(label) as BindingRow | null;
      if (row && row.telegram_id !== telegramId && row.key_hash === hex) return "conflict";
      this.db
        .prepare(
          `INSERT INTO access_key_bindings (label, telegram_id, key_hash) VALUES (?, ?, ?)
           ON CONFLICT(label) DO UPDATE SET telegram_id = excluded.telegram_id,
             key_hash = excluded.key_hash, bound_at = datetime('now')`,
        )
        .run(label, telegramId, hex);
      return "ok";
    });
    return tx();
  }

  /** A Telegram account may use the server iff a binding of it is backed by a listed key. */
  isTelegramIdAllowed(telegramId: string): boolean {
    if (!this.enabled) return true;
    const rows = this.db
      .prepare("SELECT label, telegram_id, key_hash FROM access_key_bindings WHERE telegram_id = ?")
      .all(telegramId) as BindingRow[];
    return rows.some((r) => this.keys.get(r.label)?.toString("hex") === r.key_hash);
  }

  /** Same check for an OAuth user id (session row key) — resolves its numeric Telegram id. */
  isUserAllowed(userId: string, sessions: AccessSessions): boolean {
    if (!this.enabled) return true;
    const telegramId = sessions.getPrimaryTelegramId(userId);
    return telegramId !== null && this.isTelegramIdAllowed(telegramId);
  }

  /** Drop bindings whose label was removed or re-issued. Returns rows deleted. Run at boot. */
  pruneStaleBindings(): number {
    const rows = this.db.prepare("SELECT label, telegram_id, key_hash FROM access_key_bindings").all() as BindingRow[];
    let removed = 0;
    for (const r of rows) {
      if (this.keys.get(r.label)?.toString("hex") !== r.key_hash) {
        this.db.prepare("DELETE FROM access_key_bindings WHERE label = ?").run(r.label);
        removed++;
      }
    }
    return removed;
  }

  // ─── Key tickets (key form → QR stream) ──────────────────────────────

  issueTicket(label: string, now = Date.now()): string {
    this.sweep(now);
    const ticket = randomBytes(32).toString("hex");
    this.tickets.set(ticket, { label, expiresAt: now + KEY_TICKET_TTL_MS });
    return ticket;
  }

  /** Label of a live ticket whose key is still listed, else null. Not consumed. */
  ticketLabel(ticket: string | undefined, now = Date.now()): string | null {
    if (!ticket) return null;
    const t = this.tickets.get(ticket);
    if (!t) return null;
    if (t.expiresAt <= now || !this.keys.has(t.label)) {
      this.tickets.delete(ticket);
      return null;
    }
    return t.label;
  }

  consumeTicket(ticket: string | undefined): void {
    if (ticket) this.tickets.delete(ticket);
  }

  // ─── Failed-attempt limiter (per IP) ─────────────────────────────────

  isBlocked(ip: string, now = Date.now()): boolean {
    const f = this.failures.get(ip);
    if (!f) return false;
    if (f.resetAt <= now) {
      this.failures.delete(ip);
      return false;
    }
    return f.count >= KEY_FAIL_LIMIT;
  }

  recordFailure(ip: string, now = Date.now()): void {
    const f = this.failures.get(ip);
    if (!f || f.resetAt <= now) this.failures.set(ip, { count: 1, resetAt: now + KEY_FAIL_WINDOW_MS });
    else f.count += 1;
  }

  private sweep(now: number): void {
    for (const [k, t] of this.tickets) if (t.expiresAt <= now) this.tickets.delete(k);
    for (const [k, f] of this.failures) if (f.resetAt <= now) this.failures.delete(k);
  }
}

/**
 * Cut a user off: log the Telegram session out and delete it, then revoke every
 * OAuth token. Used when a request arrives for a user whose key was revoked.
 */
export async function cutOffUser(
  userId: string,
  sessions: { destroyUserSession(userId: string): Promise<unknown> },
  oauth: { revokeAllUserTokens(userId: string): number },
): Promise<void> {
  try {
    await sessions.destroyUserSession(userId);
  } finally {
    oauth.revokeAllUserTokens(userId);
  }
}

/** Value of one cookie from a Cookie header (no decoding: our values are hex). */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

/** Constant-time string equality for CSRF tokens. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
