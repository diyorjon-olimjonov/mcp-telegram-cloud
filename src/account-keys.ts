/**
 * Personal access keys, issued automatically: one per Telegram account.
 *
 * Active when the server runs WITHOUT pre-issued keys (ALLOW_OPEN_SIGNUP=1, no
 * ACCESS_KEYS). The first time an account finishes a QR login, a key is made for
 * it and shown ONCE on that page. The key signs the browser in to the website
 * settings (/my/key → /my/chats) without another QR scan.
 *
 * Only the SHA-256 of the key is stored, so nobody (admin included) can read a
 * key back. A forgotten key is replaced by the admin with
 * `bun scripts/reset-account-key.ts <@username | telegram id>`, which prints a
 * new key and invalidates the old one.
 */
import type { Database } from "bun:sqlite";
import { randomInt } from "node:crypto";
import { hashAccessKey } from "./access-keys.js";

/** No look-alikes: drops 0/o, 1/l/i. 31 symbols, 16 chars ≈ 79 bits. */
export const ACCOUNT_KEY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";

/** `xxxx-xxxx-xxxx-xxxx` from a CSPRNG. */
export function generateAccountKey(): string {
  const groups: string[] = [];
  for (let g = 0; g < 4; g++) {
    let s = "";
    for (let i = 0; i < 4; i++) s += ACCOUNT_KEY_ALPHABET[randomInt(ACCOUNT_KEY_ALPHABET.length)];
    groups.push(s);
  }
  return groups.join("-");
}

export class AccountKeys {
  constructor(private readonly db: Database) {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS account_keys (
        telegram_id TEXT PRIMARY KEY,
        key_hash TEXT NOT NULL UNIQUE,
        created_at TEXT DEFAULT (datetime('now'))
      )
    `);
  }

  /** Does this account already have a key? */
  has(telegramId: string): boolean {
    return this.db.prepare("SELECT 1 FROM account_keys WHERE telegram_id = ?").get(telegramId) != null;
  }

  /**
   * First key for an account: returns the plain key to show once, or null when
   * the account already has one (it is never shown again).
   */
  issue(telegramId: string): string | null {
    const key = generateAccountKey();
    const res = this.db
      .prepare("INSERT OR IGNORE INTO account_keys (telegram_id, key_hash) VALUES (?, ?)")
      .run(telegramId, hashAccessKey(key));
    return res.changes === 1 ? key : null;
  }

  /** Replace an account's key (admin reset). The old key stops working at once. */
  reset(telegramId: string): string {
    const key = generateAccountKey();
    this.db
      .prepare(
        `INSERT INTO account_keys (telegram_id, key_hash) VALUES (?, ?)
         ON CONFLICT(telegram_id) DO UPDATE SET key_hash = excluded.key_hash, created_at = datetime('now')`,
      )
      .run(telegramId, hashAccessKey(key));
    return key;
  }

  /**
   * Telegram id that owns the typed key, or null. Looked up by its SHA-256: the
   * key has ~79 bits of entropy, so the hash reveals nothing usable and an
   * indexed equality lookup leaks nothing a guesser could exploit.
   */
  verify(plain: string): string | null {
    const row = this.db.prepare("SELECT telegram_id FROM account_keys WHERE key_hash = ?").get(hashAccessKey(plain)) as
      | { telegram_id: string }
      | null
      | undefined;
    return row?.telegram_id ?? null;
  }
}
