/**
 * Access-key login gate (src/access-keys.ts + routes/oauth.tsx + routes/mcp.ts).
 *
 * Real OAuthProvider, real routes, real SQLite (in memory); only the Telegram
 * layer is a double, and the QR scan itself is stubbed through `qrRunner`.
 */
process.env.TELEGRAM_API_ID ??= "1";
process.env.TELEGRAM_API_HASH ??= "test";
process.env.ISSUER ??= "https://test.invalid";
process.env.MCP_TELEGRAM_TELEMETRY ??= "off";

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Hono } from "hono";

const { Database } = await import("bun:sqlite");
const { OAuthProvider } = await import("../oauth.js");
const { createOAuthRoutes } = await import("../routes/oauth.js");
const { registerMcpRoutes } = await import("../routes/mcp.js");
const { createLoginRoutes } = await import("../routes/login.js");
const { createAccountsRoutes } = await import("../routes/accounts.js");
const { qrRunner } = await import("../qr-login.js");
const { config } = await import("../config.js");
const { AccessGate, assertAccessGateConfig, hashAccessKey, parseAccessKeys, KEY_FAIL_LIMIT } = await import(
  "../access-keys.js"
);

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ISSUER = config.issuer;
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const KEY_1 = "abcd-efgh-jkmn-pqrs";
const KEY_2 = "wxyz-2345-6789-abcd";

const realRun = qrRunner.run;
afterEach(() => {
  qrRunner.run = realRun;
});

type Me = { id: number; username?: string; firstName?: string };

/** SessionManager double: an in-memory table of saved sessions keyed like the real one. */
function fakeSessions() {
  const saved = new Map<string, { session: string; telegramId: string }>();
  const destroyed: string[] = [];
  const loggedOut: number[] = [];
  let me: Me = { id: 111, username: "alice" };
  const telegramFor = (who: Me) => ({
    setSessionString: () => {},
    connect: async () => {},
    getMe: async () => who,
    logOut: async () => {
      loggedOut.push(who.id);
      return true;
    },
    disconnect: async () => {},
  });
  const sessions = {
    createTempTelegram: () => telegramFor(me),
    resolveAccountKey: async (m: Me) => m.username ?? String(m.id),
    saveSessionString: (userId: string, session: string, telegramId: string) => {
      saved.set(userId, { session, telegramId });
    },
    adoptSession: async () => {},
    getSavedUserIds: () => [...saved.keys()],
    tryReconnectSession: async (userId: string) => (saved.has(userId) ? telegramFor(me) : null),
    getPrimaryTelegramId: (userId: string) => saved.get(userId)?.telegramId ?? null,
    destroyUserSession: async (userId: string) => {
      destroyed.push(userId);
      saved.delete(userId);
      return { loggedOut: true };
    },
    isReviewAccount: () => false,
  };
  return {
    sessions,
    saved,
    destroyed,
    loggedOut,
    scanAs: (m: Me) => {
      me = m;
    },
  };
}

function setup(keys: Record<string, string> = { "person-1": KEY_1, "person-2": KEY_2 }) {
  const db = new Database(":memory:");
  const oauth = new OAuthProvider({ issuer: ISSUER, db });
  const fake = fakeSessions();
  const gateFor = (k: Record<string, string>) =>
    new AccessGate(db, new Map(Object.entries(k).map(([label, key]) => [label, hashAccessKey(key)])));
  const access = gateFor(keys);
  const app = new Hono();
  app.route("/oauth", createOAuthRoutes({ oauth, sessions: fake.sessions as never, access }));
  const clientId = oauth.registerClient({ redirect_uris: [REDIRECT], client_name: "Claude" }).client_id as string;
  const bindings = () => (db.prepare("SELECT COUNT(*) AS n FROM access_key_bindings").get() as { n: number }).n;
  return { db, oauth, fake, access, app, clientId, bindings, gateFor };
}

/** Unique IP per scenario so the process-wide OAuth limiter never trips across test files. */
const ipFor = () =>
  `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

function authorizeQuery(clientId: string): string {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    state: "st",
  }).toString();
}

function cookieValue(res: Response, name: string): string | undefined {
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const [k, v] = (pair ?? "").split("=");
    if (k === name) return v;
  }
  return undefined;
}

/** GET the key page, then POST a key. Returns the POST response. */
async function submitKey(s: ReturnType<typeof setup>, key: string, ip: string): Promise<Response> {
  const page = await s.app.request(`/oauth/authorize?${authorizeQuery(s.clientId)}`, { headers: { "x-real-ip": ip } });
  const html = await page.text();
  const csrf = cookieValue(page, "ak_csrf");
  assert.ok(csrf, "key page sets a CSRF cookie");
  assert.match(html, new RegExp(`name="csrf" value="${csrf}"`));
  const body = new URLSearchParams({
    csrf,
    client_id: s.clientId,
    redirect_uri: REDIRECT,
    state: "st",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    access_key: key,
  });
  return s.app.request("/oauth/authorize/key", {
    method: "POST",
    headers: {
      origin: ISSUER,
      "content-type": "application/x-www-form-urlencoded",
      cookie: `ak_csrf=${csrf}`,
      "x-real-ip": ip,
    },
    body,
  });
}

/** Full QR stream with a stubbed scan; returns the SSE text. */
async function runQr(s: ReturnType<typeof setup>, ticket: string | undefined, ip: string): Promise<Response> {
  qrRunner.run = async () => ({ ok: true, sessionString: "stub-session" }) as never;
  return s.app.request(`/oauth/authorize/qr?${authorizeQuery(s.clientId)}`, {
    headers: { cookie: ticket ? `ak_ticket=${ticket}` : "", "x-real-ip": ip },
  });
}

async function exchange(s: ReturnType<typeof setup>, sse: string) {
  const m = sse.match(/event: redirect\ndata: (.*)\n/);
  assert.ok(m, `expected a redirect event, got: ${sse.slice(0, 300)}`);
  const code = new URL(JSON.parse(m[1] as string).url).searchParams.get("code") ?? "";
  return s.app.request("/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-real-ip": ipFor() },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: s.clientId,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    }),
  });
}

/** Key → QR → token for the given Telegram account. */
async function connect(s: ReturnType<typeof setup>, key: string, me: Me) {
  const ip = ipFor();
  const posted = await submitKey(s, key, ip);
  assert.equal(posted.status, 303);
  const ticket = cookieValue(posted, "ak_ticket");
  s.fake.scanAs(me);
  const sse = await (await runQr(s, ticket, ip)).text();
  return { sse, ticket };
}

describe("access keys — parsing and boot guard", () => {
  it("parses label:sha256 pairs and rejects malformed entries without echoing hashes", () => {
    const h = hashAccessKey(KEY_1);
    assert.deepEqual([...parseAccessKeys(` person-1:${h} , `).entries()], [["person-1", h]]);
    assert.throws(() => parseAccessKeys("person-1"), /entry #1/);
    assert.throws(() => parseAccessKeys("Person 1:abc"), /label/);
    assert.throws(() => parseAccessKeys(`a:${h},a:${h}`), /twice/);
    try {
      parseAccessKeys("person-1:nothex");
    } catch (e) {
      assert.ok(!(e as Error).message.includes("nothex"), "error must not echo the hash value");
    }
  });

  it("keys are case/dash-insensitive (normalized before hashing)", () => {
    assert.equal(hashAccessKey("ABCD EFGH-JKMN-pqrs"), hashAccessKey(KEY_1));
  });

  it("empty ACCESS_KEYS refuses to start in production unless ALLOW_OPEN_SIGNUP=1", () => {
    assert.throws(
      () => assertAccessGateConfig({ nodeEnv: "production", keyCount: 0, allowOpenSignup: false }),
      /ACCESS_KEYS is empty/,
    );
    assertAccessGateConfig({ nodeEnv: "production", keyCount: 0, allowOpenSignup: true });
    assertAccessGateConfig({ nodeEnv: "production", keyCount: 3, allowOpenSignup: false });
  });

  it("the real server process exits with a clear error when ACCESS_KEYS is empty in production", {
    timeout: 90_000,
  }, () => {
    const dir = mkdtempSync(join(tmpdir(), "ak-boot-"));
    const res = spawnSync(process.execPath, ["src/server.tsx"], {
      cwd: ROOT,
      env: {
        PATH: process.env.PATH ?? "",
        NODE_ENV: "production",
        ISSUER: "https://boot.invalid",
        TELEGRAM_API_ID: "1",
        TELEGRAM_API_HASH: "x",
        ACCESS_KEYS: "",
        DATABASE_PATH: join(dir, "cloud.db"),
        PORT: "0",
        MCP_TELEGRAM_TELEMETRY: "off",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.notEqual(res.status, 0, "must not keep running");
    assert.match(`${res.stderr}${res.stdout}`, /ACCESS_KEYS is empty: refusing to start in production/);
    assert.ok(!existsSync(join(dir, "cloud.db")), "refuses before opening the database");
  });

  it("with no keys and no opt-in the gate fails closed", () => {
    const gate = new AccessGate(new Database(":memory:"), new Map());
    assert.equal(gate.enabled, true);
    assert.equal(gate.verify(KEY_1), null);
    assert.equal(new AccessGate(new Database(":memory:"), new Map(), { allowOpenSignup: true }).enabled, false);
  });
});

describe("access keys — authorize flow", () => {
  it("asks for the key BEFORE the QR, in Uzbek with English fallback", async () => {
    const s = setup();
    const res = await s.app.request(`/oauth/authorize?${authorizeQuery(s.clientId)}`, {
      headers: { "x-real-ip": ipFor() },
    });
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /Kirish kaliti/);
    assert.match(html, /Davom etish/);
    assert.match(html, /Access key/);
    assert.ok(!html.includes("/oauth/authorize/qr"), "no QR stream on the key page");
  });

  it("wrong key is refused and nothing is stored", async () => {
    const s = setup();
    const ip = ipFor();
    const res = await submitKey(s, "zzzz-zzzz-zzzz-zzzz", ip);
    assert.equal(res.status, 403);
    assert.match(await res.text(), /Kalit noto&#39;g&#39;ri|Kalit noto'g'ri/);
    assert.equal(cookieValue(res, "ak_ticket"), undefined, "no ticket for a wrong key");
    assert.equal(s.bindings(), 0);
    assert.equal(s.fake.saved.size, 0);
    // And the QR stream cannot be opened without a ticket — no MTProto connection.
    let scanned = false;
    qrRunner.run = async () => {
      scanned = true;
      return { ok: true, sessionString: "x" } as never;
    };
    const qr = await s.app.request(`/oauth/authorize/qr?${authorizeQuery(s.clientId)}`, {
      headers: { "x-real-ip": ip },
    });
    assert.equal(qr.status, 403);
    assert.equal(scanned, false);
    assert.equal(s.fake.saved.size, 0);
  });

  it("rejects a key POST without the CSRF token or from another origin", async () => {
    const s = setup();
    const body = new URLSearchParams({ client_id: s.clientId, access_key: KEY_1, csrf: "x" });
    const noCsrf = await s.app.request("/oauth/authorize/key", {
      method: "POST",
      headers: { origin: ISSUER, "content-type": "application/x-www-form-urlencoded", "x-real-ip": ipFor() },
      body,
    });
    assert.equal(noCsrf.status, 403);
    const crossSite = await s.app.request("/oauth/authorize/key", {
      method: "POST",
      headers: {
        origin: "https://evil.example",
        "content-type": "application/x-www-form-urlencoded",
        cookie: "ak_csrf=x",
        "x-real-ip": ipFor(),
      },
      body,
    });
    assert.equal(crossSite.status, 403);
  });

  it("blocks an IP after repeated wrong keys, even for a correct key", async () => {
    const s = setup();
    const ip = ipFor();
    for (let i = 0; i < KEY_FAIL_LIMIT; i++) assert.equal((await submitKey(s, `bad-${i}`, ip)).status, 403);
    const res = await submitKey(s, KEY_1, ip);
    assert.equal(res.status, 403);
    assert.match(await res.text(), /Too many attempts/);
    assert.equal(cookieValue(res, "ak_ticket"), undefined);
    // Another IP is unaffected.
    assert.equal((await submitKey(s, KEY_1, ipFor())).status, 303);
  });

  it("valid key → QR → token", async () => {
    const s = setup();
    const ip = ipFor();
    const posted = await submitKey(s, KEY_1, ip);
    assert.equal(posted.status, 303);
    assert.match(posted.headers.get("location") ?? "", /^\/oauth\/authorize\?/);
    const ticket = cookieValue(posted, "ak_ticket");
    assert.ok(ticket);

    // With the ticket the authorize page moves on to the QR step.
    const qrPage = await s.app.request(`/oauth/authorize?${authorizeQuery(s.clientId)}`, {
      headers: { cookie: `ak_ticket=${ticket}`, "x-real-ip": ip },
    });
    assert.equal(qrPage.status, 200);
    assert.ok(!(await qrPage.text()).includes("Kirish kaliti"));

    s.fake.scanAs({ id: 111, username: "alice" });
    const sse = await (await runQr(s, ticket, ip)).text();
    const token = await exchange(s, sse);
    assert.equal(token.status, 200);
    const body = (await token.json()) as { access_token: string; refresh_token: string };
    assert.ok(body.access_token && body.refresh_token);
    assert.equal(s.oauth.validateToken(body.access_token)?.userId, "alice");
    assert.equal(s.bindings(), 1);
    assert.equal(s.access.isTelegramIdAllowed("111"), true);
  });

  it("a key is bound to the first Telegram account; a second account is refused and nothing is stored", async () => {
    const s = setup();
    const first = await connect(s, KEY_1, { id: 111, username: "alice" });
    assert.match(first.sse, /event: redirect/);

    const second = await connect(s, KEY_1, { id: 222, username: "bob" });
    assert.ok(!second.sse.includes("event: redirect"), "no code for the second account");
    assert.match(second.sse, /already bound to a different Telegram account/);
    assert.equal(s.fake.saved.has("bob"), false, "the second account's session is not stored");
    assert.ok(s.fake.loggedOut.includes(222), "the refused scan's Telegram authorization is ended");
    assert.equal(s.access.isTelegramIdAllowed("222"), false);

    // The first account keeps working with the same key (re-login).
    const again = await connect(s, KEY_1, { id: 111, username: "alice" });
    assert.match(again.sse, /event: redirect/);
  });

  it("the ticket is single-use after a successful bind", async () => {
    const s = setup();
    const { ticket } = await connect(s, KEY_1, { id: 111, username: "alice" });
    const reuse = await s.app.request(`/oauth/authorize/qr?${authorizeQuery(s.clientId)}`, {
      headers: { cookie: `ak_ticket=${ticket}`, "x-real-ip": ipFor() },
    });
    assert.equal(reuse.status, 403);
  });
});

describe("access keys — revocation cuts users off", () => {
  async function connectedUser() {
    const s = setup();
    const { sse } = await connect(s, KEY_1, { id: 111, username: "alice" });
    const tokens = (await (await exchange(s, sse)).json()) as { access_token: string; refresh_token: string };
    return { s, tokens };
  }

  it("removed label: next MCP request is 401 and the stored session + tokens are deleted", async () => {
    const { s, tokens } = await connectedUser();
    // Redeploy without person-1.
    const after = s.gateFor({ "person-2": KEY_2 });
    const app = new Hono();
    registerMcpRoutes(app, {
      oauth: s.oauth,
      sessions: s.fake.sessions as never,
      usage: {} as never,
      destructive: {} as never,
      uploads: {} as never,
      access: after,
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { authorization: `Bearer ${tokens.access_token}`, "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(res.status, 401);
    assert.deepEqual(s.fake.destroyed, ["alice"]);
    assert.equal(s.fake.saved.has("alice"), false);
    assert.equal(s.oauth.validateToken(tokens.access_token), null, "tokens revoked");
  });

  it("removed label: token refresh is refused and the user is cut off", async () => {
    const { s, tokens } = await connectedUser();
    const after = s.gateFor({ "person-2": KEY_2 });
    const app = new Hono();
    app.route("/oauth", createOAuthRoutes({ oauth: s.oauth, sessions: s.fake.sessions as never, access: after }));
    const res = await app.request("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "x-real-ip": ipFor() },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: s.clientId,
      }),
    });
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as { error: string }).error, "invalid_grant");
    assert.deepEqual(s.fake.destroyed, ["alice"]);
  });

  it("label still listed: refresh keeps working", async () => {
    const { s, tokens } = await connectedUser();
    const res = await s.app.request("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "x-real-ip": ipFor() },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: s.clientId,
      }),
    });
    assert.equal(res.status, 200);
    assert.deepEqual(s.fake.destroyed, []);
  });

  it("label re-issued with a NEW key: old holder is cut off, the new key can bind another account", async () => {
    const { s } = await connectedUser();
    const reissued = s.gateFor({ "person-1": "nnnn-pppp-qqqq-rrrr" });
    assert.equal(reissued.isTelegramIdAllowed("111"), false, "old holder no longer allowed");
    assert.equal(reissued.bind("person-1", "333"), "ok");
    assert.equal(reissued.isTelegramIdAllowed("333"), true);
    assert.equal(reissued.pruneStaleBindings(), 0);
  });

  it("boot prune drops bindings of removed labels", async () => {
    const { s } = await connectedUser();
    assert.equal(s.gateFor({ "person-2": KEY_2 }).pruneStaleBindings(), 1);
    assert.equal(s.bindings(), 0);
  });
});

describe("access keys — side doors", () => {
  it("/login/qr refuses a Telegram account that holds no key and stores nothing", async () => {
    const s = setup();
    const app = new Hono();
    app.route("/login", createLoginRoutes({ sessions: s.fake.sessions as never, oauth: s.oauth, access: s.access }));
    qrRunner.run = async () => ({ ok: true, sessionString: "x" }) as never;
    s.fake.scanAs({ id: 999, username: "mallory" });
    const sse = await (await app.request("/login/qr?userId=mallory", { headers: { "x-real-ip": ipFor() } })).text();
    assert.match(sse, /not linked to an access key/);
    assert.ok(!sse.includes("event: connected"));
    assert.equal(s.fake.saved.size, 0);
  });

  it("adding a second Telegram account is disabled while the gate is on", async () => {
    const s = setup();
    const app = new Hono();
    app.route("/accounts", createAccountsRoutes({ sessions: s.fake.sessions as never, access: s.access }));
    assert.equal((await app.request("/accounts/add/anything")).status, 403);
    assert.equal((await app.request("/accounts/add/anything/qr")).status, 403);
  });

  it("a browser session whose key was revoked does not get the silent fast path", async () => {
    const s = setup();
    await connect(s, KEY_1, { id: 111, username: "alice" });
    s.oauth.recordGrant("alice", "https://claude.ai");
    const cookie = `tg_sid=${s.oauth.createBrowserSession("alice", 3600)}`;
    const after = s.gateFor({ "person-2": KEY_2 });
    const app = new Hono();
    app.route("/oauth", createOAuthRoutes({ oauth: s.oauth, sessions: s.fake.sessions as never, access: after }));
    const res = await app.request(`/oauth/authorize?${authorizeQuery(s.clientId)}`, {
      headers: { cookie, "x-real-ip": ipFor() },
    });
    assert.equal(res.status, 200, "no 302 with a code");
    assert.match(await res.text(), /Kirish kaliti/);
  });
});

describe("make-access-keys script", () => {
  /** Copy the script + its one import into a fake repo so the DEFAULT output dir can be observed. */
  function fakeRepo() {
    const parent = mkdtempSync(join(tmpdir(), "ak-script-"));
    const repo = join(parent, "repo");
    mkdirSync(join(repo, "scripts"), { recursive: true });
    mkdirSync(join(repo, "src"), { recursive: true });
    copyFileSync(join(ROOT, "scripts", "make-access-keys.ts"), join(repo, "scripts", "make-access-keys.ts"));
    copyFileSync(join(ROOT, "src", "access-keys.ts"), join(repo, "src", "access-keys.ts"));
    return { parent, repo };
  }
  const run = (repo: string, args: string[]) =>
    spawnSync(process.execPath, [join(repo, "scripts", "make-access-keys.ts"), ...args], {
      cwd: repo,
      encoding: "utf8",
      timeout: 20_000,
    });

  it("writes plain keys to the PARENT of the repo (mode 600) and prints only label:hash", () => {
    const { parent, repo } = fakeRepo();
    const res = run(repo, ["--count", "3", "--prefix", "person"]);
    assert.equal(res.status, 0, res.stderr);
    const csvPath = join(parent, "access-keys-PRIVATE.csv");
    assert.ok(existsSync(csvPath));
    assert.ok(!existsSync(join(repo, "access-keys-PRIVATE.csv")), "nothing inside the repo");
    assert.equal(statSync(csvPath).mode & 0o777, 0o600);

    const rows = readFileSync(csvPath, "utf8").trim().split("\n");
    assert.equal(rows[0], "label,key");
    const keys = rows.slice(1).map((r) => r.split(","));
    assert.equal(keys.length, 3);
    for (const [, key] of keys) assert.match(key ?? "", /^[a-hjkmnp-z2-9]{4}(-[a-hjkmnp-z2-9]{4}){3}$/);

    const env = res.stdout.trim();
    assert.equal(env, keys.map(([label, key]) => `${label}:${hashAccessKey(key ?? "")}`).join(","));
    for (const [, key] of keys) assert.ok(!res.stdout.includes(key ?? "") && !res.stderr.includes(key ?? ""));
    assert.equal(parseAccessKeys(env).size, 3);
  });

  it("--label adds one key, and an existing CSV is never silently overwritten", () => {
    const { parent, repo } = fakeRepo();
    assert.equal(run(repo, ["--count", "2"]).status, 0);
    assert.notEqual(run(repo, ["--count", "2"]).status, 0, "refuses to overwrite without --force");
    const add = run(repo, ["--label", "person-31"]);
    assert.equal(add.status, 0, add.stderr);
    assert.match(add.stdout.trim(), /^person-31:[0-9a-f]{64}$/);
    const rows = readFileSync(join(parent, "access-keys-PRIVATE.csv"), "utf8").trim().split("\n");
    assert.equal(rows.length, 4);
    assert.notEqual(run(repo, ["--label", "person-31"]).status, 0, "duplicate label refused");
  });

  it("refuses an output directory inside the repository", () => {
    const { repo } = fakeRepo();
    const res = run(repo, ["--count", "1", "--out-dir", join(repo, "src")]);
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /refusing to write plain keys inside the repository/);
    assert.ok(!existsSync(join(repo, "src", "access-keys-PRIVATE.csv")));
  });

  it(".gitignore guards access-keys-*.csv", () => {
    assert.match(readFileSync(join(ROOT, ".gitignore"), "utf8"), /^access-keys-\*\.csv$/m);
  });
});
