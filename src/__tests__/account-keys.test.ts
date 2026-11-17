/**
 * Personal access keys (open-signup mode): one per Telegram account, issued on the
 * first QR login, shown once, stored as a hash, replaced by the admin script.
 */
process.env.TELEGRAM_API_ID ??= "1";
process.env.TELEGRAM_API_HASH ??= "test";
process.env.ISSUER ??= "https://test.invalid";
process.env.MCP_TELEGRAM_TELEMETRY ??= "off";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Hono } from "hono";

const { Database } = await import("bun:sqlite");
const { AccountKeys, generateAccountKey, ACCOUNT_KEY_ALPHABET } = await import("../account-keys.js");
const { AccessGate, hashAccessKey } = await import("../access-keys.js");
const { OAuthProvider } = await import("../oauth.js");
const { createMyKeyRoutes } = await import("../routes/my-key.js");
const { readBrowserSessionToken } = await import("../cookie-handler.js");
const { findTelegramId } = await import("../../scripts/reset-account-key.ts");
const { config } = await import("../config.js");

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("AccountKeys", () => {
  it("generates xxxx-xxxx-xxxx-xxxx keys from the no-look-alike alphabet", () => {
    for (let i = 0; i < 50; i++) {
      const k = generateAccountKey();
      assert.match(k, /^[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}$/);
      for (const ch of k.replace(/-/g, "")) assert.ok(ACCOUNT_KEY_ALPHABET.includes(ch));
    }
  });

  it("issues a key once per account; later logins get nothing to show", () => {
    const keys = new AccountKeys(new Database(":memory:"));
    const first = keys.issue("111");
    assert.ok(first);
    assert.equal(keys.issue("111"), null, "never shown twice");
    assert.ok(keys.has("111"));
    assert.equal(keys.verify(first), "111");
  });

  it("stores only the hash", () => {
    const db = new Database(":memory:");
    const keys = new AccountKeys(db);
    const k = keys.issue("111") as string;
    const row = db.prepare("SELECT * FROM account_keys").get() as Record<string, string>;
    assert.equal(row.key_hash, hashAccessKey(k));
    assert.ok(!JSON.stringify(row).includes(k.replace(/-/g, "")), "plain key is not stored");
  });

  it("accepts the key typed in upper case or with spaces instead of dashes", () => {
    const keys = new AccountKeys(new Database(":memory:"));
    const k = keys.issue("111") as string;
    assert.equal(keys.verify(k.toUpperCase()), "111");
    assert.equal(keys.verify(k.replace(/-/g, " ")), "111");
    assert.equal(keys.verify("zzzz-zzzz-zzzz-zzzz"), null);
  });

  it("different accounts get different keys", () => {
    const keys = new AccountKeys(new Database(":memory:"));
    const a = keys.issue("111") as string;
    const b = keys.issue("222") as string;
    assert.notEqual(a, b);
    assert.equal(keys.verify(a), "111");
    assert.equal(keys.verify(b), "222");
  });

  it("admin reset: new key works, old key stops working", () => {
    const keys = new AccountKeys(new Database(":memory:"));
    const old = keys.issue("111") as string;
    const fresh = keys.reset("111");
    assert.notEqual(fresh, old);
    assert.equal(keys.verify(old), null);
    assert.equal(keys.verify(fresh), "111");
    assert.equal(keys.issue("111"), null, "a reset account is not re-issued on login");
  });
});

describe("reset script: finding the account", () => {
  const db = new Database(":memory:");
  db.exec("CREATE TABLE user_sessions (user_id TEXT PRIMARY KEY, session_string TEXT, telegram_id TEXT)");
  db.prepare("INSERT INTO user_sessions VALUES ('Alice', 'x', '111'), ('222', 'y', '222')").run();

  it("by @username (case-insensitive) or numeric id", () => {
    assert.equal(findTelegramId(db, "@alice"), "111");
    assert.equal(findTelegramId(db, "Alice"), "111");
    assert.equal(findTelegramId(db, "222"), "222");
    assert.equal(findTelegramId(db, "111"), "111");
  });

  it("unknown account: null", () => {
    assert.equal(findTelegramId(db, "@nobody"), null);
    assert.equal(findTelegramId(db, "999"), null);
  });
});

describe("/my/key in open-signup mode accepts personal keys", () => {
  function setup() {
    const db = new Database(":memory:");
    const oauth = new OAuthProvider({ issuer: config.issuer, db });
    const access = new AccessGate(db, new Map(), { allowOpenSignup: true });
    const accountKeys = new AccountKeys(db);
    const sessions = {
      findUserIdByTelegramId: (tg: string) => (tg === "111" ? "alice" : null),
      getSavedUserIds: () => ["alice"],
    };
    const app = new Hono();
    app.route("/my", createMyKeyRoutes({ access, accountKeys, sessions, oauth, defaultNext: "/my/chats" }));
    return { app, oauth, accountKeys };
  }

  async function signIn(app: Hono, key: string) {
    const ip = `10.9.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
    const page = await app.request("/my/key", { headers: { "x-real-ip": ip } });
    const csrf =
      page.headers
        .getSetCookie()
        .find((c) => c.startsWith("my_key_csrf="))
        ?.split(";")[0]
        ?.slice("my_key_csrf=".length) ?? "";
    return app.request("/my/key", {
      method: "POST",
      headers: {
        origin: config.issuer,
        "content-type": "application/x-www-form-urlencoded",
        cookie: `my_key_csrf=${csrf}`,
        "x-real-ip": ip,
      },
      body: new URLSearchParams({ csrf, next: "/my/chats", access_key: key }),
    });
  }

  it("the account's own key signs the browser in as that account", async () => {
    const s = setup();
    const key = s.accountKeys.issue("111") as string;
    const res = await signIn(s.app, key);
    assert.equal(res.status, 303);
    const sid = res.headers
      .getSetCookie()
      .find((c) => c.startsWith("tg_sid="))
      ?.split(";")[0];
    assert.ok(sid);
    assert.equal(s.oauth.getBrowserSessionUser(readBrowserSessionToken(sid)), "alice");
  });

  it("wrong or replaced key is refused", async () => {
    const s = setup();
    const old = s.accountKeys.issue("111") as string;
    s.accountKeys.reset("111");
    assert.equal((await signIn(s.app, old)).status, 403);
    assert.equal((await signIn(s.app, "zzzz-zzzz-zzzz-zzzz")).status, 403);
  });

  it("a key whose account is no longer connected does not sign in", async () => {
    const s = setup();
    const key = s.accountKeys.issue("333") as string;
    const res = await signIn(s.app, key);
    assert.equal(res.status, 403);
  });
});

describe("QR login issues the key only after the session is stored, for the scanned account", () => {
  const source = readFileSync(join(SRC, "qr-login.ts"), "utf8");
  it("both flows issue for String(me.id) and send it on the success event", () => {
    const issues = source.match(/accountKeys\?\.issue\(String\(me\.id\)\)/g) ?? [];
    assert.equal(issues.length, 2, "login + OAuth flows");
    const oauthSave = source.indexOf(
      "sessions.saveSessionString(userId, outcome.sessionString, String(me.id));\n          const accountKey",
    );
    assert.ok(oauthSave > 0, "OAuth flow issues right after saving the session");
    assert.equal((source.match(/\.\.\.\(accountKey && \{ accountKey \}\)/g) ?? []).length, 2);
  });
});
