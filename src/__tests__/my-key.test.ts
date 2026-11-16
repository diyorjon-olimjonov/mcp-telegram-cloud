/**
 * /my/key — signing in to the website settings with the access key.
 * Real AccessGate + OAuthProvider on an in-memory DB; the session layer is a double.
 */
process.env.TELEGRAM_API_ID ??= "1";
process.env.TELEGRAM_API_HASH ??= "test";
process.env.ISSUER ??= "https://test.invalid";
process.env.MCP_TELEGRAM_TELEMETRY ??= "off";

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";

const { Database } = await import("bun:sqlite");
const { OAuthProvider } = await import("../oauth.js");
const { AccessGate, hashAccessKey, KEY_FAIL_LIMIT } = await import("../access-keys.js");
const { createMyKeyRoutes, KEY_SIGNIN_MAX_AGE_SECONDS } = await import("../routes/my-key.js");
const { createMyRoutes } = await import("../routes/my.js");
const { readBrowserSessionToken } = await import("../cookie-handler.js");
const { config } = await import("../config.js");

const ISSUER = config.issuer;
const KEY_1 = "abcd-efgh-jkmn-pqrs";
const KEY_2 = "wxyz-2345-6789-abcd";
const KEY_3 = "hhhh-jjjj-kkkk-mmmm";

function setup(keys: Record<string, string> = { "person-1": KEY_1, "person-2": KEY_2, "person-3": KEY_3 }) {
  const db = new Database(":memory:");
  const oauth = new OAuthProvider({ issuer: ISSUER, db });
  const gateFor = (k: Record<string, string>) =>
    new AccessGate(db, new Map(Object.entries(k).map(([l, key]) => [l, hashAccessKey(key)])));
  const access = gateFor(keys);
  // alice (tg 111) connected with person-1, bob (tg 222) with person-2; person-3 never connected.
  access.bind("person-1", "111");
  access.bind("person-2", "222");
  const saved = new Map([
    ["alice", "111"],
    ["bob", "222"],
  ]);
  const sessions = {
    findUserIdByTelegramId: (tg: string) => [...saved].find(([, t]) => t === tg)?.[0] ?? null,
    getSavedUserIds: () => [...saved.keys()],
  };
  const appFor = (gate: InstanceType<typeof AccessGate>) => {
    const app = new Hono();
    app.route("/my", createMyKeyRoutes({ access: gate, sessions, oauth, defaultNext: "/my/chats" }));
    return app;
  };
  return { oauth, access, gateFor, appFor, app: appFor(access) };
}

const ipFor = () => `10.7.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

function cookieValue(res: Response, name: string): { value: string; attrs: string } | undefined {
  for (const c of res.headers.getSetCookie()) {
    if (c.startsWith(`${name}=`)) return { value: c.slice(name.length + 1).split(";")[0] ?? "", attrs: c };
  }
  return undefined;
}

async function signIn(app: Hono, key: string, opts: { ip?: string; next?: string; origin?: string } = {}) {
  const ip = opts.ip ?? ipFor();
  const page = await app.request(`/my/key${opts.next ? `?next=${encodeURIComponent(opts.next)}` : ""}`, {
    headers: { "x-real-ip": ip },
  });
  const html = await page.text();
  const csrf = cookieValue(page, "my_key_csrf")?.value ?? "";
  const next = html.match(/name="next" value="([^"]*)"/)?.[1] ?? "";
  return app.request("/my/key", {
    method: "POST",
    headers: {
      origin: opts.origin ?? ISSUER,
      "content-type": "application/x-www-form-urlencoded",
      cookie: `my_key_csrf=${csrf}`,
      "x-real-ip": ip,
    },
    body: new URLSearchParams({ csrf, next, access_key: key }),
  });
}

describe("/my/key — settings sign-in with the access key", () => {
  it("shows a key form (Uzbek, English fallback)", async () => {
    const html = await (await setup().app.request("/my/key")).text();
    assert.match(html, /Sozlamalarga kirish/);
    assert.match(html, /Davom etish/);
    assert.match(html, /Access key/);
  });

  it("a bound key signs the browser in as ITS account and goes to /my/chats", async () => {
    const s = setup();
    for (const [key, user] of [
      [KEY_1, "alice"],
      [KEY_2, "bob"],
    ] as const) {
      const res = await signIn(s.app, key);
      assert.equal(res.status, 303);
      assert.equal(res.headers.get("location"), "/my/chats");
      const sid = cookieValue(res, "tg_sid");
      assert.ok(sid, "browser session cookie set");
      assert.match(sid.attrs, new RegExp(`Max-Age=${KEY_SIGNIN_MAX_AGE_SECONDS}`));
      assert.match(sid.attrs, /HttpOnly/);
      assert.equal(s.oauth.getBrowserSessionUser(readBrowserSessionToken(`tg_sid=${sid.value}`)), user);
    }
  });

  it("wrong key: refused, nothing signed in", async () => {
    const res = await signIn(setup().app, "zzzz-zzzz-zzzz-zzzz");
    assert.equal(res.status, 403);
    assert.match(await res.text(), /Kalit noto&#39;g&#39;ri|Kalit noto'g'ri/);
    assert.equal(cookieValue(res, "tg_sid"), undefined);
  });

  it("valid key that never connected: tells the person to connect from Claude first", async () => {
    const res = await signIn(setup().app, KEY_3);
    assert.equal(res.status, 403);
    assert.match(await res.text(), /Connect from Claude with it first/);
    assert.equal(cookieValue(res, "tg_sid"), undefined);
  });

  it("revoked or re-issued key no longer opens the settings", async () => {
    const s = setup();
    const removed = s.appFor(s.gateFor({ "person-2": KEY_2 }));
    assert.equal((await signIn(removed, KEY_1)).status, 403);
    const reissued = s.appFor(s.gateFor({ "person-1": "nnnn-pppp-qqqq-rrrr", "person-2": KEY_2 }));
    assert.equal((await signIn(reissued, KEY_1)).status, 403, "old key text");
    const res = await signIn(reissued, "nnnn-pppp-qqqq-rrrr");
    assert.match(await res.text(), /Connect from Claude/, "new key is not bound to alice");
  });

  it("only /my/chats or /my/settings can be the destination", async () => {
    const s = setup();
    assert.equal((await signIn(s.app, KEY_1, { next: "/my/settings" })).headers.get("location"), "/my/settings");
    assert.equal((await signIn(s.app, KEY_1, { next: "https://evil.example/" })).headers.get("location"), "/my/chats");
    assert.equal((await signIn(s.app, KEY_1, { next: "//evil.example" })).headers.get("location"), "/my/chats");
  });

  it("CSRF: other origin or missing token is refused", async () => {
    const s = setup();
    assert.equal((await signIn(s.app, KEY_1, { origin: "https://evil.example" })).status, 403);
    const res = await s.app.request("/my/key", {
      method: "POST",
      headers: { origin: ISSUER, "content-type": "application/x-www-form-urlencoded", "x-real-ip": ipFor() },
      body: new URLSearchParams({ access_key: KEY_1, csrf: "x" }),
    });
    assert.equal(res.status, 403);
    assert.equal(cookieValue(res, "tg_sid"), undefined);
  });

  it("shares the per-IP failure limit with the OAuth key form", async () => {
    const s = setup();
    const ip = ipFor();
    for (let i = 0; i < KEY_FAIL_LIMIT; i++) await signIn(s.app, `bad-${i}`, { ip });
    const res = await signIn(s.app, KEY_1, { ip });
    assert.equal(res.status, 403);
    assert.match(await res.text(), /Too many attempts/);
    assert.equal(cookieValue(res, "tg_sid"), undefined);
  });
});

describe("/my/settings sends signed-out visitors to the key form when the gate is on", () => {
  it("redirects to /my/key?next=/my/settings", async () => {
    const app = new Hono();
    app.route(
      "/my",
      createMyRoutes({
        destructive: {} as never,
        sessions: { getSavedUserIds: () => [] } as never,
        uploads: {} as never,
        oauth: { getBrowserSessionUser: () => null, validateToken: () => null },
        keyLogin: true,
      }),
    );
    const res = await app.request("/my/settings");
    assert.equal(res.status, 302);
    assert.match(res.headers.get("location") ?? "", /\/my\/key\?next=\/my\/settings$/);
  });
});
