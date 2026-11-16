/**
 * `/my/key` — sign in to the website settings (/my/chats, /my/settings) with the
 * ACCESS KEY the operator handed out, instead of scanning a Telegram QR again.
 *
 * The key only works once it is bound to a Telegram account (i.e. after the
 * person connected from Claude with it); it then signs the browser in as that
 * account. Same protections as the OAuth key form: constant-time comparison
 * against hashes, the shared per-IP failure limiter (5 / 15 min), Origin check +
 * double-submit CSRF token, key never logged or stored.
 */
import { randomBytes } from "node:crypto";
import type { Context } from "hono";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { css } from "hono/css";
import type { FC } from "hono/jsx";
import { type AccessGate, readCookie, safeEqual } from "../access-keys.js";
import { config } from "../config.js";
import { buildBrowserSessionCookie } from "../cookie-handler.js";
import { logger, logUser } from "../logger.js";
import type { OAuthProvider } from "../oauth.js";
import { Layout } from "../pages/Layout.js";
import { getClientIp } from "../rate-limit.js";
import type { SessionManager } from "../session-manager.js";
import { button, card, scope, subtitle, tg, title } from "../styles.js";

/** Browser session length after a key sign-in. */
export const KEY_SIGNIN_MAX_AGE_SECONDS = 12 * 60 * 60;
const CSRF_COOKIE = "my_key_csrf";
/** Only these pages can be the post-sign-in destination (no open redirect). */
const NEXT_PAGES = new Set(["/my/chats", "/my/settings"]);

export interface MyKeyDeps {
  access: Pick<AccessGate, "enabled" | "verify" | "boundTelegramId" | "isBlocked" | "recordFailure">;
  sessions: Pick<SessionManager, "findUserIdByTelegramId" | "getSavedUserIds">;
  oauth: Pick<OAuthProvider, "createBrowserSession">;
  /** Where to go when `next` is missing or not allowed. */
  defaultNext: string;
}

type KeyError = "invalid" | "blocked" | "not_connected";

const input = css`
  width: 100%;
  font-size: 18px;
  letter-spacing: 1px;
  text-align: center;
  padding: 12px 14px;
  margin: 8px 0 16px;
  border: 1px solid ${tg.divider};
  border-radius: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
`;
const errorBox = css`
  color: ${tg.destructive};
  margin: 0 0 12px;
  font-size: 15px;
`;
const en = css`
  color: ${tg.hint};
  font-size: 13px;
`;

const ERRORS: Record<KeyError, [string, string]> = {
  invalid: ["Kalit noto'g'ri.", "Invalid key."],
  blocked: [
    "Juda ko'p urinish. 15 daqiqadan so'ng qayta urinib ko'ring.",
    "Too many attempts — try again in 15 minutes.",
  ],
  not_connected: [
    "Bu kalit hali Telegram akkauntiga bog'lanmagan. Avval Claude orqali shu kalit bilan ulaning.",
    "This key is not linked to a Telegram account yet. Connect from Claude with it first.",
  ],
};

export const MyKeyPage: FC<{ csrf: string; next: string; error?: KeyError }> = (props) => (
  <Layout title={`${config.brandName} — Kirish kaliti`}>
    <div class={card}>
      <h1 class={title}>Sozlamalarga kirish</h1>
      <p class={subtitle}>
        Sozlamalarni o'zgartirish uchun sizga berilgan kirish kalitini kiriting.
        <br />
        <span class={en}>Enter the access key you were given to change your settings.</span>
      </p>
      {props.error && (
        <p class={errorBox} role="alert">
          {ERRORS[props.error][0]} <span class={en}>{ERRORS[props.error][1]}</span>
        </p>
      )}
      <form method="post" action="/my/key" autocomplete="off">
        <input type="hidden" name="csrf" value={props.csrf} />
        <input type="hidden" name="next" value={props.next} />
        <label for="access_key" class={en}>
          Kirish kaliti / Access key
        </label>
        <input
          class={input}
          id="access_key"
          name="access_key"
          type="password"
          required
          maxlength={64}
          autocapitalize="off"
          spellcheck={false}
          placeholder="xxxx-xxxx-xxxx-xxxx"
        />
        <button class={button} type="submit">
          Davom etish
        </button>
      </form>
      <p class={scope}>
        <span class={en}>Kalit faqat u bog'langan Telegram akkaunt sozlamalarini ochadi.</span>
      </p>
    </div>
  </Layout>
);

function csrfCookie(value: string, maxAge: number): string {
  const secure = config.issuer.startsWith("https://") ? "; Secure" : "";
  return `${CSRF_COOKIE}=${value}; Path=/my; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${secure}`;
}

export function createMyKeyRoutes(deps: MyKeyDeps): Hono {
  const app = new Hono({ strict: false });
  const safeNext = (v: string | undefined) => (v && NEXT_PAGES.has(v) ? v : deps.defaultNext);

  const page = (c: Context, next: string, error?: KeyError) => {
    const csrf = randomBytes(32).toString("hex");
    c.header("Set-Cookie", csrfCookie(csrf, 30 * 60), { append: true });
    c.header("Cache-Control", "no-store");
    return c.html(<MyKeyPage csrf={csrf} next={next} {...(error && { error })} />, error ? 403 : 200);
  };

  app.get("/key", (c) => page(c, safeNext(c.req.query("next"))));

  app.post("/key", bodyLimit({ maxSize: 4096 }), async (c) => {
    if (!deps.access.enabled) return c.text("Not found", 404);
    if (c.req.header("origin") !== config.issuer) return c.text("Forbidden", 403);
    const form = await c.req.parseBody().catch(() => null);
    const field = (name: string) => {
      const v = form?.[name];
      return typeof v === "string" ? v : "";
    };
    const cookie = readCookie(c.req.header("cookie"), CSRF_COOKIE) ?? "";
    if (!cookie || !safeEqual(cookie, field("csrf"))) return c.text("Forbidden", 403);
    const next = safeNext(field("next"));

    const ip = getClientIp(c);
    if (deps.access.isBlocked(ip)) return page(c, next, "blocked");
    const label = deps.access.verify(field("access_key").slice(0, 256));
    if (!label) {
      deps.access.recordFailure(ip);
      logger.warn("Settings sign-in: access key rejected", { component: "my", event: "my_key.rejected" });
      return page(c, next, "invalid");
    }
    const telegramId = deps.access.boundTelegramId(label);
    const userId = telegramId ? deps.sessions.findUserIdByTelegramId(telegramId) : null;
    if (!userId || !deps.sessions.getSavedUserIds().includes(userId)) return page(c, next, "not_connected");

    const token = deps.oauth.createBrowserSession(userId, KEY_SIGNIN_MAX_AGE_SECONDS);
    c.header("Set-Cookie", buildBrowserSessionCookie(token, KEY_SIGNIN_MAX_AGE_SECONDS), { append: true });
    c.header("Set-Cookie", csrfCookie("", 0), { append: true });
    logger.info(`Settings sign-in with access key (${label})`, {
      component: "my",
      event: "my_key.accepted",
      userId: logUser(userId),
    });
    return c.redirect(next, 303);
  });

  return app;
}
