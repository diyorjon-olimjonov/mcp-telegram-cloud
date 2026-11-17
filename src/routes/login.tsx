import { Hono } from "hono";
import type { AccountKeys } from "../account-keys.js";
import type { OAuthProvider } from "../oauth.js";
import { LoginPage } from "../pages/LoginPage.js";
import { handleQrLogin } from "../qr-login.js";
import { qrLoginRateLimit } from "../rate-limit.js";
import { detectRequestLocale, islandScripts, reactPagesAvailable, renderReactPage } from "../react-pages.js";
import type { SessionManager } from "../session-manager.js";

export interface LoginRoutesDeps {
  sessions: SessionManager;
  oauth: Pick<OAuthProvider, "createBrowserHandoff">;
  /** Access-key gate: only Telegram accounts bound to a listed key may sign in. */
  access?: { enabled: boolean; isTelegramIdAllowed(telegramId: string): boolean };
  /** Open-signup mode: personal key made on an account's first QR login. */
  accountKeys?: Pick<AccountKeys, "issue">;
}

export function createLoginRoutes({ sessions, oauth, access, accountKeys }: LoginRoutesDeps): Hono {
  const app = new Hono();

  app.get("/", async (c) => {
    if (reactPagesAvailable()) {
      const locale = detectRequestLocale(c);
      const html = await renderReactPage("login", {
        locale,
        scripts: islandScripts("language-switcher", "qr-flow"),
      });
      return c.html(html);
    }
    return c.html(<LoginPage />);
  });

  app.get("/qr", qrLoginRateLimit, async (c) => {
    const userId = c.req.query("userId");
    if (!userId) {
      return c.text("userId required", 400);
    }

    const stream = await handleQrLogin(sessions, userId, c.req.raw.signal, oauth, access, accountKeys);

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    });
  });

  return app;
}
