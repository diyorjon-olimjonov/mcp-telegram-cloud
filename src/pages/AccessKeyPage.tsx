import { css } from "hono/css";
import type { FC } from "hono/jsx";
import { config } from "../config.js";
import { button, card, scope, subtitle, tg, title } from "../styles.js";
import { Layout } from "./Layout.js";

export interface AccessKeyPageProps {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  /** Double-submit token; the same value is set in the `ak_csrf` cookie. */
  csrf: string;
  error?: "invalid" | "blocked";
}

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

/**
 * Step 1 of `/oauth/authorize` when the access-key gate is on: the key comes
 * BEFORE the Telegram QR. Uzbek (Latin) first, English underneath as fallback.
 * Posts to `/oauth/authorize/key`, which re-checks Origin + the CSRF token.
 */
export const AccessKeyPage: FC<AccessKeyPageProps> = (props) => {
  return (
    <Layout title={`${config.brandName} — Kirish kaliti`}>
      <div class={card}>
        <h1 class={title}>Kirish kaliti</h1>
        <p class={subtitle}>
          Davom etish uchun sizga berilgan kirish kalitini kiriting.
          <br />
          <span class={en}>Access key — enter the key you were given to continue.</span>
        </p>

        {props.error === "invalid" && (
          <p class={errorBox} role="alert">
            Kalit noto'g'ri. <span class={en}>Invalid key.</span>
          </p>
        )}
        {props.error === "blocked" && (
          <p class={errorBox} role="alert">
            Juda ko'p urinish. 15 daqiqadan so'ng qayta urinib ko'ring.{" "}
            <span class={en}>Too many attempts — try again in 15 minutes.</span>
          </p>
        )}

        <form method="post" action="/oauth/authorize/key" autocomplete="off">
          <input type="hidden" name="csrf" value={props.csrf} />
          <input type="hidden" name="client_id" value={props.clientId} />
          <input type="hidden" name="redirect_uri" value={props.redirectUri} />
          <input type="hidden" name="state" value={props.state} />
          <input type="hidden" name="code_challenge" value={props.codeChallenge} />
          <input type="hidden" name="code_challenge_method" value={props.codeChallengeMethod} />
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
          Kalit bir marta, bitta Telegram akkauntiga bog'lanadi.{" "}
          <span class={en}>A key is bound to the first Telegram account that signs in with it.</span>
        </p>
      </div>
    </Layout>
  );
};
