# Hosting on Railway (access-key gated, read-only)

This fork runs `mcp-telegram-cloud` as a **Claude custom connector** for a small,
invited group. Every person links **their own** Telegram account, but only after
entering an **access key** you hand out. By default the server is **read-only**
and can only read **channels and groups** (no private chats, bots or Saved
Messages).

What the fork adds on top of upstream:

| Feature | Env | Default |
| --- | --- | --- |
| Access-key gate before the Telegram QR, key bound to the first Telegram account, revocation cuts the user off | `ACCESS_KEYS`, `ALLOW_OPEN_SIGNUP` | gate on; production refuses to boot without keys |
| Read-only tool surface | `TOOL_MODE` | `read-only` |
| Personal-data read tools removed | `HIDDEN_TOOLS` | 16 tools (see below) |
| Only groups and channels readable | `CHAT_POLICY` | `channels-and-groups` |
| Railway build/deploy settings | `railway.json` | Dockerfile builder, `/health` healthcheck, restart on failure |

---

## 1. Generate the access keys (on your computer)

```bash
bun scripts/make-access-keys.ts --count 30 --prefix person
```

- Creates `person-1` … `person-30`. Keys look like `abcd-efgh-jkmn-pqrs`
  (lowercase letters + digits, no look-alikes `0 o 1 l i`, about 79 bits).
- The **plain keys** go only to `access-keys-PRIVATE.csv` (`label,key`) in the
  **parent folder of the repository**, file mode `600`. The script refuses to
  write inside the repo, and `.gitignore` also blocks `access-keys-*.csv`.
- **stdout** is the value for `ACCESS_KEYS` (`person-1:<sha256>,person-2:<sha256>,…`).
  The server only ever sees these hashes.
- It refuses to overwrite an existing CSV (pass `--force` only if you really
  want to throw the old keys away).

Hand each person their key privately (one key per person). Keys are
case-insensitive and dashes/spaces are ignored when typed.

## 2. Create the Railway service

1. Railway → **New Project** → **Deploy from GitHub repo** → your fork, branch `main`.
   `railway.json` selects the Dockerfile build, the `/health` healthcheck and
   restart-on-failure automatically.
2. **Settings → Networking → Generate Domain** *before anything else* (target
   port **3000**). This domain is the permanent OAuth **issuer**: changing it
   later invalidates every token and client registration, and every person has
   to reconnect and scan the QR again.
3. **Volumes → Add volume**, mount path **`/app/data`**. The SQLite database
   (`/app/data/cloud.db`) lives there; without a volume every redeploy logs
   everyone out.

## 3. Variables (Service → Variables → Raw Editor)

Paste the values yourself; never commit them or share them in chat.

```env
TELEGRAM_API_ID=<from my.telegram.org/apps>
TELEGRAM_API_HASH=<from my.telegram.org/apps>
ISSUER=https://<your-railway-domain>          # no trailing slash
ADMIN_TOKEN=<openssl rand -hex 32>
SESSION_ENCRYPTION_KEY=<openssl rand -hex 32>
LOG_HASH_SALT=<openssl rand -hex 32>
LOG_USER_IDS=false
OAUTH_RATE_LIMIT=10
RAILWAY_RUN_UID=0
ACCESS_KEYS=<the single line printed in step 1>
TOOL_MODE=read-only
CHAT_POLICY=channels-and-groups
CHAT_ALLOWLIST=on
FREE_TIER_LIMIT=300
USAGE_LOG_RETENTION_DAYS=30
```

Notes:

- **`SESSION_ENCRYPTION_KEY`** encrypts every stored Telegram session. Back it up
  in **two** safe places (e.g. your password manager + an offline copy). If it is
  lost, stored sessions become unreadable and everyone must scan the QR again;
  if it leaks together with the volume, sessions can be decrypted.
- **`RAILWAY_RUN_UID=0`**: Railway volumes are mounted owned by root, while the
  image runs as the unprivileged `bun` user. Running as uid 0 lets the server
  write to `/app/data`.
- **`FREE_TIER_LIMIT`** is the per-person daily tool-call cap (default 100).
  300 leaves room for long research sessions while still stopping a runaway loop.
- **`OAUTH_RATE_LIMIT=10`** is per IP per minute on `/oauth/*`. One connection
  takes ~6 requests (register, authorize, key, authorize, QR, token).
- `HIDDEN_TOOLS` can stay unset (= default list).

## 4. Deploy and verify

- `https://<domain>/health` → `200` with `{"status":"ok",…}`.
- Deploy logs show `Access-key gate ON: 30 key(s) listed` and
  `Tool policy: TOOL_MODE=read-only, 16 hidden, …` and **no** line mentioning
  `PLAINTEXT` (that would mean `SESSION_ENCRYPTION_KEY` is missing).
- Open the connector flow (next step): the first page must be **"Kirish kaliti"**,
  not the QR code.
- Check that per-IP limits see real client IPs: after one wrong key from your
  phone, a correct key from another network must still work. (The limiter reads
  `X-Real-IP`, else the last `X-Forwarded-For` entry.)

## 5. Connect from Claude

Claude → **Settings → Connectors → Add custom connector** →
`https://<domain>/mcp` → **Connect** → enter your key → scan the QR with Telegram
(Settings → Devices → Link Desktop Device).

Then open `https://<domain>/my/chats` **in the same browser** (the QR login
signed it in) and tick the groups/channels Claude may read — with
`CHAT_ALLOWLIST=on` (default) nothing is readable until you do. The page has a
search box, shows the 300 most recent dialogs (then "Ko'proq ko'rsatish"), pins
ticked chats on top with "N ta tanlangan", and is the only place these rules
can change. Then try:

> list my channels and show the last 3 posts of @fvhokimligi

Also confirm:

- a wrong key shows **"Kalit noto'g'ri"** and nothing is stored;
- the same key used with a **second** Telegram account is refused ("This access
  key is already bound to a different Telegram account").

---

## Access keys: issue, revoke, re-issue

| Task | How |
| --- | --- |
| **Issue one more key** | `bun scripts/make-access-keys.ts --label person-31` → appends the plain key to `access-keys-PRIVATE.csv` and prints `person-31:<sha256>`. Append `,person-31:<sha256>` to `ACCESS_KEYS` in Railway and redeploy. |
| **Revoke a person** | Delete their `label:hash` entry from `ACCESS_KEYS` and redeploy. On their next request (MCP call or token refresh) the server logs their Telegram session out, deletes it, revokes their OAuth tokens and answers 401. Their key binding is also pruned at boot. |
| **Re-issue a key** (lost key, or the label goes to someone else) | Generate a fresh key for a **new** label with `--label person-32` (simplest), **or** keep the label and replace only its hash in `ACCESS_KEYS`. When the hash of a label changes, the old holder is cut off on their next request and the new key can bind a new Telegram account. |
| **Unbind a key from an account** (person changed Telegram account) | Same as re-issue: give them a new key. |

Rules enforced by the server:

- A key is bound to the **first Telegram account** that completes the QR login
  with it. Another account using the same key is refused and nothing is stored.
- Adding a second Telegram account (`accounts-add`) is disabled while the gate
  is on, and `/login` only signs in accounts that are already bound to a key.
- Five wrong keys from one IP block that IP for 15 minutes, even for a correct key.
- The key form is CSRF-protected (Origin check + double-submit token), and keys
  are compared as SHA-256 in constant time.
- What is stored per binding: the label, the numeric Telegram user ID, and the
  SHA-256 of the key (the same public hash as in `ACCESS_KEYS`; it lets the
  server notice re-issued keys).

---

## Environment variables added by this fork

| Variable | Values | Default | Effect |
| --- | --- | --- | --- |
| `ACCESS_KEYS` | `label:sha256hex,…` | empty | Login gate. Labels: lowercase, digits, `-`/`_`. Malformed entries stop the boot. Empty + production ⇒ refuses to start. |
| `ALLOW_OPEN_SIGNUP` | `1` | unset | Run without keys on purpose (anyone can sign in). |
| `TOOL_MODE` | `read-only`, `full` | `read-only` | `read-only`: only tools annotated `readOnlyHint=true`; others are absent from `tools/list` and refused by name; the destructive toggle on `/my/settings` is hidden. Unknown value stops the boot. |
| `HIDDEN_TOOLS` | comma list, `none`, `default,…` | default list | Removes tools in every mode. Unknown names are logged at boot. |
| `CHAT_POLICY` | `channels-and-groups`, `all` | `channels-and-groups` | Every chat argument must be a group/channel (checked before the Telegram call; unresolvable ⇒ refused); listings drop private chats and bots; unfilterable cross-chat tools are absent. Applies in both tool modes. |
| `CHAT_ALLOWLIST` | `on`, `off` | `on` | With `channels-and-groups`: only chats the user ticked on `/my/chats` are readable (deny by default); listings show only ticked chats; `telegram-get-groups-for-discussion` and `telegram-get-my-boosts` are absent. No MCP tool can read or change the rules. |

Default `HIDDEN_TOOLS`:
`telegram-get-contacts`, `telegram-get-contact-requests`, `telegram-get-profile`,
`telegram-get-profile-photo`, `telegram-get-saved-music`,
`telegram-get-global-privacy-settings`, `telegram-get-paid-reaction-privacy`,
`telegram-get-drafts`, `telegram-get-chat-members`,
`telegram-get-group-call-participants`, `telegram-get-message-read-participants`,
`telegram-get-poll-voters`, `telegram-get-story-views`, `telegram-get-boosts-list`,
`telegram-get-admin-log`, `telegram-get-sessions`.

Absent under `CHAT_POLICY=channels-and-groups`: `telegram-get-updates`,
`telegram-get-saved-dialogs`, `telegram-get-all-stories`,
`telegram-get-contact-requests`, `telegram-get-chat-folders`,
`telegram-get-suggested-folders`, `telegram-get-business-chat-links`,
`telegram-resolve-business-chat-link`.

---

## Cost and memory

- **Usage limit:** Railway → Workspace → Usage → set a **hard limit** (e.g. $10/month
  to start) plus an email alert at ~70 %. One replica is enough for ~30 people;
  do not scale replicas — the access-key tickets and rate limits live in memory
  and SQLite cannot be shared across replicas.
- **Memory per connected user:** `GET /health` returns `activeSessions` (live
  Telegram clients in memory). Compare it with the service's **Metrics → Memory**
  graph: `(memory now − memory with 0 sessions) ÷ activeSessions`. Expect a base
  of roughly 150–250 MB and on the order of 10–30 MB per live Telegram client;
  measure on your own deployment before raising limits.
