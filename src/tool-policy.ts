/**
 * Server-wide tool exposure policy (env-controlled, process constant).
 *
 * - `TOOL_MODE=read-only` (default): only tools annotated `readOnlyHint: true`
 *   are registered. Writes, "hard to undo" overwrites and deletions are absent
 *   from `tools/list`, and a `tools/call` naming one fails like any unknown tool
 *   (the registry also re-checks at call time as defence in depth).
 * - `TOOL_MODE=full`: upstream behavior (destructive tools still need the
 *   per-user opt-in on /my/settings).
 * - `HIDDEN_TOOLS`: comma-separated tool names removed in every mode. Unset ⇒
 *   {@link DEFAULT_HIDDEN_TOOLS} (personal-data reads). `none` ⇒ hide nothing.
 *   The token `default` expands to the default list, so
 *   `HIDDEN_TOOLS=default,telegram-get-sessions` extends it.
 */

export type ToolMode = "read-only" | "full";

/**
 * Personal-data read tools hidden by default. Every name exists in the catalogue
 * (pinned by tool-policy.test.ts). Groups: contacts; user profiles/photos;
 * privacy settings; drafts; member / participant / viewer lists; admin logs;
 * the account's active device sessions. The catalogue has no phone-resolution,
 * user-status or blocked-users READ tools (upstream keeps those behind
 * MCP_TELEGRAM_ENABLE_PERSONAL_DATA, which this image does not set).
 */
export const DEFAULT_HIDDEN_TOOLS: readonly string[] = [
  // contacts
  "telegram-get-contacts",
  "telegram-get-contact-requests",
  // user profiles / photos
  "telegram-get-profile",
  "telegram-get-profile-photo",
  "telegram-get-saved-music",
  // privacy settings
  "telegram-get-global-privacy-settings",
  "telegram-get-paid-reaction-privacy",
  // drafts
  "telegram-get-drafts",
  // member / participant / viewer lists
  "telegram-get-chat-members",
  "telegram-get-group-call-participants",
  "telegram-get-message-read-participants",
  "telegram-get-poll-voters",
  "telegram-get-story-views",
  "telegram-get-boosts-list",
  // admin logs
  "telegram-get-admin-log",
  // active device sessions (IPs, devices, locations)
  "telegram-get-sessions",
];

export interface ToolPolicy {
  readonly mode: ToolMode;
  readonly hidden: ReadonlySet<string>;
}

export function parseToolMode(raw: string | undefined): ToolMode {
  const v = raw?.trim().toLowerCase();
  if (!v || v === "read-only") return "read-only";
  if (v === "full") return "full";
  // A typo must never silently widen access.
  throw new Error(`TOOL_MODE must be "read-only" or "full", got "${raw}".`);
}

export function parseHiddenTools(raw: string | undefined): Set<string> {
  const v = raw?.trim();
  if (!v) return new Set(DEFAULT_HIDDEN_TOOLS);
  if (v.toLowerCase() === "none") return new Set();
  const out = new Set<string>();
  for (const name of v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)) {
    if (name === "default") for (const d of DEFAULT_HIDDEN_TOOLS) out.add(d);
    else out.add(name);
  }
  return out;
}

/** Whether a tool is exposed at all under `policy`. */
export function isToolExposed(
  tool: { readonly name: string; readonly annotations: { readonly readOnlyHint: boolean } },
  policy: ToolPolicy,
): boolean {
  if (policy.hidden.has(tool.name)) return false;
  if (policy.mode === "read-only" && tool.annotations.readOnlyHint !== true) return false;
  return true;
}
