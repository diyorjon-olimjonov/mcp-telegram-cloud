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
  /** CHAT_POLICY; absent ⇒ "all" (upstream behavior, unit-test fixtures). */
  readonly chatPolicy?: ChatPolicy;
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
  if (policy.chatPolicy === "channels-and-groups" && CHANNELS_ONLY_ABSENT_TOOLS.has(tool.name)) return false;
  return true;
}

// ─── Chat-type policy (CHAT_POLICY) ─────────────────────────────────────

/**
 * `CHAT_POLICY=channels-and-groups` (default): private 1:1 chats, bots and Saved
 * Messages are off limits. Enforced server-side in three places:
 *  1. tools that read across chats with no way to filter the result are not
 *     registered at all ({@link CHANNELS_ONLY_ABSENT_TOOLS});
 *  2. every chat argument ({@link CHAT_ARG_KEYS}) is resolved and must be a group
 *     or channel BEFORE the tool's Telegram call runs ({@link checkChatArgs});
 *  3. chat listings / searches drop private chats and bots from their results
 *     ({@link restrictToGroupsAndChannels}).
 * `CHAT_POLICY=all`: upstream behavior.
 */
export type ChatPolicy = "channels-and-groups" | "all";

export function parseChatPolicy(raw: string | undefined): ChatPolicy {
  const v = raw?.trim().toLowerCase();
  if (!v || v === "channels-and-groups") return "channels-and-groups";
  if (v === "all") return "all";
  throw new Error(`CHAT_POLICY must be "channels-and-groups" or "all", got "${raw}".`);
}

/** Arguments that name a chat/peer whose messages, media or metadata a tool touches. */
export const CHAT_ARG_KEYS = ["chatId", "fromChatId", "toChatId", "chat", "peer", "entityId", "channelId"] as const;

/**
 * Cross-chat tools that cannot be restricted to groups/channels by filtering:
 * raw update streams, Saved Messages, contacts' stories, contact requests,
 * folder definitions (which list private peers) and business chat links (which
 * open private chats). Not registered under `channels-and-groups`.
 */
export const CHANNELS_ONLY_ABSENT_TOOLS: ReadonlySet<string> = new Set([
  "telegram-get-updates",
  "telegram-get-saved-dialogs",
  "telegram-get-all-stories",
  "telegram-get-contact-requests",
  "telegram-get-chat-folders",
  "telegram-get-suggested-folders",
  "telegram-get-business-chat-links",
  "telegram-resolve-business-chat-link",
]);

export const CHAT_BLOCKED_MSG =
  "This server only reads channels and groups. Private chats, bots and Saved Messages are not available.";
export const CHAT_UNVERIFIED_MSG =
  "Could not verify that this chat is a group or channel, so it was not read. Use the @username or numeric ID from telegram-list-chats.";

/** GramJS entity classes that are groups or channels (basic groups, supergroups, broadcast channels). */
const GROUP_OR_CHANNEL = new Set(["Chat", "ChatForbidden", "Channel", "ChannelForbidden"]);
const SELF_REF = /^@?(me|self|saved|saved messages)$/i;

/**
 * Check every chat argument of a call. Returns null when all are groups or
 * channels, else the refusal text. Fails closed: a chat that cannot be resolved
 * is refused. Auth errors are re-thrown so the session-revoked path still runs.
 */
export async function checkChatArgs(
  args: Record<string, unknown>,
  telegram: { resolveChat(chatId: string): Promise<unknown> },
  isAuthError: (e: unknown) => boolean = () => false,
): Promise<string | null> {
  for (const key of CHAT_ARG_KEYS) {
    const raw = args[key];
    if (raw === undefined || raw === null || raw === "") continue;
    const ref = String(raw).trim();
    if (SELF_REF.test(ref)) return CHAT_BLOCKED_MSG;
    let entity: unknown;
    try {
      entity = await telegram.resolveChat(ref);
    } catch (e) {
      if (isAuthError(e)) throw e;
      return CHAT_UNVERIFIED_MSG;
    }
    const cls = (entity as { className?: unknown } | null)?.className;
    if (typeof cls !== "string" || !GROUP_OR_CHANNEL.has(cls)) return CHAT_BLOCKED_MSG;
  }
  return null;
}

type Typed = { type?: unknown };
const isGroupOrChannel = (x: Typed | null | undefined): boolean => x?.type === "group" || x?.type === "channel";

/**
 * Wrap a TelegramService so chat listings and searches only return groups and
 * channels (`type` is "private" for users, bots and Saved Messages). Methods run
 * against the real instance; everything else passes through untouched.
 */
export function restrictToGroupsAndChannels<T extends object>(telegram: T): T {
  const filters: Record<string, (out: unknown, args: unknown[]) => unknown> = {
    getDialogs: (out, args) =>
      args[2] === "private" || args[2] === "contact_requests" ? [] : (out as Typed[]).filter(isGroupOrChannel),
    getUnreadDialogs: (out) => (out as Typed[]).filter(isGroupOrChannel),
    searchChats: (out) => (out as Typed[]).filter(isGroupOrChannel),
    searchGlobal: (out) => (out as { chat?: Typed }[]).filter((m) => isGroupOrChannel(m.chat)),
  };
  return new Proxy(telegram, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target);
      if (typeof value !== "function") return value;
      const filter = typeof prop === "string" ? filters[prop] : undefined;
      if (!filter) return value.bind(target);
      return async (...args: unknown[]) => filter(await value.apply(target, args), args);
    },
  });
}
