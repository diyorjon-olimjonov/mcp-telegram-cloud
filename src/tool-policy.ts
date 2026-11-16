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

import { type AllowedChats, chatAllowed, chatIds, isPublicChat } from "./chat-allowlist.js";

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

/**
 * Tools exposed in read-only mode although not annotated readOnlyHint:
 * `telegram-download-media` only fetches a file from a message (its "write" is a
 * 15-minute private copy on this server for download). It takes a chatId, so
 * CHAT_POLICY and the per-user allowlist decide which chats it can read from.
 * Hide it with HIDDEN_TOOLS=default,telegram-download-media.
 */
export const READ_ONLY_EXTRA_TOOLS: ReadonlySet<string> = new Set(["telegram-download-media"]);

export interface ToolPolicy {
  readonly mode: ToolMode;
  readonly hidden: ReadonlySet<string>;
  /** CHAT_POLICY; absent ⇒ "all" (upstream behavior, unit-test fixtures). */
  readonly chatPolicy?: ChatPolicy;
  /** CHAT_ALLOWLIST=on: with channels-and-groups, only chats the user ticked on /my/chats. */
  readonly chatAllowlist?: boolean;
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
  if (policy.mode === "read-only" && tool.annotations.readOnlyHint !== true && !READ_ONLY_EXTRA_TOOLS.has(tool.name)) {
    return false;
  }
  if (policy.chatPolicy === "channels-and-groups" && CHANNELS_ONLY_ABSENT_TOOLS.has(tool.name)) return false;
  if (allowlistActive(policy) && ALLOWLIST_ABSENT_TOOLS.has(tool.name)) return false;
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

// ─── Per-user chat allowlist (CHAT_ALLOWLIST) ────────────────────────────

/** `CHAT_ALLOWLIST=on` (default) | `off`. Only meaningful with CHAT_POLICY=channels-and-groups. */
export function parseChatAllowlist(raw: string | undefined): boolean {
  const v = raw?.trim().toLowerCase();
  if (!v || v === "on") return true;
  if (v === "off") return false;
  throw new Error(`CHAT_ALLOWLIST must be "on" or "off", got "${raw}".`);
}

export function allowlistActive(policy: ToolPolicy | undefined): boolean {
  return policy?.chatPolicy === "channels-and-groups" && policy.chatAllowlist === true;
}

/**
 * Tools that list groups/channels without a chat argument and whose output
 * cannot be matched to the allowlist (boosted channels, discussion-group
 * candidates). Absent while the allowlist is active, so names of chats the user
 * did not tick never reach the model.
 */
export const ALLOWLIST_ABSENT_TOOLS: ReadonlySet<string> = new Set([
  "telegram-get-groups-for-discussion",
  "telegram-get-my-boosts",
]);

/** Refusal for a group/channel the user has not ticked; points at the only place rules change. */
export function chatNotSelectedMsg(settingsUrl: string): string {
  return (
    "This group or channel is not in your readable list. The account owner can tick it at " +
    `${settingsUrl} (rules can only be changed there).`
  );
}

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
  /** Per-user allowlist (CHAT_ALLOWLIST=on): a group/channel must also be ticked. */
  allowlist?: { allowed: AllowedChats; refusal: string },
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
    if (allowlist) {
      const ids = chatIds(entity);
      if (!ids || !chatAllowed(ids.marked, isPublicChat(entity), allowlist.allowed)) return allowlist.refusal;
    }
  }
  return null;
}

type Typed = { type?: unknown; id?: unknown; username?: unknown };
const isGroupOrChannel = (x: Typed | null | undefined): boolean => x?.type === "group" || x?.type === "channel";

/**
 * Listing ids are marked (`-100…`, `-…`) for dialogs and bare for search results.
 * Search results carry `username` (public ⇒ allowed by default); dialog listings
 * do not, so list-chats / get-unread are answered by {@link allowlistAnswer}.
 */
function isAllowedListing(x: Typed | null | undefined, allowed: AllowedChats | undefined): boolean {
  if (!isGroupOrChannel(x)) return false;
  if (!allowed) return true;
  const isPublic = typeof x?.username === "string" && x.username.length > 0;
  return chatAllowed(String(x?.id ?? ""), isPublic, allowed);
}

// ─── Limits and allowlist-aware listings ────────────────────────────────

/** Upper bound for `limit` on the listing / reading tools (Telegram rate protection). */
export const LIMIT_CAP = 100;
export const LIMIT_CAPPED_TOOLS: ReadonlySet<string> = new Set([
  "telegram-list-chats",
  "telegram-get-unread",
  "telegram-search-chats",
  "telegram-search-global",
  "telegram-read-messages",
  "telegram-search-messages",
  "telegram-read-topic-messages",
  "telegram-get-replies",
  "telegram-list-topics",
]);

/** Said instead of a bare empty list, so the model knows why and does not blame the server. */
export function emptyListingMsg(settingsUrl: string): string {
  return (
    "No readable groups or channels found. Public groups/channels (with an @username) are readable by default; " +
    `private ones must be ticked by the account owner at ${settingsUrl} (sign in there with the access key). ` +
    "Private chats, bots and Saved Messages are never readable on this server. This is a setting, not a connection problem."
  );
}

interface RawDialog {
  id?: { toString(): string };
  title?: string;
  name?: string;
  isGroup?: boolean;
  isChannel?: boolean;
  unreadCount?: number;
  entity?: unknown;
}

/**
 * Answers `telegram-list-chats` / `telegram-get-unread` under the allowlist with
 * ONE raw dialog fetch (entities carry @username, so public-by-default works):
 * groups/channels only, filtered by the allowlist, `filterType` and `limit`.
 * Returns null when the tool should run normally.
 */
export async function allowlistAnswer(
  toolName: string,
  args: Record<string, unknown>,
  telegram: { getClient?: () => unknown },
  allowed: AllowedChats,
  settingsUrl: string,
): Promise<string | null> {
  if (toolName !== "telegram-list-chats" && toolName !== "telegram-get-unread") return null;
  const filter = args.filterType;
  if (filter === "private" || filter === "contact_requests") return emptyListingMsg(settingsUrl);
  const client = telegram.getClient?.() as { getDialogs(p: object): Promise<RawDialog[]> } | null | undefined;
  if (!client) return null;
  const limit = typeof args.limit === "number" && args.limit > 0 ? Math.min(args.limit, LIMIT_CAP) : 20;
  const offsetDate = typeof args.offsetDate === "number" ? args.offsetDate : undefined;
  // Over-fetch (bounded) because private chats and unticked groups are dropped below.
  const dialogs = await client.getDialogs({ limit: Math.min(limit * 3, 300), ...(offsetDate && { offsetDate }) });
  const rows: string[] = [];
  for (const d of dialogs) {
    if (!(d.isGroup || d.isChannel)) continue;
    const kind = d.isChannel && !d.isGroup ? "channel" : "group";
    if (filter !== undefined && filter !== kind) continue;
    const id = d.id?.toString() ?? "";
    if (!chatAllowed(id, isPublicChat(d.entity), allowed)) continue;
    const unread = d.unreadCount ?? 0;
    if (toolName === "telegram-get-unread" && unread <= 0) continue;
    rows.push(
      `${kind === "channel" ? "C" : "G"} ${d.title ?? d.name ?? ""} (${id})${unread > 0 ? ` [${unread} unread]` : ""}`,
    );
    if (rows.length >= limit) break;
  }
  return rows.length > 0 ? rows.join("\n") : emptyListingMsg(settingsUrl);
}

/**
 * Wrap a TelegramService so chat listings and searches only return groups and
 * channels (`type` is "private" for users, bots and Saved Messages). Methods run
 * against the real instance; everything else passes through untouched.
 */
export function restrictToGroupsAndChannels<T extends object>(
  telegram: T,
  /** Per-user allowlist: when given, listings also drop every chat that is not ticked. */
  allowed?: AllowedChats,
): T {
  const keep = (x: Typed | null | undefined) => isAllowedListing(x, allowed);
  const filters: Record<string, (out: unknown, args: unknown[]) => unknown> = {
    getDialogs: (out, args) =>
      args[2] === "private" || args[2] === "contact_requests" ? [] : (out as Typed[]).filter(keep),
    getUnreadDialogs: (out) => (out as Typed[]).filter(keep),
    searchChats: (out) => (out as Typed[]).filter(keep),
    searchGlobal: (out) => (out as { chat?: Typed }[]).filter((m) => keep(m.chat)),
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
