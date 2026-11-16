/**
 * Per-user chat allowlist ("which of my groups/channels may be read").
 *
 * Active when CHAT_POLICY=channels-and-groups and CHAT_ALLOWLIST=on (default).
 * - PUBLIC groups/channels (they have an @username) count as ticked by default;
 *   the user may untick one, which stores an explicit "deny" row.
 * - PRIVATE groups/channels (invite-only, no @username) are readable only when
 *   the user ticks them.
 * The rules are edited ONLY on /my/chats (browser session + same-origin check);
 * no MCP tool reads or changes them.
 *
 * Stored per row: owner user id, the chat's marked id (`-100…` channel /
 * supergroup, `-…` basic group), its bare id, title, kind, and `allowed`
 * (1 = ticked, 0 = public chat explicitly unticked).
 */
import type { Database } from "bun:sqlite";

export type ChatKind = "channel" | "group";

export interface AllowedChat {
  id: string; // marked id
  title: string;
  kind: ChatKind;
}

/** What the tool layer needs, by marked id (dialog ids) and bare id (search results). */
export interface AllowedChats {
  marked: ReadonlySet<string>;
  bare: ReadonlySet<string>;
  /** Public chats the user explicitly unticked. */
  deniedMarked?: ReadonlySet<string>;
  deniedBare?: ReadonlySet<string>;
  /** The ticked chats themselves (title/kind). */
  chats?: readonly AllowedChat[];
}

/**
 * Marked + bare id of a GramJS group/channel entity, or null for anything else.
 * Taken from the entity class, never by parsing a marked string. Same form as
 * GramJS getPeerId, which is what dialog ids carry (channel 555 → "-100555").
 */
export function chatIds(entity: unknown): { marked: string; bare: string } | null {
  const e = entity as { className?: unknown; id?: { toString(): string } } | null;
  const bare = e?.id?.toString();
  if (!bare || !/^\d+$/.test(bare)) return null;
  if (e?.className === "Channel" || e?.className === "ChannelForbidden") return { marked: `-100${bare}`, bare };
  if (e?.className === "Chat" || e?.className === "ChatForbidden") return { marked: `-${bare}`, bare };
  return null;
}

/** A group/channel is public when it has an active @username. */
export function isPublicChat(entity: unknown): boolean {
  const e = entity as { username?: unknown; usernames?: { active?: boolean }[] } | null;
  if (typeof e?.username === "string" && e.username.length > 0) return true;
  return Array.isArray(e?.usernames) && e.usernames.some((u) => u?.active === true);
}

/**
 * The rule, in one place: an explicit untick wins, then an explicit tick, then
 * public-by-default. `id` is marked when it starts with "-", bare otherwise.
 */
export function chatAllowed(id: string, isPublic: boolean, allowed: AllowedChats): boolean {
  const marked = id.startsWith("-");
  const denied = marked ? allowed.deniedMarked : allowed.deniedBare;
  if (denied?.has(id)) return false;
  if ((marked ? allowed.marked : allowed.bare).has(id)) return true;
  return isPublic;
}

export class ChatAllowlist {
  constructor(private readonly db: Database) {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS chat_allowlist (
        user_id TEXT NOT NULL,
        chat_id TEXT NOT NULL,
        bare_id TEXT NOT NULL,
        title TEXT NOT NULL,
        kind TEXT NOT NULL,
        allowed INTEGER NOT NULL DEFAULT 1,
        added_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY (user_id, chat_id)
      )
    `);
    const cols = this.db.prepare("PRAGMA table_info(chat_allowlist)").all() as { name: string }[];
    if (!cols.some((c) => c.name === "allowed")) {
      this.db.exec("ALTER TABLE chat_allowlist ADD COLUMN allowed INTEGER NOT NULL DEFAULT 1");
    }
  }

  /** Ticked chats (allowed = 1), newest first. */
  list(userId: string): AllowedChat[] {
    return this.db
      .prepare(
        "SELECT chat_id AS id, title, kind FROM chat_allowlist WHERE user_id = ? AND allowed = 1 ORDER BY added_at DESC",
      )
      .all(userId) as AllowedChat[];
  }

  /** Marked ids of public chats the user unticked. */
  deniedIds(userId: string): string[] {
    return (
      this.db.prepare("SELECT chat_id FROM chat_allowlist WHERE user_id = ? AND allowed = 0").all(userId) as {
        chat_id: string;
      }[]
    ).map((r) => r.chat_id);
  }

  forUser(userId: string): AllowedChats {
    const rows = this.db
      .prepare("SELECT chat_id, bare_id, allowed FROM chat_allowlist WHERE user_id = ?")
      .all(userId) as { chat_id: string; bare_id: string; allowed: number }[];
    const on = rows.filter((r) => r.allowed === 1);
    const off = rows.filter((r) => r.allowed !== 1);
    return {
      marked: new Set(on.map((r) => r.chat_id)),
      bare: new Set(on.map((r) => r.bare_id)),
      deniedMarked: new Set(off.map((r) => r.chat_id)),
      deniedBare: new Set(off.map((r) => r.bare_id)),
      chats: this.list(userId),
    };
  }

  private upsert(userId: string, chat: AllowedChat, bare: string, allowed: 0 | 1): void {
    this.db
      .prepare(
        `INSERT INTO chat_allowlist (user_id, chat_id, bare_id, title, kind, allowed) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, chat_id) DO UPDATE SET title = excluded.title, kind = excluded.kind,
           allowed = excluded.allowed, added_at = datetime('now')`,
      )
      .run(userId, chat.id, bare, chat.title.slice(0, 256), chat.kind, allowed);
  }

  /** Tick. `bare` must come from {@link chatIds} on the resolved entity. */
  allow(userId: string, chat: AllowedChat, bare: string): void {
    this.upsert(userId, chat, bare, 1);
  }

  /** Untick a PUBLIC chat (which would otherwise be readable by default). */
  deny(userId: string, chat: AllowedChat, bare: string): void {
    this.upsert(userId, chat, bare, 0);
  }

  /** Forget any rule for this chat (a private chat goes back to unreadable). */
  remove(userId: string, chatId: string): void {
    this.db.prepare("DELETE FROM chat_allowlist WHERE user_id = ? AND chat_id = ?").run(userId, chatId);
  }

  /** Number of explicitly ticked chats. */
  count(userId: string): number {
    return (
      this.db.prepare("SELECT COUNT(*) AS n FROM chat_allowlist WHERE user_id = ? AND allowed = 1").get(userId) as {
        n: number;
      }
    ).n;
  }
}
