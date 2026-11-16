/**
 * Per-user chat allowlist ("which of my groups/channels may be read").
 *
 * Active when CHAT_POLICY=channels-and-groups and CHAT_ALLOWLIST=on (default).
 * Deny by default: until a user ticks a group/channel on /my/chats, every chat
 * tool refuses and listings come back empty. The rules are edited ONLY on that
 * page (browser session + same-origin check); no MCP tool reads or changes them.
 *
 * Stored per row: owner user id, the chat's marked id (`-100…` channel /
 * supergroup, `-…` basic group), its bare id, title and kind (for the page).
 */
import type { Database } from "bun:sqlite";

export type ChatKind = "channel" | "group";

export interface AllowedChat {
  id: string; // marked id
  title: string;
  kind: ChatKind;
}

/** What the tool layer needs: membership by marked id (dialog ids) and by bare id (search results). */
export interface AllowedChats {
  marked: ReadonlySet<string>;
  bare: ReadonlySet<string>;
}

/**
 * Marked + bare id of a GramJS group/channel entity, or null for anything else.
 * Taken from the entity class, never by parsing a marked string: a basic group
 * whose id starts with "100" would otherwise be mistaken for a channel.
 */
export function chatIds(entity: unknown): { marked: string; bare: string } | null {
  const e = entity as { className?: unknown; id?: { toString(): string } } | null;
  const bare = e?.id?.toString();
  if (!bare || !/^\d+$/.test(bare)) return null;
  // Same form as GramJS getPeerId, which is what dialog ids carry ("-100" + id;
  // verified: channel 555 → "-100555").
  if (e?.className === "Channel" || e?.className === "ChannelForbidden") return { marked: `-100${bare}`, bare };
  if (e?.className === "Chat" || e?.className === "ChatForbidden") return { marked: `-${bare}`, bare };
  return null;
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
        added_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY (user_id, chat_id)
      )
    `);
  }

  list(userId: string): AllowedChat[] {
    return this.db
      .prepare("SELECT chat_id AS id, title, kind FROM chat_allowlist WHERE user_id = ? ORDER BY added_at DESC")
      .all(userId) as AllowedChat[];
  }

  forUser(userId: string): AllowedChats {
    const rows = this.db.prepare("SELECT chat_id, bare_id FROM chat_allowlist WHERE user_id = ?").all(userId) as {
      chat_id: string;
      bare_id: string;
    }[];
    return { marked: new Set(rows.map((r) => r.chat_id)), bare: new Set(rows.map((r) => r.bare_id)) };
  }

  /** `bare` must come from {@link chatIds} on the resolved entity. */
  allow(userId: string, chat: AllowedChat, bare: string): void {
    this.db
      .prepare(
        `INSERT INTO chat_allowlist (user_id, chat_id, bare_id, title, kind) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id, chat_id) DO UPDATE SET title = excluded.title, kind = excluded.kind`,
      )
      .run(userId, chat.id, bare, chat.title.slice(0, 256), chat.kind);
  }

  remove(userId: string, chatId: string): void {
    this.db.prepare("DELETE FROM chat_allowlist WHERE user_id = ? AND chat_id = ?").run(userId, chatId);
  }

  count(userId: string): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM chat_allowlist WHERE user_id = ?").get(userId) as { n: number })
      .n;
  }
}
