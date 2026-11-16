/**
 * `/my/chats` — the ONLY place a user decides which of their groups/channels the
 * MCP tools may read (CHAT_ALLOWLIST, deny by default). No MCP tool reads or
 * changes these rules.
 *
 *   GET  /my/chats              page (Uzbek)
 *   GET  /my/chats.js           its script (CSP is script-src 'self': no inline JS)
 *   GET  /my/chats/data?before= one page of dialogs (300 per page, most recent first)
 *   POST /my/chats/toggle       {id, on} — tick / untick one chat
 *
 * Auth: browser session (tg_sid) for a user with a saved Telegram session.
 * CSRF on the write: exact Origin match + JSON body (a cross-site page cannot send
 * application/json without a CORS preflight, and /my/* answers none).
 */
import type { Context } from "hono";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { css, cx } from "hono/css";
import type { FC } from "hono/jsx";
import { type ChatAllowlist, type ChatKind, chatIds } from "../chat-allowlist.js";
import { config } from "../config.js";
import { readBrowserSessionToken } from "../cookie-handler.js";
import { logger, logUser } from "../logger.js";
import type { OAuthProvider } from "../oauth.js";
import { Layout } from "../pages/Layout.js";
import { rateLimit } from "../rate-limit.js";
import type { SessionManager } from "../session-manager.js";
import { card, globalReset, subtitle, tg, title } from "../styles.js";

/** Dialogs fetched per page ("first 300 dialogs", then "Ko'proq ko'rsatish"). */
export const DIALOG_PAGE_SIZE = 300;

export interface MyChatsDeps {
  sessions: Pick<SessionManager, "getSavedUserIds" | "tryReconnectSession">;
  oauth: Pick<OAuthProvider, "getBrowserSessionUser">;
  allowlist: ChatAllowlist;
}

/** One row on the page. `id` is the marked chat id. */
export interface DialogRow {
  id: string;
  title: string;
  kind: ChatKind;
  members: number | null;
  /** Unix seconds of the last message, 0 if unknown. */
  date: number;
}

interface RawDialog {
  id?: { toString(): string };
  title?: string;
  name?: string;
  isGroup?: boolean;
  isChannel?: boolean;
  date?: number;
  entity?: { participantsCount?: number | null; megagroup?: boolean };
}

/** Groups and channels only (users, bots and Saved Messages are never listed). */
export function toDialogRows(dialogs: readonly RawDialog[]): DialogRow[] {
  return dialogs
    .filter((d) => d.isGroup || d.isChannel)
    .map((d) => ({
      id: d.id?.toString() ?? "",
      title: d.title ?? d.name ?? "",
      kind: (d.isChannel && !d.isGroup ? "channel" : "group") as ChatKind,
      members: typeof d.entity?.participantsCount === "number" ? d.entity.participantsCount : null,
      date: d.date ?? 0,
    }))
    .filter((r) => /^-\d+$/.test(r.id));
}

function requireUser(c: Context, deps: MyChatsDeps): string | null {
  const userId = deps.oauth.getBrowserSessionUser(readBrowserSessionToken(c.req.header("cookie")));
  if (!userId || !deps.sessions.getSavedUserIds().includes(userId)) return null;
  return userId;
}

function originMatchesIssuer(value: string | undefined): boolean {
  if (!value) return false;
  try {
    return new URL(value).origin === config.issuer;
  } catch {
    return false;
  }
}

const pageCss = `${globalReset}
  body { align-items: flex-start; }
  #chat-list { list-style: none; margin: 8px 0 0; padding: 0; text-align: left; }
  #chat-list li { border-bottom: 1px solid ${tg.outline}; }
  #chat-list label { display: flex; gap: 12px; align-items: flex-start; padding: 10px 4px; cursor: pointer; }
  #chat-list input { margin-top: 3px; width: 18px; height: 18px; flex: none; }
  .chat-title { font-weight: 600; word-break: break-word; }
  .chat-meta { color: ${tg.hint}; font-size: 13px; margin-top: 2px; }
  #chat-list li.ticked { background: ${tg.tertiaryBg}; }
`;

const wide = css`
  max-width: 640px;
  text-align: left;
`;
const searchBox = css`
  width: 100%;
  font-size: 16px;
  padding: 10px 12px;
  border: 1px solid ${tg.divider};
  border-radius: 10px;
  margin: 8px 0;
`;
const counter = css`
  font-weight: 600;
  margin: 4px 0;
`;
const moreBtn = css`
  margin-top: 16px;
  width: 100%;
  padding: 12px;
  border: 1px solid ${tg.divider};
  border-radius: 10px;
  background: ${tg.bg};
  color: ${tg.link};
  font-size: 15px;
  cursor: pointer;
`;
const hint = css`
  color: ${tg.hint};
  font-size: 13px;
`;

export const MyChatsPage: FC<{ username: string }> = (props) => (
  <Layout title={`${config.brandName} — Guruh va kanallar`} globalCss={pageCss}>
    <div class={cx(card, wide)}>
      <h1 class={title}>O'qiladigan guruh va kanallar</h1>
      <p class={subtitle}>
        @{props.username} — Claude faqat siz belgilagan guruh va kanallarni o'qiy oladi. Hech narsa belgilanmagan
        bo'lsa, hech biri o'qilmaydi. Shaxsiy chatlar, botlar va "Saqlangan xabarlar" hech qachon o'qilmaydi.
        <br />
        <span class={hint}>
          Only the groups and channels you tick here can be read. Rules can be changed only on this page.
        </span>
      </p>
      <input
        id="chat-search"
        class={searchBox}
        type="search"
        placeholder="Qidirish… / Search…"
        autocomplete="off"
        aria-label="Qidirish"
      />
      <p class={counter}>
        <span id="chat-count">0</span> ta tanlangan
      </p>
      <p id="chat-status" class={hint} role="status" aria-live="polite">
        Yuklanmoqda…
      </p>
      <ul id="chat-list" />
      <button id="chat-more" class={moreBtn} type="button" hidden>
        Ko'proq ko'rsatish
      </button>
      <p class={hint}>
        <a href="/my/settings">← Sozlamalar / Settings</a>
      </p>
    </div>
    <script src="/my/chats.js" defer />
  </Layout>
);

/** Client script. Rows are built with textContent only (titles are untrusted). */
export const MY_CHATS_JS = `"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const list = $("chat-list"), search = $("chat-search"), count = $("chat-count");
  const more = $("chat-more"), status = $("chat-status");
  const dialogs = new Map(); // id -> row, insertion order = most recent activity first
  const selected = new Map(); // id -> row
  let next = null, loading = false, firstLoad = true;

  const pad = (n) => String(n).padStart(2, "0");
  const fmtDate = (s) => {
    if (!s) return "";
    const d = new Date(s * 1000);
    return pad(d.getDate()) + "." + pad(d.getMonth() + 1) + "." + d.getFullYear();
  };
  const fmtNum = (n) => String(n).replace(/\\B(?=(\\d{3})+(?!\\d))/g, " ");
  const info = (id) => Object.assign({}, selected.get(id) || {}, dialogs.get(id) || {});

  function row(r, checked) {
    const li = document.createElement("li");
    if (checked) li.className = "ticked";
    const label = document.createElement("label");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = checked;
    box.addEventListener("change", () => toggle(r, box.checked, box));
    const text = document.createElement("div");
    const t = document.createElement("div");
    t.className = "chat-title";
    t.textContent = r.title || "(nomsiz)";
    const meta = document.createElement("div");
    meta.className = "chat-meta";
    const parts = [r.kind === "channel" ? "kanal" : "guruh"];
    if (typeof r.members === "number") parts.push(fmtNum(r.members) + " a'zo");
    if (r.date) parts.push("oxirgi faollik: " + fmtDate(r.date));
    meta.textContent = parts.join(" · ");
    text.append(t, meta);
    label.append(box, text);
    li.append(label);
    return li;
  }

  function render() {
    const q = search.value.trim().toLowerCase();
    const match = (r) => !q || (r.title || "").toLowerCase().includes(q);
    const pinned = [...selected.keys()].map(info).sort((a, b) => (b.date || 0) - (a.date || 0));
    list.replaceChildren();
    for (const r of pinned) if (match(r)) list.append(row(r, true));
    for (const r of dialogs.values()) if (!selected.has(r.id) && match(r)) list.append(row(r, false));
    count.textContent = String(selected.size);
    more.hidden = !next;
    if (!loading) {
      status.textContent = list.children.length
        ? ""
        : q ? "Hech narsa topilmadi." : "Guruh yoki kanal topilmadi.";
    }
  }

  async function load() {
    if (loading) return;
    loading = true;
    more.disabled = true;
    status.textContent = "Yuklanmoqda…";
    try {
      const url = "/my/chats/data" + (next ? "?before=" + encodeURIComponent(next) : "");
      const res = await fetch(url, { credentials: "same-origin", headers: { accept: "application/json" } });
      if (res.status === 401) { location.href = "/login"; return; }
      if (!res.ok) throw new Error(String(res.status));
      const data = await res.json();
      if (firstLoad) for (const s of data.selected) selected.set(s.id, s);
      firstLoad = false;
      for (const d of data.dialogs) dialogs.set(d.id, d);
      next = data.next;
      loading = false;
      render();
    } catch {
      loading = false;
      render();
      status.textContent = "Ro'yxatni yuklab bo'lmadi. Sahifani yangilang. / Could not load the list.";
    } finally {
      more.disabled = false;
    }
  }

  async function toggle(r, on, box) {
    box.disabled = true;
    try {
      const res = await fetch("/my/chats/toggle", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: r.id, on }),
      });
      if (!res.ok) throw new Error(String(res.status));
      if (on) selected.set(r.id, r); else selected.delete(r.id);
      render();
    } catch {
      box.checked = !on;
      box.disabled = false;
      status.textContent = "Saqlab bo'lmadi, qayta urinib ko'ring. / Could not save.";
    }
  }

  search.addEventListener("input", render);
  more.addEventListener("click", load);
  load();
})();
`;

export function createMyChatsRoutes(deps: MyChatsDeps): Hono {
  const app = new Hono({ strict: false });
  const limiter = rateLimit({ limit: 60, windowMs: 60_000, scope: "my_chats" });

  app.get("/chats.js", (c) => {
    c.header("Content-Type", "application/javascript; charset=utf-8");
    c.header("Cache-Control", "no-cache");
    return c.body(MY_CHATS_JS);
  });

  app.get("/chats", (c) => {
    const userId = requireUser(c, deps);
    if (!userId) return c.redirect(`${config.issuer}/login`, 302);
    c.header("Cache-Control", "no-store");
    return c.html(<MyChatsPage username={userId} />);
  });

  app.get("/chats/data", limiter, async (c) => {
    const userId = requireUser(c, deps);
    if (!userId) return c.json({ error: "unauthorized" }, 401);
    c.header("Cache-Control", "no-store");
    const before = Number(c.req.query("before") ?? "");
    const telegram = await deps.sessions.tryReconnectSession(userId);
    const client = telegram?.getClient?.();
    if (!client) return c.json({ error: "telegram_unavailable" }, 409);
    const raw = (await client.getDialogs({
      limit: DIALOG_PAGE_SIZE,
      ...(Number.isFinite(before) && before > 0 && { offsetDate: before }),
    })) as unknown as RawDialog[];
    const last = raw.length === DIALOG_PAGE_SIZE ? raw[raw.length - 1]?.date : undefined;
    return c.json({
      selected: deps.allowlist.list(userId),
      dialogs: toDialogRows(raw),
      next: last ? String(last) : null,
    });
  });

  app.post("/chats/toggle", limiter, bodyLimit({ maxSize: 4096 }), async (c) => {
    const userId = requireUser(c, deps);
    if (!userId) return c.json({ error: "unauthorized" }, 401);
    if (!originMatchesIssuer(c.req.header("origin"))) return c.json({ error: "forbidden" }, 403);
    if (!(c.req.header("content-type") ?? "").startsWith("application/json")) {
      return c.json({ error: "json_required" }, 415);
    }
    const body = (await c.req.json().catch(() => null)) as { id?: unknown; on?: unknown } | null;
    const id = typeof body?.id === "string" ? body.id : "";
    if (!/^-\d{1,20}$/.test(id) || typeof body?.on !== "boolean") return c.json({ error: "bad_request" }, 400);

    if (!body.on) {
      deps.allowlist.remove(userId, id);
    } else {
      // Only a group/channel this account can actually resolve can be ticked; the
      // stored title/kind come from Telegram, not from the request.
      const telegram = await deps.sessions.tryReconnectSession(userId);
      if (!telegram) return c.json({ error: "telegram_unavailable" }, 409);
      let entity: unknown;
      try {
        entity = await telegram.resolveChat(id);
      } catch {
        return c.json({ error: "chat_not_found" }, 404);
      }
      const ids = chatIds(entity);
      if (!ids || ids.marked !== id) return c.json({ error: "not_a_group_or_channel" }, 400);
      const e = entity as { className?: string; megagroup?: boolean; title?: string };
      const kind: ChatKind = e.className?.startsWith("Channel") && !e.megagroup ? "channel" : "group";
      deps.allowlist.allow(userId, { id, title: e.title ?? "", kind }, ids.bare);
    }
    logger.info(`Chat allowlist ${body.on ? "add" : "remove"}`, {
      component: "my",
      event: "chat_allowlist.toggle",
      userId: logUser(userId),
    });
    return c.json({ ok: true, count: deps.allowlist.count(userId) });
  });

  return app;
}
