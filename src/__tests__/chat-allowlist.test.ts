/**
 * Per-user chat allowlist (CHAT_ALLOWLIST, deny by default) — tool enforcement
 * through the real registry, and the /my/chats page that is the only place the
 * rules change.
 */
process.env.ISSUER ??= "https://chat-allowlist-test.invalid";
process.env.TELEGRAM_API_ID ??= "1";
process.env.TELEGRAM_API_HASH ??= "stub";
process.env.MCP_TELEGRAM_TELEMETRY ??= "off";

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { TelegramService } from "@overpod/mcp-telegram/service";
import { Hono } from "hono";

const { Database } = await import("bun:sqlite");
const { registerAllTools } = await import("../tool-registry.js");
const { TOOLS } = await import("../tools.js");
const { ALLOWLIST_ABSENT_TOOLS, DEFAULT_HIDDEN_TOOLS, parseChatAllowlist } = await import("../tool-policy.js");
const { ChatAllowlist, chatIds } = await import("../chat-allowlist.js");
const { createMyChatsRoutes, DIALOG_PAGE_SIZE, MY_CHATS_JS } = await import("../routes/my-chats.js");
const { config } = await import("../config.js");
type Policy = import("../tool-policy.js").ToolPolicy;
type Allowed = import("../chat-allowlist.js").AllowedChats;

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const POLICY: Policy = {
  mode: "read-only",
  hidden: new Set(DEFAULT_HIDDEN_TOOLS),
  chatPolicy: "channels-and-groups",
  chatAllowlist: true,
};

// FV Hokimligi: PUBLIC channel (@fvhokimligi). Other: PRIVATE channel 555. Team: PRIVATE basic group 4001.
const ENTITIES: Record<string, { className: string; id: string; title: string; username?: string }> = {
  "@fvhokimligi": { className: "Channel", id: "1234567890", title: "FV Hokimligi", username: "fvhokimligi" },
  "-1001234567890": { className: "Channel", id: "1234567890", title: "FV Hokimligi", username: "fvhokimligi" },
  "-100555": { className: "Channel", id: "555", title: "Other" },
  "-4001": { className: "Chat", id: "4001", title: "Team" },
  "@alice": { className: "User", id: "77", title: "", username: "alice" },
};
const DIALOGS = [
  { id: "-1001234567890", name: "FV Hokimligi", type: "channel", unreadCount: 1, username: "fvhokimligi" },
  { id: "-100555", name: "Other", type: "channel", unreadCount: 1 },
  { id: "-4001", name: "Team", type: "group", unreadCount: 1 },
  { id: "77", name: "Alice", type: "private", unreadCount: 1, username: "alice" },
];
/** What GramJS client.getDialogs returns (entities carry @username). */
const RAW_DIALOGS = [
  {
    id: "-1001234567890",
    title: "FV Hokimligi",
    isChannel: true,
    isGroup: false,
    unreadCount: 1,
    entity: { username: "fvhokimligi" },
  },
  { id: "-100555", title: "Other", isChannel: true, isGroup: false, unreadCount: 1, entity: {} },
  { id: "-4001", title: "Team", isChannel: false, isGroup: true, unreadCount: 1, entity: {} },
  { id: "77", title: "Alice", isChannel: false, isGroup: false, unreadCount: 1, entity: { username: "alice" } },
];
const bareOf = (marked: string) => marked.replace(/^-(100)?/, "");

function fakeTelegram() {
  const calls: string[] = [];
  const argsOf: Record<string, unknown[]> = {};
  const impl: Record<string, (...a: unknown[]) => unknown> = {
    resolveChat: async (ref) => {
      const e = ENTITIES[String(ref)];
      if (!e) throw new Error("not found");
      return e;
    },
    getDialogs: async () => DIALOGS,
    getUnreadDialogs: async () => DIALOGS,
    searchChats: async () => DIALOGS.map((d) => ({ ...d, id: bareOf(d.id) })),
    searchGlobal: async () =>
      DIALOGS.map((d, i) => ({
        id: i,
        text: `post in ${d.name}`,
        sender: "x",
        date: "2026-01-01",
        chat: { ...d, id: bareOf(d.id) },
      })),
    getMessages: async () => [],
  };
  const rawClient = {
    getDialogs: async (p: unknown) => {
      calls.push("client.getDialogs");
      argsOf["client.getDialogs"] = [p];
      return RAW_DIALOGS;
    },
  };
  const telegram = new Proxy({} as TelegramService, {
    get(_t, prop) {
      const name = String(prop);
      if (name === "then") return undefined;
      if (name === "getClient") return () => rawClient;
      return async (...args: unknown[]) => {
        calls.push(name);
        argsOf[name] = args;
        const fn = impl[name];
        if (!fn) throw new Error(`unexpected Telegram call ${name}`);
        return fn(...args);
      };
    },
  });
  return { telegram, calls, argsOf };
}

type Handler = (a: unknown, e: unknown) => Promise<CallToolResult>;

function register(allowedChats?: () => Allowed) {
  const fake = fakeTelegram();
  const server = new McpServer({ name: "allowlist-test", version: "0.0.0" });
  registerAllTools(server, TOOLS, {
    getTelegram: () => fake.telegram,
    requireConnection: async () => null,
    policy: POLICY,
    chatSettingsUrl: "https://host.example/my/chats",
    ...(allowedChats && { allowedChats }),
  });
  // biome-ignore lint/suspicious/noExplicitAny: call registered handlers directly
  const registered = (server as any)._registeredTools as Record<string, { handler: Handler }>;
  const call = async (name: string, args: Record<string, unknown>) => {
    fake.calls.length = 0;
    const r = await registered[name]?.handler(args, {});
    assert.ok(r, `${name} not registered`);
    return r;
  };
  return { registered, call, calls: fake.calls, argsOf: fake.argsOf };
}

const text = (r: CallToolResult) => r.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");

const store = () => new ChatAllowlist(new Database(":memory:"));

function tick(list: InstanceType<typeof ChatAllowlist>, user: string, ref: string) {
  const e = ENTITIES[ref];
  const ids = chatIds(e);
  assert.ok(e && ids);
  list.allow(user, { id: ids.marked, title: e.title, kind: e.className === "Chat" ? "group" : "channel" }, ids.bare);
}
function untick(list: InstanceType<typeof ChatAllowlist>, user: string, ref: string) {
  const e = ENTITIES[ref];
  const ids = chatIds(e);
  assert.ok(e && ids);
  list.deny(user, { id: ids.marked, title: e.title, kind: "channel" }, ids.bare);
}
const LISTINGS = [
  ["telegram-list-chats", { limit: 20 }],
  ["telegram-get-unread", { limit: 20 }],
  ["telegram-search-chats", { query: "a", limit: 20 }],
  ["telegram-search-global", { query: "a", limit: 20 }],
] as const;

describe("chat allowlist — ids and parsing", () => {
  it("marks ids exactly like GramJS dialog ids", () => {
    assert.deepEqual(chatIds({ className: "Channel", id: "1234567890" }), {
      marked: "-1001234567890",
      bare: "1234567890",
    });
    assert.deepEqual(chatIds({ className: "Channel", id: "555" }), { marked: "-100555", bare: "555" });
    assert.deepEqual(chatIds({ className: "Chat", id: "4001" }), { marked: "-4001", bare: "4001" });
    assert.equal(chatIds({ className: "User", id: "77" }), null);
  });

  it("CHAT_ALLOWLIST defaults to on; typo fails", () => {
    assert.equal(parseChatAllowlist(undefined), true);
    assert.equal(parseChatAllowlist("off"), false);
    assert.throws(() => parseChatAllowlist("maybe"), /CHAT_ALLOWLIST/);
    assert.equal(config.toolPolicy.chatAllowlist, true);
  });
});

describe("chat allowlist — public by default, private needs a tick", () => {
  it("nothing ticked: a PUBLIC channel is readable, PRIVATE groups/channels are refused before the read", async () => {
    const list = store();
    for (const r of [register(() => list.forUser("u1")), register()]) {
      const pub = await r.call("telegram-read-messages", { chatId: "@fvhokimligi", limit: 3 });
      assert.notEqual(pub.isError, true, text(pub));
      assert.deepEqual(r.calls, ["resolveChat", "getMessages"]);
      for (const chatId of ["-100555", "-4001"]) {
        const res = await r.call("telegram-read-messages", { chatId, limit: 3 });
        assert.equal(res.isError, true);
        assert.match(text(res), /not in your readable list.*https:\/\/host\.example\/my\/chats/);
        assert.deepEqual(r.calls, ["resolveChat"]);
      }
    }
  });

  it("nothing ticked: listings show public groups/channels only", async () => {
    const list = store();
    const { call } = register(() => list.forUser("u1"));
    for (const [name, args] of LISTINGS) {
      const out = text(await call(name, args));
      assert.match(out, /FV Hokimligi/, name);
      assert.ok(!/Other|Team|Alice/.test(out), `${name}: ${out}`);
    }
  });

  it("an empty listing explains why instead of looking broken", async () => {
    const list = store();
    const { call } = register(() => list.forUser("u1"));
    const out = text(await call("telegram-list-chats", { limit: 20, filterType: "group" }));
    assert.match(
      out,
      /No readable groups or channels found.*https:\/\/host\.example\/my\/chats.*not a connection problem/,
    );
  });

  it("tools that list chats without a way to filter them are absent", () => {
    const { registered } = register(() => store().forUser("u1"));
    for (const n of ALLOWLIST_ABSENT_TOOLS) assert.ok(!registered[n], `${n} must be absent`);
  });
});

describe("chat allowlist — ticking and unticking", () => {
  it("ticking a private chat makes it readable; removing the tick makes it unreadable again", async () => {
    const list = store();
    const { call, calls } = register(() => list.forUser("u1"));
    tick(list, "u1", "-100555");
    const ok = await call("telegram-read-messages", { chatId: "-100555", limit: 3 });
    assert.notEqual(ok.isError, true, text(ok));
    assert.deepEqual(calls, ["resolveChat", "getMessages"]);
    list.remove("u1", "-100555");
    assert.match(text(await call("telegram-read-messages", { chatId: "-100555" })), /not in your readable list/);
  });

  it("unticking a PUBLIC chat blocks it and hides it from listings", async () => {
    const list = store();
    untick(list, "u1", "@fvhokimligi");
    const { call } = register(() => list.forUser("u1"));
    assert.match(text(await call("telegram-read-messages", { chatId: "@fvhokimligi" })), /not in your readable list/);
    for (const [name, args] of LISTINGS) {
      assert.ok(!/FV Hokimligi/.test(text(await call(name, args))), name);
    }
    tick(list, "u1", "@fvhokimligi");
    assert.notEqual((await call("telegram-read-messages", { chatId: "@fvhokimligi" })).isError, true);
  });

  it("private 1:1 chats stay blocked regardless (even with an @username)", async () => {
    const { call } = register(() => store().forUser("u1"));
    assert.match(
      text(await call("telegram-read-messages", { chatId: "@alice", limit: 3 })),
      /only reads channels and groups/,
    );
  });

  it("listings show ticked private chats plus public ones (marked and bare ids)", async () => {
    const list = store();
    tick(list, "u1", "-4001");
    const { call } = register(() => list.forUser("u1"));
    for (const [name, args] of LISTINGS) {
      const out = text(await call(name, args));
      assert.match(out, /FV Hokimligi/, name);
      assert.match(out, /Team/, name);
      assert.ok(!/Other|Alice/.test(out), `${name}: ${out}`);
    }
  });

  it("rules are per user", async () => {
    const list = store();
    tick(list, "u1", "-100555");
    const { call } = register(() => list.forUser("u2"));
    assert.match(text(await call("telegram-read-messages", { chatId: "-100555" })), /not in your readable list/);
  });
});

describe("listing limits", () => {
  it("a huge limit is capped before Telegram is asked", async () => {
    const { call, argsOf } = register(() => store().forUser("u1"));
    await call("telegram-read-messages", { chatId: "@fvhokimligi", limit: 5000 });
    assert.equal(argsOf.getMessages?.[1], 100);
    await call("telegram-list-chats", { limit: 5000 });
    const p = argsOf["client.getDialogs"]?.[0] as { limit: number };
    assert.ok(p.limit <= 300, `dialog fetch limit ${p.limit}`);
  });
});

describe("chat allowlist — no MCP tool can read or change the rules", () => {
  it("tool modules never touch the allowlist", () => {
    for (const f of readdirSync(join(SRC, "tools"))) {
      const src = readFileSync(join(SRC, "tools", f), "utf8");
      assert.ok(!/chat-allowlist|allowedChats|chat_allowlist/.test(src), `${f} references the allowlist`);
    }
  });

  it("handlers never receive the allowlist in their deps", async () => {
    const list = store();
    tick(list, "u1", "@fvhokimligi");
    let seen: string[] = [];
    const server = new McpServer({ name: "deps-test", version: "0.0.0" });
    registerAllTools(
      server,
      [
        {
          name: "telegram-probe",
          description: "probe",
          annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
          skipRequireConnection: true,
          handler: async (_a, deps) => {
            seen = Object.keys(deps);
            return { content: [{ type: "text", text: "ok" }] };
          },
        },
      ],
      {
        getTelegram: () => fakeTelegram().telegram,
        requireConnection: async () => null,
        policy: POLICY,
        allowedChats: () => list.forUser("u1"),
      },
    );
    // biome-ignore lint/suspicious/noExplicitAny: call registered handler directly
    await (server as any)._registeredTools["telegram-probe"].handler({}, {});
    assert.ok(seen.length > 0);
    assert.ok(!seen.some((k) => /allow|chat/i.test(k)), `deps: ${seen.join(",")}`);
  });

  it("no tool name or description is about managing chat rules", () => {
    for (const t of TOOLS) assert.ok(!/allowlist|readable list/i.test(`${t.name} ${t.description}`), t.name);
  });
});

describe("/my/chats page", () => {
  const ISSUER = config.issuer;
  const RAW_DIALOGS = [
    {
      id: "-1001234567890",
      title: "FV Hokimligi",
      isChannel: true,
      isGroup: false,
      date: 1_763_000_000,
      entity: { participantsCount: 12_345 },
    },
    { id: "77", title: "Alice", isChannel: false, isGroup: false, date: 1_762_900_000, entity: {} },
    {
      id: "-4001",
      title: "Team",
      isChannel: false,
      isGroup: true,
      date: 1_762_800_000,
      entity: { participantsCount: 8 },
    },
    {
      id: "-100555",
      title: "Other",
      isChannel: true,
      isGroup: true,
      date: 1_762_700_000,
      entity: { participantsCount: null },
    },
  ];

  function app(opts: { signedIn?: boolean; dialogs?: unknown[] } = {}) {
    const list = store();
    const getDialogsCalls: unknown[] = [];
    const telegram = {
      getClient: () => ({
        getDialogs: async (p: unknown) => {
          getDialogsCalls.push(p);
          return opts.dialogs ?? RAW_DIALOGS;
        },
      }),
      resolveChat: async (ref: string) => {
        const e = ENTITIES[ref];
        if (!e) throw new Error("nf");
        return e;
      },
    };
    const a = new Hono();
    a.route(
      "/my",
      createMyChatsRoutes({
        sessions: { getSavedUserIds: () => ["alice"], tryReconnectSession: async () => telegram as never },
        oauth: { getBrowserSessionUser: () => (opts.signedIn === false ? null : "alice") },
        allowlist: list,
      }),
    );
    const ip = `10.9.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
    const get = (path: string) => a.request(path, { headers: { "x-real-ip": ip } });
    const post = (body: unknown, headers: Record<string, string> = {}) =>
      a.request("/my/chats/toggle", {
        method: "POST",
        headers: { origin: ISSUER, "content-type": "application/json", "x-real-ip": ip, ...headers },
        body: JSON.stringify(body),
      });
    return { get, list, post, getDialogsCalls };
  }

  it("requires a signed-in browser session", async () => {
    const res = await app({ signedIn: false }).get("/my/chats");
    assert.equal(res.status, 302);
    assert.match(res.headers.get("location") ?? "", /\/my\/key\?next=\/my\/chats$/);
    assert.equal((await app({ signedIn: false }).get("/my/chats/data")).status, 401);
  });

  it("renders the checklist UI: search, counter, 'Ko'proq ko'rsatish', no select-all", async () => {
    const html = await (await app().get("/my/chats")).text();
    assert.match(html, /id="chat-search"/);
    assert.match(html, /ta tanlangan/);
    assert.match(html, /Ko&#39;proq ko&#39;rsatish|Ko'proq ko'rsatish/);
    assert.match(html, /<script src="\/my\/chats\.js"/);
    for (const s of [html, MY_CHATS_JS]) assert.ok(!/select.?all|hammasini|barchasini/i.test(s), "no select-all");
  });

  it("serves the script as JavaScript, filters as you type, builds rows without innerHTML", async () => {
    const res = await app().get("/my/chats.js");
    assert.match(res.headers.get("content-type") ?? "", /javascript/);
    const js = await res.text();
    assert.ok(!/innerHTML/.test(js));
    assert.match(js, /addEventListener\("input", render\)/);
    assert.match(js, /kanal/);
    assert.match(js, /guruh/);
  });

  it("data: first 300 dialogs, groups/channels only, most recent first, with type/members/date", async () => {
    const { get, getDialogsCalls } = app();
    const body = (await (await get("/my/chats/data")).json()) as { dialogs: Record<string, unknown>[]; next: unknown };
    assert.equal(DIALOG_PAGE_SIZE, 300);
    assert.deepEqual(getDialogsCalls, [{ limit: 300 }]);
    assert.deepEqual(
      body.dialogs.map((d) => [d.id, d.kind, d.members]),
      [
        ["-1001234567890", "channel", 12_345],
        ["-4001", "group", 8],
        ["-100555", "group", null],
      ],
    );
    assert.equal(body.dialogs[0]?.date, 1_763_000_000);
    assert.equal(body.next, null, "fewer than 300 ⇒ no more pages");
  });

  it("data: a full page offers 'more', and the next request continues from the last date", async () => {
    const full = Array.from({ length: 300 }, (_, i) => ({
      id: `-${5000 + i}`,
      title: `G${i}`,
      isGroup: true,
      date: 2_000_000 - i,
    }));
    const { get, getDialogsCalls } = app({ dialogs: full });
    const first = (await (await get("/my/chats/data")).json()) as { next: string };
    assert.equal(first.next, String(2_000_000 - 299));
    await get(`/my/chats/data?before=${first.next}`);
    assert.deepEqual(getDialogsCalls[1], { limit: 300, offsetDate: 2_000_000 - 299 });
  });

  it("toggle: same-origin JSON only", async () => {
    const { post, list } = app();
    assert.equal((await post({ id: "-1001234567890", on: true }, { origin: "https://evil.example" })).status, 403);
    assert.equal((await post({ id: "-1001234567890", on: true }, { "content-type": "text/plain" })).status, 415);
    assert.equal((await post({ id: "not-an-id", on: true })).status, 400);
    assert.equal(list.count("alice"), 0);
  });

  it("toggle: ticks with the title from Telegram (not the request), unticks, refuses unknown chats", async () => {
    const { post, list } = app();
    const on = await post({ id: "-1001234567890", on: true, title: "spoofed" });
    assert.equal(on.status, 200);
    assert.deepEqual(list.list("alice"), [{ id: "-1001234567890", title: "FV Hokimligi", kind: "channel" }]);
    assert.ok(list.forUser("alice").bare.has("1234567890"));

    assert.equal((await post({ id: "-4001", on: true })).status, 200);
    assert.equal(list.count("alice"), 2);

    assert.equal((await post({ id: "-1001234567890", on: false })).status, 200);
    assert.deepEqual(
      list.list("alice").map((r) => r.id),
      ["-4001"],
    );

    assert.equal((await post({ id: "-77", on: true })).status, 404, "unknown chat");
    assert.equal(list.count("alice"), 1);
  });

  it("selected chats come back with the data for pinning", async () => {
    const { get, post } = app();
    await post({ id: "-4001", on: true });
    const body = (await (await get("/my/chats/data")).json()) as { selected: { id: string }[] };
    assert.deepEqual(
      body.selected.map((s) => s.id),
      ["-4001"],
    );
  });
});
