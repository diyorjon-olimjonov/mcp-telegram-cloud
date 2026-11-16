/**
 * CHAT_POLICY=channels-and-groups (src/tool-policy.ts + tool-registry.ts).
 *
 * Every registered tool that takes a chat argument is driven through the real
 * registry wrapper with a Telegram double: a private user, a bot or Saved
 * Messages must be refused BEFORE any Telegram call other than the chat-type
 * lookup itself, and listings/searches must drop private chats from results.
 */
process.env.ISSUER ??= "https://chat-policy-test.invalid";
process.env.TELEGRAM_API_ID ??= "1";
process.env.TELEGRAM_API_HASH ??= "stub";
process.env.MCP_TELEGRAM_TELEMETRY ??= "off";

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { TelegramService } from "@overpod/mcp-telegram/service";

const { registerAllTools } = await import("../tool-registry.js");
const { TOOLS } = await import("../tools.js");
const {
  CHANNELS_ONLY_ABSENT_TOOLS,
  CHAT_ARG_KEYS,
  CHAT_BLOCKED_MSG,
  CHAT_UNVERIFIED_MSG,
  DEFAULT_HIDDEN_TOOLS,
  parseChatPolicy,
} = await import("../tool-policy.js");
const { config } = await import("../config.js");
type Policy = import("../tool-policy.js").ToolPolicy;

/** Entities the fake resolves, by the reference a caller would type. */
const ENTITIES: Record<string, { className: string; bot?: boolean }> = {
  "@alice": { className: "User" },
  "123456": { className: "User" },
  "@helper_bot": { className: "User", bot: true },
  "@fvhokimligi": { className: "Channel" },
  "-1001234567890": { className: "Channel" },
  "-4001": { className: "Chat" },
};

const DIALOGS = [
  { id: "1", name: "Alice", type: "private", unreadCount: 2 },
  { id: "2", name: "Helper Bot", type: "private", unreadCount: 1, isBot: true },
  { id: "3", name: "Saved Messages", type: "private", unreadCount: 0 },
  { id: "-1001", name: "Hokimlik News", type: "channel", unreadCount: 5 },
  { id: "-4001", name: "Team Group", type: "group", unreadCount: 3 },
];

function fakeTelegram() {
  const calls: string[] = [];
  const impl: Record<string, (...a: unknown[]) => unknown> = {
    resolveChat: async (ref) => {
      const e = ENTITIES[String(ref)];
      if (!e) throw new Error(`Cannot find chat "${ref}"`);
      return e;
    },
    getDialogs: async (_l, _o, filterType) => (filterType ? DIALOGS.filter((d) => d.type === filterType) : DIALOGS),
    getUnreadDialogs: async () => DIALOGS.filter((d) => d.unreadCount > 0),
    searchChats: async () => DIALOGS,
    searchGlobal: async () =>
      DIALOGS.map((d, i) => ({ id: i, text: `msg in ${d.name}`, sender: "x", date: "2026-01-01", chat: d })),
    getMessages: async () => [],
  };
  const telegram = new Proxy({} as TelegramService, {
    get(_t, prop) {
      const name = String(prop);
      if (name === "then") return undefined;
      return async (...args: unknown[]) => {
        calls.push(name);
        const fn = impl[name];
        if (!fn) throw new Error(`unexpected Telegram call ${name}`);
        return fn(...args);
      };
    },
  });
  return { telegram, calls };
}

type Handler = (args: unknown, extra: unknown) => Promise<CallToolResult>;

function register(policy: Policy) {
  const fake = fakeTelegram();
  const server = new McpServer({ name: "chat-policy-test", version: "0.0.0" });
  registerAllTools(server, TOOLS, {
    getTelegram: () => fake.telegram,
    requireConnection: async () => null,
    checkDestructive: () => null,
    recordDestructive: () => {},
    policy,
  });
  // biome-ignore lint/suspicious/noExplicitAny: reaching the SDK's registry to call handlers without schema-specific args
  const registered = (server as any)._registeredTools as Record<string, { handler: Handler }>;
  const call = async (name: string, args: Record<string, unknown>) => {
    fake.calls.length = 0;
    const tool = registered[name];
    assert.ok(tool, `${name} not registered`);
    return tool.handler(args, {});
  };
  return { registered, call, calls: fake.calls };
}

const text = (r: CallToolResult) => r.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");

const CHANNELS: Policy = {
  mode: "read-only",
  hidden: new Set(DEFAULT_HIDDEN_TOOLS),
  chatPolicy: "channels-and-groups",
};
/** Widest surface the policy must hold for: every tool, nothing hidden. */
const CHANNELS_FULL: Policy = { mode: "full", hidden: new Set(), chatPolicy: "channels-and-groups" };

const chatTools = (registered: Record<string, unknown>) =>
  TOOLS.filter((t) => registered[t.name] && CHAT_ARG_KEYS.some((k) => t.inputSchema && k in t.inputSchema));

describe("chat policy — parsing and defaults", () => {
  it("defaults to channels-and-groups; a typo fails loudly", () => {
    assert.equal(parseChatPolicy(undefined), "channels-and-groups");
    assert.equal(parseChatPolicy("ALL"), "all");
    assert.throws(() => parseChatPolicy("channels"), /CHAT_POLICY/);
    assert.equal(config.toolPolicy.chatPolicy, "channels-and-groups");
  });
});

describe("chat policy — private chats, bots and Saved Messages are blocked in every chat tool", () => {
  for (const [label, policy] of [
    ["read-only", CHANNELS],
    ["full (all tools)", CHANNELS_FULL],
  ] as const) {
    it(`${label}: refuses before any Telegram read`, async () => {
      const { registered, call, calls } = register(policy);
      const tools = chatTools(registered);
      assert.ok(tools.length >= (label === "read-only" ? 25 : 90), `expected many chat tools, got ${tools.length}`);
      const checked = new Set<string>();
      for (const ref of ["@alice", "123456", "@helper_bot", "me", "@me", "Saved Messages"]) {
        for (const t of tools) {
          // Enough generic args to pass each tool's own preValidate, so the chat check is what refuses.
          const args: Record<string, unknown> = {
            messageId: 1,
            messageIds: [1],
            limit: 5,
            text: "x",
            query: "x",
            row: 0,
            column: 0,
          };
          for (const k of CHAT_ARG_KEYS) if (t.inputSchema && k in t.inputSchema) args[k] = ref;
          const res = await call(t.name, args);
          // A tool whose own argument validation rejects the generic args never reaches
          // Telegram either; everything else must be stopped by the chat check itself.
          const preValidated = (t.preValidate as ((a: unknown) => unknown) | undefined)?.(args) != null;
          if (preValidated) {
            assert.deepEqual(calls, [], `${t.name}(${ref}) reached Telegram`);
            continue;
          }
          checked.add(t.name);
          assert.equal(res.isError, true, `${t.name}(${ref}) must be refused`);
          assert.equal(text(res), CHAT_BLOCKED_MSG, `${t.name}(${ref})`);
          assert.ok(
            calls.every((c) => c === "resolveChat"),
            `${t.name}(${ref}) reached Telegram: ${calls.join(",")}`,
          );
        }
      }
      assert.ok(checked.size >= tools.length - 10, `chat check exercised on ${checked.size}/${tools.length}`);
      if (label === "read-only") assert.equal(checked.size, tools.length, "every read tool hits the chat check");
    });
  }

  it("a chat that cannot be resolved is refused (fail closed)", async () => {
    const { call, calls } = register(CHANNELS);
    const res = await call("telegram-read-messages", { chatId: "Some Unknown Person", limit: 5 });
    assert.equal(text(res), CHAT_UNVERIFIED_MSG);
    assert.deepEqual(calls, ["resolveChat"]);
  });

  it("forwarding checks both ends", async () => {
    const { call, calls } = register(CHANNELS_FULL);
    const res = await call("telegram-forward-message", {
      fromChatId: "@fvhokimligi",
      toChatId: "@alice",
      messageIds: [1],
    });
    assert.equal(text(res), CHAT_BLOCKED_MSG);
    assert.ok(calls.every((c) => c === "resolveChat"));
  });
});

describe("chat policy — groups and channels work", () => {
  it("reads a public channel by @username, a supergroup and a basic group by id", async () => {
    const { call, calls } = register(CHANNELS);
    for (const chatId of ["@fvhokimligi", "-1001234567890", "-4001"]) {
      const res = await call("telegram-read-messages", { chatId, limit: 3 });
      assert.notEqual(res.isError, true, `${chatId}: ${text(res)}`);
      assert.deepEqual(calls, ["resolveChat", "getMessages"]);
    }
  });
});

describe("chat policy — listings exclude private chats and bots", () => {
  it("list-chats", async () => {
    const { call } = register(CHANNELS);
    const out = text(await call("telegram-list-chats", { limit: 20 }));
    assert.match(out, /Hokimlik News/);
    assert.match(out, /Team Group/);
    assert.ok(!/Alice|Helper Bot|Saved Messages/.test(out), out);
    const priv = text(await call("telegram-list-chats", { limit: 20, filterType: "private" }));
    assert.ok(!/Alice|Helper Bot|Saved Messages/.test(priv), priv);
  });

  it("get-unread, search-chats, search-global", async () => {
    const { call } = register(CHANNELS);
    for (const [name, args] of [
      ["telegram-get-unread", { limit: 20 }],
      ["telegram-search-chats", { query: "a", limit: 20 }],
      ["telegram-search-global", { query: "a", limit: 20 }],
    ] as const) {
      const out = text(await call(name, args));
      assert.match(out, /Hokimlik News/, name);
      assert.ok(!/Alice|Helper Bot|Saved Messages/.test(out), `${name}: ${out}`);
    }
  });

  it("cross-chat tools that cannot be filtered are not registered", () => {
    const { registered } = register(CHANNELS_FULL);
    for (const n of CHANNELS_ONLY_ABSENT_TOOLS) assert.ok(!registered[n], `${n} must be absent`);
    const open = register({ mode: "full", hidden: new Set(), chatPolicy: "all" });
    assert.ok(open.registered["telegram-get-updates"], "present again with CHAT_POLICY=all");
  });
});

describe("chat policy — all", () => {
  it("leaves private chats alone (upstream behavior)", async () => {
    const { call, calls } = register({ mode: "read-only", hidden: new Set(), chatPolicy: "all" });
    const res = await call("telegram-read-messages", { chatId: "@alice", limit: 3 });
    assert.notEqual(res.isError, true);
    assert.deepEqual(calls, ["getMessages"]);
    assert.match(text(await call("telegram-list-chats", { limit: 20 })), /Alice/);
  });
});
