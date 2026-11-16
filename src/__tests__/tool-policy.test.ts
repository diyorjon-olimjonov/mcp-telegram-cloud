/**
 * TOOL_MODE / HIDDEN_TOOLS (src/tool-policy.ts) — driven through a real MCP
 * client ↔ server pair over the SDK's in-memory transport, so "absent from
 * tools/list" and "rejected when called by name" are what a client really sees.
 */
process.env.ISSUER ??= "https://tool-policy-test.invalid";
process.env.TELEGRAM_API_ID ??= "1";
process.env.TELEGRAM_API_HASH ??= "stub";
process.env.MCP_TELEGRAM_TELEMETRY ??= "off";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TelegramService } from "@overpod/mcp-telegram/service";
import { Hono } from "hono";

const { registerAllTools } = await import("../tool-registry.js");
const { TOOLS } = await import("../tools.js");
const { DEFAULT_HIDDEN_TOOLS, isToolExposed, parseHiddenTools, parseToolMode } = await import("../tool-policy.js");
const { createMyRoutes } = await import("../routes/my.js");

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
type Policy = import("../tool-policy.js").ToolPolicy;

/** Every handler would need Telegram; any handler running at all is a failure here. */
let handlerRan: string[] = [];
const telegramTrap = new Proxy({} as TelegramService, {
  get(_t, prop) {
    handlerRan.push(String(prop));
    throw new Error("Telegram must not be reached");
  },
});

async function connect(policy: Policy | undefined) {
  handlerRan = [];
  const server = new McpServer({ name: "policy-test", version: "0.0.0" });
  registerAllTools(server, TOOLS, {
    getTelegram: () => telegramTrap,
    requireConnection: async () => null,
    ...(policy && { policy }),
  });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(clientT);
  const listed = (await client.listTools()).tools;
  return { client, listed, names: new Set(listed.map((t) => t.name)) };
}

/** A call the server refuses: either a JSON-RPC error or an isError result, never a handler run. */
async function assertRejected(client: Client, name: string) {
  let refused = false;
  let text = "";
  try {
    const res = await client.callTool({ name, arguments: { chatId: "@x", text: "hi", messageIds: [1] } });
    refused = res.isError === true;
    text = JSON.stringify(res.content);
  } catch (e) {
    refused = true;
    text = (e as Error).message;
  }
  assert.ok(refused, `${name} must be rejected`);
  assert.match(text, /not found|not available|Unknown tool/i, `${name}: ${text}`);
  assert.deepEqual(handlerRan, [], `${name}: handler must not run`);
}

const READ_ONLY: Policy = { mode: "read-only", hidden: new Set(DEFAULT_HIDDEN_TOOLS) };
const FULL: Policy = { mode: "full", hidden: new Set(DEFAULT_HIDDEN_TOOLS) };

const byName = new Map(TOOLS.map((t) => [t.name, t]));
const writeTool = TOOLS.find((t) => !t.annotations.readOnlyHint && !t.annotations.destructiveHint && !t.requiresEnv);
const destructiveTool =
  TOOLS.find((t) => t.name === "telegram-delete-messages") ?? TOOLS.find((t) => t.annotations.destructiveHint);

describe("tool policy — parsing", () => {
  it("TOOL_MODE defaults to read-only and a typo fails loudly instead of widening access", () => {
    assert.equal(parseToolMode(undefined), "read-only");
    assert.equal(parseToolMode(""), "read-only");
    assert.equal(parseToolMode("FULL"), "full");
    assert.throws(() => parseToolMode("readonly-ish"), /TOOL_MODE/);
  });

  it("HIDDEN_TOOLS: unset = defaults, none = nothing, `default` expands", () => {
    assert.deepEqual([...parseHiddenTools(undefined)], [...DEFAULT_HIDDEN_TOOLS]);
    assert.equal(parseHiddenTools("none").size, 0);
    assert.deepEqual([...parseHiddenTools(" telegram-get-state ")], ["telegram-get-state"]);
    const ext = parseHiddenTools("default,telegram-get-state");
    assert.ok(ext.has("telegram-get-contacts") && ext.has("telegram-get-state"));
  });

  it("every default-hidden name exists in the catalogue and is a read tool", () => {
    for (const name of DEFAULT_HIDDEN_TOOLS) {
      const t = byName.get(name);
      assert.ok(t, `${name} is not a tool — the default list is stale`);
      assert.equal(t.annotations.readOnlyHint, true, `${name} should be a read tool`);
    }
  });
});

describe("tool policy — read-only mode", () => {
  it("tools/list holds only readOnlyHint=true tools, minus HIDDEN_TOOLS", async () => {
    const { listed, names } = await connect(READ_ONLY);
    assert.ok(listed.length > 30, "read tools are still there");
    for (const t of listed) assert.equal(t.annotations?.readOnlyHint, true, `${t.name} is not read-only`);
    for (const h of DEFAULT_HIDDEN_TOOLS) assert.ok(!names.has(h), `${h} must be hidden`);
    assert.ok(names.has("telegram-read-messages"));
    assert.ok(names.has("telegram-list-chats"));
    const expected = TOOLS.filter((t) => isToolExposed(t, READ_ONLY) && !t.requiresEnv).map((t) => t.name);
    for (const n of expected) assert.ok(names.has(n), `${n} missing`);
  });

  it("write and destructive tools are absent and rejected when called by name", async () => {
    assert.ok(writeTool && destructiveTool);
    const { client, names } = await connect(READ_ONLY);
    for (const t of TOOLS.filter((x) => !x.annotations.readOnlyHint)) assert.ok(!names.has(t.name), t.name);
    await assertRejected(client, "telegram-send-message");
    await assertRejected(client, writeTool.name);
    await assertRejected(client, destructiveTool.name);
  });

  it("hidden personal-data tools are rejected when called by name", async () => {
    const { client } = await connect(READ_ONLY);
    await assertRejected(client, "telegram-get-contacts");
    await assertRejected(client, "telegram-get-chat-members");
  });
});

describe("tool policy — full mode", () => {
  it("write tools come back, HIDDEN_TOOLS are still respected", async () => {
    const { names, client } = await connect(FULL);
    assert.ok(names.has("telegram-send-message"));
    for (const h of DEFAULT_HIDDEN_TOOLS) assert.ok(!names.has(h), `${h} must be hidden in full mode too`);
    await assertRejected(client, "telegram-get-contacts");
  });

  it("HIDDEN_TOOLS=none exposes the personal-data reads again", async () => {
    const { names } = await connect({ mode: "read-only", hidden: new Set() });
    assert.ok(names.has("telegram-get-contacts"));
  });

  it("no policy (unit tests / upstream behavior) registers everything", async () => {
    const { names } = await connect(undefined);
    assert.ok(names.has("telegram-send-message") && names.has("telegram-get-contacts"));
  });
});

describe("tool policy — wiring", () => {
  it("every MCP session is registered with the configured policy", () => {
    const src = readFileSync(join(SRC, "mcp-handler.ts"), "utf8");
    assert.match(src, /policy: config\.toolPolicy/);
  });
});

describe("/my/settings in read-only mode", () => {
  function app(readOnlyMode: boolean) {
    const toggles: boolean[] = [];
    const a = new Hono();
    a.route(
      "/my",
      createMyRoutes({
        destructive: {
          isEnabled: () => false,
          todayOkCount: () => 0,
          setEnabled: (_u: string, v: boolean) => toggles.push(v),
        } as never,
        sessions: { getSavedUserIds: () => ["alice"] } as never,
        uploads: {} as never,
        oauth: { getBrowserSessionUser: () => "alice", validateToken: () => null },
        readOnlyMode,
      }),
    );
    return { a, toggles };
  }

  it("hides the destructive toggle", async () => {
    const res = await app(true).a.request("/my/settings", { headers: { cookie: "tg_sid=x" } });
    const html = await res.text();
    assert.equal(res.status, 200);
    assert.match(html, /Read-only mode/);
    assert.ok(!/name="enabled"/.test(html), "no toggle input");
  });

  it("refuses to switch destructive tools on", async () => {
    const { a, toggles } = app(true);
    const res = await a.request("/my/settings", {
      method: "POST",
      headers: { cookie: "tg_sid=x", origin: (await import("../config.js")).config.issuer },
      body: new URLSearchParams({ enabled: "1" }),
    });
    assert.equal(res.status, 403);
    assert.deepEqual(toggles, []);
  });
});
