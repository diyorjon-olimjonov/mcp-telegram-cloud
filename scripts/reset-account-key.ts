#!/usr/bin/env bun
/**
 * Admin: give a user a NEW personal access key (open-signup mode, see
 * src/account-keys.ts). Keys are stored only as hashes, so a forgotten key
 * cannot be read back; this replaces it, and the old key stops working at once.
 *
 *   bun scripts/reset-account-key.ts @username
 *   bun scripts/reset-account-key.ts 123456789        # numeric Telegram id
 *   bun scripts/reset-account-key.ts --list           # connected accounts (no keys)
 *
 * Run it where the database lives (inside the server container:
 * `docker compose exec cloud bun scripts/reset-account-key.ts @username`).
 * The new key is printed once on stdout — hand it to the user privately.
 */
import { Database } from "bun:sqlite";
import { existsSync } from "node:fs";
import { AccountKeys } from "../src/account-keys.ts";

function fail(msg: string): never {
  process.stderr.write(`reset-account-key: ${msg}\n`);
  process.exit(1);
}

export function findTelegramId(db: Database, who: string): string | null {
  const arg = who.trim().replace(/^@/, "");
  if (/^\d+$/.test(arg)) {
    const row = db.prepare("SELECT telegram_id FROM user_sessions WHERE telegram_id = ?").get(arg);
    return row ? arg : null;
  }
  const row = db
    .prepare("SELECT telegram_id FROM user_sessions WHERE lower(user_id) = lower(?) AND telegram_id IS NOT NULL")
    .get(arg) as { telegram_id: string } | null;
  return row?.telegram_id ?? null;
}

function main() {
  const who = process.argv[2];
  if (!who) fail("usage: bun scripts/reset-account-key.ts <@username | telegram id | --list>");
  const path = process.env.DATABASE_PATH || "./data/cloud.db";
  if (!existsSync(path)) fail(`database not found at ${path} (set DATABASE_PATH)`);
  const db = new Database(path);
  const keys = new AccountKeys(db);

  if (who === "--list") {
    const rows = db
      .prepare(
        `SELECT s.user_id, s.telegram_id, k.created_at AS key_at FROM user_sessions s
         LEFT JOIN account_keys k ON k.telegram_id = s.telegram_id ORDER BY s.user_id`,
      )
      .all() as { user_id: string; telegram_id: string | null; key_at: string | null }[];
    for (const r of rows) {
      process.stdout.write(`${r.user_id}\t${r.telegram_id ?? "-"}\t${r.key_at ? `key since ${r.key_at}` : "no key"}\n`);
    }
    return;
  }

  const telegramId = findTelegramId(db, who);
  if (!telegramId) fail(`no connected account matches "${who}" (try --list)`);
  const key = keys.reset(telegramId);
  process.stderr.write(`New key for ${who} (Telegram id ${telegramId}). The old key no longer works.\n`);
  process.stdout.write(`${key}\n`);
}

if (import.meta.main) main();
