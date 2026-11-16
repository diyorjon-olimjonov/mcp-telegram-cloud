#!/usr/bin/env bun
/**
 * Generate access keys for the login gate (see src/access-keys.ts).
 *
 *   bun scripts/make-access-keys.ts --count 30 --prefix person   # person-1 … person-30
 *   bun scripts/make-access-keys.ts --label person-31            # one more key later
 *
 * Plain keys go ONLY to `access-keys-PRIVATE.csv` (columns: label,key), written
 * with mode 600 to the PARENT of the repo folder — never inside the repository.
 * stdout carries ONLY the value for the ACCESS_KEYS env var (`label:sha256hex,…`);
 * with --label it is the single new entry to append to ACCESS_KEYS.
 * Status lines go to stderr. Options:
 *   --out-dir <dir>  write the CSV elsewhere (refused if inside the repo)
 *   --force          with --count: overwrite an existing CSV (old keys are lost)
 */
import { randomInt } from "node:crypto";
import { appendFileSync, chmodSync, existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { ACCESS_LABEL_RE, hashAccessKey } from "../src/access-keys.ts";

/** No look-alikes: drops 0/o, 1/l/i. 31 symbols ⇒ 16 chars ≈ 79 bits. */
export const KEY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const CSV_NAME = "access-keys-PRIVATE.csv";

export function generateKey(groups = 4, groupLen = 4): string {
  const parts: string[] = [];
  for (let g = 0; g < groups; g++) {
    let s = "";
    for (let i = 0; i < groupLen; i++) s += KEY_ALPHABET[randomInt(KEY_ALPHABET.length)];
    parts.push(s);
  }
  return parts.join("-");
}

function fail(msg: string): never {
  process.stderr.write(`make-access-keys: ${msg}\n`);
  process.exit(1);
}

function parseArgs(argv: string[]) {
  const out: { count?: number; prefix: string; label?: string; outDir?: string; force: boolean } = {
    prefix: "person",
    force: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => argv[++i] ?? fail(`${a} needs a value`);
    if (a === "--count") out.count = Number(val());
    else if (a === "--prefix") out.prefix = val();
    else if (a === "--label") out.label = val();
    else if (a === "--out-dir") out.outDir = val();
    else if (a === "--force") out.force = true;
    else fail(`unknown option ${a}`);
  }
  return out;
}

/** True when `p` is `root` or anywhere below it. */
function isInside(root: string, p: string): boolean {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !rel.startsWith(sep) && !/^[A-Za-z]:/.test(rel));
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const repoRoot = realpathSync(resolve(dirname(new URL(import.meta.url).pathname), ".."));
  const outDir = resolve(args.outDir ?? join(repoRoot, ".."));
  if (!existsSync(outDir)) fail(`output directory does not exist: ${outDir}`);
  if (isInside(repoRoot, realpathSync(outDir))) {
    fail(`refusing to write plain keys inside the repository (${outDir}). Use a folder outside it.`);
  }
  const csvPath = join(outDir, CSV_NAME);

  let labels: string[];
  if (args.label !== undefined) {
    if (args.count !== undefined) fail("use either --count or --label, not both");
    labels = [args.label];
  } else {
    if (!Number.isInteger(args.count) || (args.count as number) < 1 || (args.count as number) > 1000) {
      fail("--count must be an integer between 1 and 1000 (or use --label <name>)");
    }
    labels = Array.from({ length: args.count as number }, (_, i) => `${args.prefix}-${i + 1}`);
  }
  for (const l of labels)
    if (!ACCESS_LABEL_RE.test(l)) fail(`invalid label "${l}" (lowercase letters, digits, - or _)`);

  const rows = labels.map((label) => ({ label, key: generateKey() }));

  if (args.label !== undefined) {
    if (existsSync(csvPath)) {
      const existing = readFileSync(csvPath, "utf8")
        .split("\n")
        .map((line) => line.split(",")[0]);
      if (existing.includes(args.label)) fail(`label ${args.label} already exists in ${csvPath}`);
      appendFileSync(csvPath, rows.map((r) => `${r.label},${r.key}\n`).join(""), { mode: 0o600 });
    } else {
      writeFileSync(csvPath, `label,key\n${rows.map((r) => `${r.label},${r.key}\n`).join("")}`, { mode: 0o600 });
    }
  } else {
    if (existsSync(csvPath) && !args.force) {
      fail(`${csvPath} already exists — keys in it would be lost. Move it away or pass --force.`);
    }
    writeFileSync(csvPath, `label,key\n${rows.map((r) => `${r.label},${r.key}\n`).join("")}`, { mode: 0o600 });
  }
  chmodSync(csvPath, 0o600);

  process.stderr.write(
    `make-access-keys: wrote ${rows.length} plain key(s) to ${csvPath} (mode 600). ` +
      (args.label !== undefined
        ? "Append the line below to ACCESS_KEYS (comma-separated):\n"
        : "Set ACCESS_KEYS to the line below:\n"),
  );
  process.stdout.write(`${rows.map((r) => `${r.label}:${hashAccessKey(r.key)}`).join(",")}\n`);
}

if (import.meta.main) main();
