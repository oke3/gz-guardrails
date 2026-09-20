#!/usr/bin/env node

/**
 * gz-guardrails CLI — check, scan, rules, config.
 */

import { readFileSync } from "node:fs";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { GuardrailEngine } from "./core/engine.js";
import { getDefaultRules } from "./core/rules.js";
import type { GuardConfig, GuardResult } from "./core/types.js";

// ── Helpers ────────────────────────────────────────────────────

const CONFIG_DIR = join(homedir(), ".gz-guardrails");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

function usage(): never {
  console.log(`
gz-guardrails — AI safety middleware

Usage:
  gz-guardrails check <text>              Check input text
  gz-guardrails check --file <path>       Check file contents
  gz-guardrails scan <text>               Show all detections (no actions)
  gz-guardrails rules                     List configured rules
  gz-guardrails config init               Generate default config
  gz-guardrails config show               Show current config

Options:
  --json          Output as JSON
  --help, -h      Show this help
`);
  process.exit(0);
}

function parseArgs(argv: string[]): { command: string; args: string[]; flags: Record<string, string | boolean> } {
  const args = argv.slice(2);
  const command = args[0] ?? "";
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];

  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") {
      flags.json = true;
    } else if (a === "--help" || a === "-h") {
      flags.help = true;
    } else if (a === "--file" && args[i + 1]) {
      flags.file = args[++i];
    } else if (a.startsWith("--")) {
      flags[a.slice(2)] = args[++i] ?? true;
    } else {
      positional.push(a);
    }
  }

  return { command, args: positional, flags };
}

function printResult(result: GuardResult, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const status = result.safe ? "\x1b[32m✓ SAFE\x1b[0m" : "\x1b[31m✗ BLOCKED\x1b[0m";
  console.log(`\n${status}  (${result.latencyMs.toFixed(1)}ms)`);
  console.log(`  Detections: ${result.detections.length}`);

  if (result.modifiedInput) {
    console.log(`\n  Modified input:\n  ${result.modifiedInput}`);
  }
  if (result.modifiedOutput) {
    console.log(`\n  Modified output:\n  ${result.modifiedOutput}`);
  }

  if (result.detections.length > 0) {
    console.log("\n  Detections:");
    for (const d of result.detections) {
      const sev = d.severity.toUpperCase().padEnd(8);
      console.log(`    [${sev}] ${d.detector}: ${d.match}`);
    }
  }

  if (result.actions.length > 0) {
    console.log("\n  Actions:");
    for (const a of result.actions) {
      console.log(`    ${a.type}: ${a.reason}`);
    }
  }
  console.log();
}

async function loadConfig(): Promise<Partial<GuardConfig>> {
  try {
    const raw = readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

// ── Commands ───────────────────────────────────────────────────

async function cmdCheck(text: string, json: boolean): Promise<void> {
  const config = await loadConfig();
  const engine = new GuardrailEngine(config);
  const result = await engine.checkInput(text);
  printResult(result, json);
  process.exit(result.safe ? 0 : 1);
}

async function cmdCheckFile(filePath: string, json: boolean): Promise<void> {
  const text = readFileSync(filePath, "utf-8");
  const config = await loadConfig();
  const engine = new GuardrailEngine(config);
  const result = await engine.checkInput(text);
  printResult(result, json);
  process.exit(result.safe ? 0 : 1);
}

async function cmdScan(text: string, json: boolean): Promise<void> {
  const config = await loadConfig();
  const engine = new GuardrailEngine(config);
  // Run without actions — just detect
  const result = await engine.checkInput(text);
  // Override safe to true since scan mode doesn't block
  result.safe = true;
  result.actions = [];
  printResult(result, json);
}

function cmdRules(json: boolean): void {
  const rules = getDefaultRules();
  if (json) {
    console.log(JSON.stringify(rules, null, 2));
    return;
  }
  console.log("\nConfigured Rules:");
  console.log("─".repeat(72));
  for (const r of rules) {
    const status = r.enabled ? "\x1b[32mON\x1b[0m  " : "\x1b[31mOFF\x1b[0m ";
    console.log(
      `  ${status} ${r.name.padEnd(24)} ${r.detector.padEnd(24)} ${r.action.padEnd(8)} [${r.severity.join(", ")}]`,
    );
  }
  console.log();
}

async function cmdConfigInit(): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  const defaultConfig: GuardConfig = {
    rules: getDefaultRules(),
    inputChecks: [
      "pii-email", "pii-phone", "pii-ssn", "pii-credit-card", "pii-ip", "pii-address",
      "injection-pattern", "injection-heuristic",
      "toxicity-profanity", "toxicity-threats", "toxicity-hate", "toxicity-selfharm",
      "length-input",
    ],
    outputChecks: [
      "pii-email", "pii-phone", "pii-ip",
      "toxicity-profanity", "toxicity-threats",
      "length-output",
    ],
    blockOnSeverity: ["critical"],
    logLevel: "block",
  };
  await writeFile(CONFIG_FILE, JSON.stringify(defaultConfig, null, 2));
  console.log(`✓ Config written to ${CONFIG_FILE}`);
}

async function cmdConfigShow(): Promise<void> {
  try {
    const raw = readFileSync(CONFIG_FILE, "utf-8");
    console.log(JSON.stringify(JSON.parse(raw), null, 2));
  } catch {
    console.error("No config found. Run: gz-guardrails config init");
    process.exit(1);
  }
}

// ── Main ───────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { command, args, flags } = parseArgs(process.argv);

  if (flags.help || !command) usage();

  switch (command) {
    case "check": {
      if (flags.file) {
        await cmdCheckFile(flags.file as string, !!flags.json);
      } else if (args[0]) {
        await cmdCheck(args[0], !!flags.json);
      } else {
        console.error("Usage: gz-guardrails check <text> | --file <path>");
        process.exit(1);
      }
      break;
    }
    case "scan": {
      if (args[0]) {
        await cmdScan(args[0], !!flags.json);
      } else {
        console.error("Usage: gz-guardrails scan <text>");
        process.exit(1);
      }
      break;
    }
    case "rules":
      cmdRules(!!flags.json);
      break;
    case "config": {
      const sub = args[0];
      if (sub === "init") await cmdConfigInit();
      else if (sub === "show") await cmdConfigShow();
      else console.error("Usage: gz-guardrails config init|show");
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      usage();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
