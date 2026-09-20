import type {
  GuardConfig,
  GuardResult,
  GuardRule,
  GuardStats,
  Detection,
  Action,
  Severity,
} from "./types.js";
import { getDefaultRules, findMatchingRule } from "./rules.js";

// Detector imports
import { detectPII } from "../detectors/pii.js";
import { detectInjection } from "../detectors/injection.js";
import { detectToxicity } from "../detectors/toxicity.js";
import { detectInputLength, detectOutputLength } from "../detectors/length.js";

// Action imports
import { blockAction } from "../actions/block.js";
import { maskAction } from "../actions/mask.js";
import { warnAction } from "../actions/warn.js";
import { replaceAction } from "../actions/replace.js";

// ── Detector registry ──────────────────────────────────────────

type DetectorFn = (text: string, config?: Record<string, unknown>) => Detection[];

const DETECTOR_REGISTRY: Record<string, DetectorFn> = {
  "pii-email": (t) => detectPII(t).filter((d) => d.detector === "pii-email"),
  "pii-phone": (t) => detectPII(t).filter((d) => d.detector === "pii-phone"),
  "pii-ssn": (t) => detectPII(t).filter((d) => d.detector === "pii-ssn"),
  "pii-credit-card": (t) => detectPII(t).filter((d) => d.detector === "pii-credit-card"),
  "pii-ip": (t) => detectPII(t).filter((d) => d.detector === "pii-ip"),
  "pii-address": (t) => detectPII(t).filter((d) => d.detector === "pii-address"),
  "injection-pattern": (t) => detectInjection(t).filter((d) => d.detector === "injection-pattern"),
  "injection-heuristic": (t) => detectInjection(t).filter((d) => d.detector === "injection-heuristic"),
  "toxicity-profanity": (t, c) => detectToxicity(t, c as any).filter((d) => d.detector === "toxicity-profanity"),
  "toxicity-threats": (t) => detectToxicity(t).filter((d) => d.detector === "toxicity-threats"),
  "toxicity-hate": (t) => detectToxicity(t).filter((d) => d.detector === "toxicity-hate"),
  "toxicity-selfharm": (t) => detectToxicity(t).filter((d) => d.detector === "toxicity-selfharm"),
  "length-input": (t, c) => detectInputLength(t, c as any),
  "length-output": (t, c) => detectOutputLength(t, c as any),
};

// ── Default config ─────────────────────────────────────────────

const DEFAULT_CONFIG: GuardConfig = {
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

// ── GuardrailEngine ────────────────────────────────────────────

export class GuardrailEngine {
  private config: GuardConfig;
  private stats: GuardStats = { checked: 0, blocked: 0, masked: 0, warned: 0 };

  constructor(config?: Partial<GuardConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    if (config?.rules) {
      this.config.rules = config.rules;
    }
  }

  // ── Main API ────────────────────────────────────────────────

  async checkInput(input: string): Promise<GuardResult> {
    return this.runChecks(input, this.config.inputChecks, "input");
  }

  async checkOutput(output: string): Promise<GuardResult> {
    return this.runChecks(output, this.config.outputChecks, "output");
  }

  async check(
    input: string,
    output: string,
  ): Promise<{ input: GuardResult; output: GuardResult }> {
    const [inputResult, outputResult] = await Promise.all([
      this.checkInput(input),
      this.checkOutput(output),
    ]);
    return { input: inputResult, output: outputResult };
  }

  // ── Configuration ───────────────────────────────────────────

  addRule(rule: GuardRule): void {
    const idx = this.config.rules.findIndex((r) => r.name === rule.name);
    if (idx >= 0) {
      this.config.rules[idx] = rule;
    } else {
      this.config.rules.push(rule);
    }
  }

  removeRule(name: string): void {
    this.config.rules = this.config.rules.filter((r) => r.name !== name);
  }

  getRules(): GuardRule[] {
    return [...this.config.rules];
  }

  getConfig(): GuardConfig {
    return { ...this.config, rules: [...this.config.rules] };
  }

  // ── Stats ───────────────────────────────────────────────────

  getStats(): GuardStats {
    return { ...this.stats };
  }

  resetStats(): void {
    this.stats = { checked: 0, blocked: 0, masked: 0, warned: 0 };
  }

  // ── Internal pipeline ───────────────────────────────────────

  private async runChecks(
    text: string,
    checks: string[],
    _mode: "input" | "output",
  ): Promise<GuardResult> {
    const start = performance.now();
    this.stats.checked++;

    // 1. Run all enabled detectors
    const allDetections: Detection[] = [];
    for (const detectorName of checks) {
      const detector = DETECTOR_REGISTRY[detectorName];
      if (!detector) continue;
      const detections = detector(text, {});
      allDetections.push(...detections);
    }

    // 2. For each detection, find matching rules and execute actions
    const actions: Action[] = [];
    let blocked = false;
    let modifiedContent: string | undefined;

    // Group detections by detector name for rule matching
    const grouped = new Map<string, Detection[]>();
    for (const d of allDetections) {
      const list = grouped.get(d.detector) ?? [];
      list.push(d);
      grouped.set(d.detector, list);
    }

    for (const [detectorName, detections] of grouped) {
      // Find highest severity detection for this detector
      const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
      let worstSeverity: Severity = "low";
      for (const d of detections) {
        if (severityOrder.indexOf(d.severity) < severityOrder.indexOf(worstSeverity)) {
          worstSeverity = d.severity;
        }
      }

      // Find matching rule
      const rule = findMatchingRule(
        this.config.rules,
        detectorName,
        worstSeverity,
      );

      if (!rule) continue;

      // Check if this severity should auto-block
      const shouldBlock =
        this.config.blockOnSeverity.includes(worstSeverity);

      let action: Action;
      if (shouldBlock || rule.action === "block") {
        action = blockAction(text, detections);
        blocked = true;
        this.stats.blocked++;
      } else if (rule.action === "mask") {
        action = maskAction(modifiedContent ?? text, detections);
        modifiedContent = action.modified;
        this.stats.masked++;
      } else if (rule.action === "replace") {
        action = replaceAction(
          modifiedContent ?? text,
          detections,
          rule.replacement,
        );
        modifiedContent = action.modified;
        this.stats.masked++;
      } else {
        // warn
        action = warnAction(text, detections);
        this.stats.warned++;
      }

      actions.push(action);
    }

    const latencyMs = performance.now() - start;

    // 3. Log if configured
    if (this.config.logLevel === "all" || (this.config.logLevel === "block" && blocked)) {
      console.error(
        `[gz-guardrails] ${blocked ? "BLOCKED" : "CHECKED"} | ${allDetections.length} detections | ${latencyMs.toFixed(1)}ms`,
      );
    }

    return {
      safe: !blocked,
      actions,
      modifiedInput: _mode === "input" ? modifiedContent : undefined,
      modifiedOutput: _mode === "output" ? modifiedContent : undefined,
      detections: allDetections,
      latencyMs,
    };
  }
}
