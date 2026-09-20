import type { GuardRule, Severity } from "./types.js";

/**
 * Default guard rules — covers PII, injection, toxicity, and length.
 * Each rule maps a detector to an action and severity filter.
 */
export const DEFAULT_RULES: GuardRule[] = [
  // ── PII Detection ──────────────────────────────────────────
  {
    name: "pii-email",
    enabled: true,
    detector: "pii-email",
    action: "mask",
    severity: ["medium", "high", "critical"],
  },
  {
    name: "pii-phone",
    enabled: true,
    detector: "pii-phone",
    action: "mask",
    severity: ["medium", "high", "critical"],
  },
  {
    name: "pii-ssn",
    enabled: true,
    detector: "pii-ssn",
    action: "block",
    severity: ["high", "critical"],
  },
  {
    name: "pii-credit-card",
    enabled: true,
    detector: "pii-credit-card",
    action: "block",
    severity: ["critical"],
  },
  {
    name: "pii-ip",
    enabled: true,
    detector: "pii-ip",
    action: "warn",
    severity: ["low", "medium", "high"],
  },
  {
    name: "pii-address",
    enabled: true,
    detector: "pii-address",
    action: "mask",
    severity: ["medium", "high"],
  },

  // ── Injection Detection ────────────────────────────────────
  {
    name: "injection-pattern",
    enabled: true,
    detector: "injection-pattern",
    action: "block",
    severity: ["high", "critical"],
  },
  {
    name: "injection-heuristic",
    enabled: true,
    detector: "injection-heuristic",
    action: "warn",
    severity: ["medium", "high"],
  },

  // ── Toxicity Detection ─────────────────────────────────────
  {
    name: "toxicity-profanity",
    enabled: true,
    detector: "toxicity-profanity",
    action: "warn",
    severity: ["medium", "high"],
  },
  {
    name: "toxicity-threats",
    enabled: true,
    detector: "toxicity-threats",
    action: "block",
    severity: ["high", "critical"],
  },
  {
    name: "toxicity-hate",
    enabled: true,
    detector: "toxicity-hate",
    action: "block",
    severity: ["high", "critical"],
  },
  {
    name: "toxicity-selfharm",
    enabled: true,
    detector: "toxicity-selfharm",
    action: "warn",
    severity: ["medium", "high", "critical"],
  },

  // ── Length Validation ──────────────────────────────────────
  {
    name: "length-input",
    enabled: true,
    detector: "length-input",
    action: "block",
    severity: ["high", "critical"],
  },
  {
    name: "length-output",
    enabled: true,
    detector: "length-output",
    action: "warn",
    severity: ["medium", "high"],
  },
];

/**
 * Create a deep copy of the default rules.
 */
export function getDefaultRules(): GuardRule[] {
  return DEFAULT_RULES.map((r) => ({ ...r }));
}

/**
 * Find the first matching rule for a given detector and severity.
 */
export function findMatchingRule(
  rules: GuardRule[],
  detector: string,
  severity: Severity,
): GuardRule | undefined {
  return rules.find(
    (r) => r.enabled && r.detector === detector && r.severity.includes(severity),
  );
}
