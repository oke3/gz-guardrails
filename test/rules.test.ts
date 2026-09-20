import { describe, it, expect } from "bun:test";
import { getDefaultRules, findMatchingRule } from "../src/core/rules.js";
import type { GuardRule } from "../src/core/types.js";

describe("Rules", () => {
  describe("getDefaultRules", () => {
    it("returns a non-empty array", () => {
      const rules = getDefaultRules();
      expect(rules.length).toBeGreaterThan(0);
    });

    it("returns independent copies (no shared references)", () => {
      const a = getDefaultRules();
      const b = getDefaultRules();
      a[0].name = "mutated";
      expect(b[0].name).not.toBe("mutated");
    });

    it("includes all expected rule types", () => {
      const rules = getDefaultRules();
      const detectors = rules.map((r) => r.detector);
      expect(detectors).toContain("pii-email");
      expect(detectors).toContain("injection-pattern");
      expect(detectors).toContain("toxicity-profanity");
      expect(detectors).toContain("length-input");
    });

    it("has all required fields", () => {
      const rules = getDefaultRules();
      for (const rule of rules) {
        expect(rule.name).toBeTruthy();
        expect(typeof rule.enabled).toBe("boolean");
        expect(rule.detector).toBeTruthy();
        expect(["block", "mask", "warn", "replace"]).toContain(rule.action);
        expect(rule.severity.length).toBeGreaterThan(0);
      }
    });
  });

  describe("findMatchingRule", () => {
    it("finds a matching rule", () => {
      const rules = getDefaultRules();
      const rule = findMatchingRule(rules, "pii-email", "medium");
      expect(rule).toBeDefined();
      expect(rule?.detector).toBe("pii-email");
    });

    it("returns undefined for unmatched detector", () => {
      const rules = getDefaultRules();
      const rule = findMatchingRule(rules, "nonexistent", "medium");
      expect(rule).toBeUndefined();
    });

    it("returns undefined for unmatched severity", () => {
      const rules = getDefaultRules();
      // pii-credit-card only triggers on critical
      const rule = findMatchingRule(rules, "pii-credit-card", "low");
      expect(rule).toBeUndefined();
    });

    it("skips disabled rules", () => {
      const rules: GuardRule[] = [
        {
          name: "disabled-rule",
          enabled: false,
          detector: "test-detector",
          action: "block",
          severity: ["high"],
        },
      ];
      const rule = findMatchingRule(rules, "test-detector", "high");
      expect(rule).toBeUndefined();
    });
  });
});
