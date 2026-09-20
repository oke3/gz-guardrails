import type { Detection } from "../core/types.js";

/**
 * Prompt Injection Detector — known pattern matching + heuristic analysis.
 */

// ── Known injection patterns (case-insensitive) ────────────────

const INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string; severity: Detection["severity"] }> = [
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|guidelines)/gi, label: "instruction-override", severity: "critical" },
  { pattern: /you\s+are\s+now\s+(?:a|an|my|the)\s+/gi, label: "role-reassignment", severity: "high" },
  { pattern: /\b(system|assistant|user)\s*:\s*/gi, label: "role-injection", severity: "high" },
  { pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>/gi, label: "llama-delimiter", severity: "critical" },
  { pattern: /###\s*(system|assistant)\s*:/gi, label: "markdown-role", severity: "high" },
  { pattern: /forget\s+(everything|all|what|your)\s+/gi, label: "memory-wipe", severity: "high" },
  { pattern: /do\s+not\s+(follow|obey|listen\s+to)\s+(your|the|any)\s+(rules|instructions|guidelines)/gi, label: "rule-bypass", severity: "critical" },
  { pattern: /(?:reveal|show|print|output|display)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)/gi, label: "prompt-exfil", severity: "critical" },
  { pattern: /\bact\s+as\s+if\s+(?:you\s+)?(?:have\s+)?(?:no|zero)\s+(?:restrictions|rules|limitations|filters)/gi, label: "restriction-removal", severity: "critical" },
  { pattern: /\bjailbreak\b/gi, label: "jailbreak-keyword", severity: "high" },
  { pattern: /developer\s+mode\s+(?:enabled|on|activated)/gi, label: "dev-mode", severity: "high" },
  { pattern: /\bDAN\b.*\bmode\b/gi, label: "dan-mode", severity: "critical" },
];

// ── Heuristic checks ───────────────────────────────────────────

const BASE64_SHORT_RE = /\b[A-Za-z0-9+/]{40,200}={0,2}\b/g;

function isLikelyBase64(s: string): boolean {
  if (s.length < 40 || s.length > 200) return false;
  try {
    const decoded = atob(s);
    // If decoded contains printable chars or common injection keywords, flag it
    const lower = decoded.toLowerCase();
    return (
      lower.includes("ignore") ||
      lower.includes("prompt") ||
      lower.includes("system") ||
      lower.includes("instruction") ||
      lower.includes("ignore") ||
      /[\x00-\x08\x0e-\x1f]/.test(decoded) // control chars suggest encoded payload
    );
  } catch {
    return false;
  }
}

function detectExcessiveSpecialChars(text: string): Detection[] {
  if (text.length < 10) return [];
  const nonAlphaNum = text.replace(/[a-zA-Z0-9\s]/g, "").length;
  const ratio = nonAlphaNum / text.length;
  if (ratio > 0.5) {
    return [
      {
        detector: "injection-heuristic",
        severity: "medium",
        match: `Excessive special characters (${(ratio * 100).toFixed(0)}% non-alphanumeric)`,
        position: { start: 0, end: text.length },
        metadata: { ratio },
      },
    ];
  }
  return [];
}

// ── Public API ─────────────────────────────────────────────────

export function detectInjectionPatterns(text: string): Detection[] {
  const detections: Detection[] = [];

  for (const { pattern, label, severity } of INJECTION_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      detections.push({
        detector: "injection-pattern",
        severity,
        match: m[0],
        position: { start: m.index, end: m.index + m[0].length },
        metadata: { pattern: label },
      });
    }
  }

  return detections;
}

export function detectInjectionHeuristics(text: string): Detection[] {
  const detections: Detection[] = [];

  // Base64 encoded injection attempts
  const b64Matches = text.match(BASE64_SHORT_RE);
  if (b64Matches) {
    for (const match of b64Matches) {
      if (isLikelyBase64(match)) {
        const idx = text.indexOf(match);
        detections.push({
          detector: "injection-heuristic",
          severity: "high",
          match: `[Base64 payload]`,
          position: { start: idx, end: idx + match.length },
          metadata: { decoded: atob(match).slice(0, 100) },
        });
      }
    }
  }

  // Excessive special characters
  detections.push(...detectExcessiveSpecialChars(text));

  return detections;
}

/**
 * Run all injection detectors on the input text.
 */
export function detectInjection(text: string): Detection[] {
  return [...detectInjectionPatterns(text), ...detectInjectionHeuristics(text)];
}
