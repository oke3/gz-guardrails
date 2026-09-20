import type { Detection } from "../core/types.js";

/**
 * Toxicity Detector — keyword-based profanity, threats, hate speech, self-harm.
 * All lists are configurable via the rule config.
 */

// ── Default word lists ─────────────────────────────────────────

const PROFANITY_WORDS = [
  "damn", "hell", "crap", "ass", "asshole", "bastard", "bitch",
  "bollocks", "bugger", "bloody", "dick", "dumbass", "fag",
  "fuck", "fucker", "fucking", "motherfucker", "piss", "shit",
  "slut", "twat", "wanker", "prick",
];

const THREAT_PATTERNS = [
  /\b(?:i(?:'ll| will| am going to))\s+(?:kill|murder|destroy|end|hurt|harm)\b/gi,
  /\b(?:you(?:'re| are)\s+(?:going\s+)?(?:to\s+)?(?:die|be\s+destroyed))\b/gi,
  /\b(?:death\s+threat|threatening\s+to\s+kill)\b/gi,
  /\b(?:bomb|explode|blow\s+up)\s+(?:the|this|that|a|an)\b/gi,
];

const HATE_PATTERNS = [
  /\b(?:all|every)\s+(?:jews?|muslims?|christians?|blacks?|whites?|gays?|trans\s*people)\s+(?:are|should|must)\b/gi,
  /\b(?:go\s+back\s+to)\s+(?:your|where)\b/gi,
  /\b(?:sub[-\s]?human|untermensch|inferior\s+race)\b/gi,
];

const SELF_HARM_PATTERNS = [
  /\b(?:want(?:ing)?|going)\s+to\s+(?:kill\s+myself|end\s+it|commit\s+suicide)\b/gi,
  /\b(?:how\s+to\s+(?:kill\s+myself|commit\s+suicide|end\s+my\s+life))\b/gi,
  /\b(?:suicide|self[-\s]?harm|cut(?:ting)?\s+myself)\b/gi,
];

// ── Detection helpers ──────────────────────────────────────────

function detectKeywords(
  text: string,
  words: string[],
  detector: string,
  severity: Detection["severity"],
): Detection[] {
  const lower = text.toLowerCase();
  const detections: Detection[] = [];
  for (const word of words) {
    // Use word boundary regex to avoid matching substrings (e.g. "hell" in "hello")
    const re = new RegExp(`\\b${escapeRegex(word)}\\b`, "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      detections.push({
        detector,
        severity,
        match: m[0],
        position: { start: m.index, end: m.index + m[0].length },
        metadata: { keyword: word },
      });
    }
  }
  return detections;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function detectPatterns(
  text: string,
  patterns: RegExp[],
  detector: string,
  severity: Detection["severity"],
): Detection[] {
  const detections: Detection[] = [];
  for (const pattern of patterns) {
    const re = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      detections.push({
        detector,
        severity,
        match: m[0],
        position: { start: m.index, end: m.index + m[0].length },
      });
    }
  }
  return detections;
}

// ── Public API ─────────────────────────────────────────────────

export function detectProfanity(
  text: string,
  customWords?: string[],
): Detection[] {
  const words = customWords ?? PROFANITY_WORDS;
  return detectKeywords(text, words, "toxicity-profanity", "medium");
}

export function detectThreats(text: string): Detection[] {
  return detectPatterns(text, THREAT_PATTERNS, "toxicity-threats", "high");
}

export function detectHateSpeech(text: string): Detection[] {
  return detectPatterns(text, HATE_PATTERNS, "toxicity-hate", "critical");
}

export function detectSelfHarm(text: string): Detection[] {
  return detectPatterns(text, SELF_HARM_PATTERNS, "toxicity-selfharm", "high");
}

/**
 * Run all toxicity detectors on the input text.
 */
export function detectToxicity(
  text: string,
  config?: { profanityWords?: string[] },
): Detection[] {
  return [
    ...detectProfanity(text, config?.profanityWords),
    ...detectThreats(text),
    ...detectHateSpeech(text),
    ...detectSelfHarm(text),
  ];
}
