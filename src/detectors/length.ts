import type { Detection } from "../core/types.js";

/**
 * Length Detector — validates input/output length constraints.
 */

interface LengthConfig {
  minLength?: number;
  maxLength?: number;
  /** Approximate token count (chars / 4) */
  maxTokens?: number;
}

const DEFAULTS: Required<LengthConfig> = {
  minLength: 1,
  maxLength: 100_000,
  maxTokens: 25_000,
};

function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export function detectInputLength(
  text: string,
  config?: LengthConfig,
): Detection[] {
  const cfg = { ...DEFAULTS, ...config };
  const detections: Detection[] = [];

  if (text.length < cfg.minLength) {
    detections.push({
      detector: "length-input",
      severity: "high",
      match: `Input too short (${text.length} chars, minimum ${cfg.minLength})`,
      position: { start: 0, end: text.length },
      metadata: { length: text.length, minLength: cfg.minLength },
    });
  }

  if (text.length > cfg.maxLength) {
    detections.push({
      detector: "length-input",
      severity: "critical",
      match: `Input too long (${text.length} chars, maximum ${cfg.maxLength})`,
      position: { start: 0, end: text.length },
      metadata: { length: text.length, maxLength: cfg.maxLength },
    });
  }

  const tokens = estimateTokens(text);
  if (tokens > cfg.maxTokens) {
    detections.push({
      detector: "length-input",
      severity: "high",
      match: `Input exceeds token limit (~${tokens} tokens, max ${cfg.maxTokens})`,
      position: { start: 0, end: text.length },
      metadata: { estimatedTokens: tokens, maxTokens: cfg.maxTokens },
    });
  }

  return detections;
}

export function detectOutputLength(
  text: string,
  config?: LengthConfig,
): Detection[] {
  const cfg = { ...DEFAULTS, ...config };
  const detections: Detection[] = [];

  if (text.length > cfg.maxLength) {
    detections.push({
      detector: "length-output",
      severity: "medium",
      match: `Output too long (${text.length} chars, maximum ${cfg.maxLength})`,
      position: { start: 0, end: text.length },
      metadata: { length: text.length, maxLength: cfg.maxLength },
    });
  }

  const tokens = estimateTokens(text);
  if (tokens > cfg.maxTokens) {
    detections.push({
      detector: "length-output",
      severity: "medium",
      match: `Output exceeds token limit (~${tokens} tokens, max ${cfg.maxTokens})`,
      position: { start: 0, end: text.length },
      metadata: { estimatedTokens: tokens, maxTokens: cfg.maxTokens },
    });
  }

  return detections;
}
