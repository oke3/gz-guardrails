import type { Action, Detection } from "../core/types.js";

/**
 * Mask action — redacts PII and sensitive content.
 * Replaces matched content with standardized redaction markers.
 */

const MASK_MAP: Record<string, string> = {
  "pii-email": "[EMAIL REDACTED]",
  "pii-phone": "[PHONE REDACTED]",
  "pii-ssn": "[SSN REDACTED]",
  "pii-credit-card": "[CARD REDACTED]",
  "pii-ip": "[IP REDACTED]",
  "pii-address": "[ADDRESS REDACTED]",
};

export function maskAction(
  original: string,
  detections: Detection[],
): Action {
  // Sort detections by position descending so replacements don't shift indices
  const sorted = [...detections].sort(
    (a, b) => b.position.start - a.position.start,
  );

  let modified = original;
  for (const d of sorted) {
    const replacement = MASK_MAP[d.detector] ?? "[REDACTED]";
    modified =
      modified.slice(0, d.position.start) +
      replacement +
      modified.slice(d.position.end);
  }

  return {
    type: "mask",
    original,
    modified,
    reason: `Masked ${detections.length} detection(s)`,
    detections,
  };
}
