import type { Action, Detection } from "../core/types.js";

/**
 * Warn action — logs the detection but allows content through unchanged.
 */
export function warnAction(
  original: string,
  detections: Detection[],
): Action {
  return {
    type: "warn",
    original,
    reason: `Warning: ${detections.length} detection(s) logged`,
    detections,
  };
}
