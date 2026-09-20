import type { Action, Detection } from "../core/types.js";

/**
 * Block action — rejects the input/output entirely.
 * Returns blocked: true, does not modify content.
 */
export function blockAction(
  original: string,
  detections: Detection[],
): Action {
  return {
    type: "block",
    original,
    reason: `Blocked: ${detections.length} detection(s) triggered block action`,
    detections,
  };
}
