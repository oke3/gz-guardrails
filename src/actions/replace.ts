import type { Action, Detection } from "../core/types.js";

/**
 * Replace action — substitutes flagged content with a custom string.
 */
export function replaceAction(
  original: string,
  detections: Detection[],
  replacement: string = "[CONTENT REMOVED]",
): Action {
  // Sort descending so indices stay valid
  const sorted = [...detections].sort(
    (a, b) => b.position.start - a.position.start,
  );

  let modified = original;
  for (const d of sorted) {
    modified =
      modified.slice(0, d.position.start) +
      replacement +
      modified.slice(d.position.end);
  }

  return {
    type: "replace",
    original,
    modified,
    reason: `Replaced ${detections.length} detection(s) with "${replacement}"`,
    detections,
  };
}
