/** Severity levels for detections */
export type Severity = "low" | "medium" | "high" | "critical";

/** A single detection result from a detector */
export interface Detection {
  /** Detector identifier, e.g. 'pii-email', 'injection-pattern' */
  detector: string;
  /** How severe this detection is */
  severity: Severity;
  /** The matched content or description */
  match: string;
  /** Character positions in the original string */
  position: { start: number; end: number };
  /** Optional extra metadata */
  metadata?: Record<string, unknown>;
}

/** Action taken in response to a detection */
export interface Action {
  type: "block" | "mask" | "warn" | "replace";
  original: string;
  /** Modified content (mask/replace only) */
  modified?: string;
  reason: string;
  detections: Detection[];
}

/** Full result of a guard check */
export interface GuardResult {
  /** false if any critical/high detections were blocked */
  safe: boolean;
  /** Actions executed during this check */
  actions: Action[];
  /** Content after masking/replacement (input) */
  modifiedInput?: string;
  /** Content after masking/replacement (output) */
  modifiedOutput?: string;
  /** All raw detections */
  detections: Detection[];
  /** Total processing time in ms */
  latencyMs: number;
}

/** A configurable guard rule */
export interface GuardRule {
  /** Unique rule name */
  name: string;
  /** Whether this rule is active */
  enabled: boolean;
  /** Which detector this rule uses */
  detector: string;
  /** What to do when the detector fires */
  action: "block" | "mask" | "warn" | "replace";
  /** Which severity levels trigger this action */
  severity: Severity[];
  /** Replacement string (for replace action) */
  replacement?: string;
  /** Detector-specific config */
  config?: Record<string, unknown>;
}

/** Engine configuration */
export interface GuardConfig {
  rules: GuardRule[];
  /** Detectors to run on input text */
  inputChecks: string[];
  /** Detectors to run on output text */
  outputChecks: string[];
  /** Severities that cause automatic blocking */
  blockOnSeverity: Severity[];
  /** Logging verbosity */
  logLevel: "none" | "block" | "all";
}

/** Stats tracking */
export interface GuardStats {
  checked: number;
  blocked: number;
  masked: number;
  warned: number;
}
