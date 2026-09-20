import type { Detection } from "../core/types.js";

/**
 * PII Detector — finds emails, phones, SSNs, credit cards, IPs, addresses.
 * Each detection includes character positions and a severity rating.
 */

// ── Regex patterns ─────────────────────────────────────────────

const EMAIL_RE =
  /[a-zA-Z0-9._%+\-!#$&'*/=?^`{|}~]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

const PHONE_RE =
  /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g;

const SSN_RE = /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g;

const CREDIT_CARD_RE =
  /\b(?:\d{4}[-\s]?){3}\d{4}\b/g;

const IPV4_RE =
  /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;

// Street address heuristic: number + common street words
const ADDRESS_RE =
  /\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Place|Pl|Way|Circle|Cir|Trail|Trl|Parkway|Pkwy)\b/gi;

// ── Luhn algorithm for credit card validation ──────────────────

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// ── Detection functions ────────────────────────────────────────

function detectPattern(
  text: string,
  regex: RegExp,
  detector: string,
  severity: Detection["severity"],
  validate?: (match: string) => boolean,
): Detection[] {
  const detections: Detection[] = [];
  const re = new RegExp(regex.source, regex.flags);
  let m: RegExpExecArray | null;

  while ((m = re.exec(text)) !== null) {
    const match = m[0];
    if (validate && !validate(match)) continue;
    detections.push({
      detector,
      severity,
      match,
      position: { start: m.index, end: m.index + match.length },
    });
  }
  return detections;
}

// ── Public API ─────────────────────────────────────────────────

export function detectPIIEmail(text: string): Detection[] {
  return detectPattern(text, EMAIL_RE, "pii-email", "medium");
}

export function detectPIIPhone(text: string): Detection[] {
  return detectPattern(text, PHONE_RE, "pii-phone", "medium");
}

export function detectPIISSN(text: string): Detection[] {
  return detectPattern(text, SSN_RE, "pii-ssn", "high");
}

export function detectPIICreditCard(text: string): Detection[] {
  return detectPattern(
    text,
    CREDIT_CARD_RE,
    "pii-credit-card",
    "critical",
    luhnCheck,
  );
}

export function detectPIIIP(text: string): Detection[] {
  return detectPattern(text, IPV4_RE, "pii-ip", "low");
}

export function detectPIIAddress(text: string): Detection[] {
  return detectPattern(text, ADDRESS_RE, "pii-address", "medium");
}

/**
 * Run all PII detectors on the input text.
 */
export function detectPII(text: string): Detection[] {
  return [
    ...detectPIIEmail(text),
    ...detectPIIPhone(text),
    ...detectPIISSN(text),
    ...detectPIICreditCard(text),
    ...detectPIIIP(text),
    ...detectPIIAddress(text),
  ];
}
