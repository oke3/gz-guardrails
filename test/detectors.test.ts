import { describe, it, expect } from "bun:test";
import {
  detectPIIEmail,
  detectPIIPhone,
  detectPIISSN,
  detectPIICreditCard,
  detectPIIIP,
  detectPIIAddress,
  detectPII,
} from "../src/detectors/pii.js";

describe("PII Detector", () => {
  describe("Email detection", () => {
    it("detects valid email addresses", () => {
      const results = detectPIIEmail("Contact me at user@example.com for details");
      expect(results.length).toBe(1);
      expect(results[0].detector).toBe("pii-email");
      expect(results[0].match).toBe("user@example.com");
      expect(results[0].position.start).toBe(14);
    });

    it("detects multiple emails", () => {
      const results = detectPIIEmail("Send to a@b.com and c@d.org");
      expect(results.length).toBe(2);
    });

    it("returns empty for no emails", () => {
      expect(detectPIIEmail("no emails here").length).toBe(0);
    });
  });

  describe("Phone detection", () => {
    it("detects US phone numbers", () => {
      const results = detectPIIPhone("Call (555) 123-4567 or 555-123-4567");
      expect(results.length).toBeGreaterThanOrEqual(2);
    });

    it("detects international format", () => {
      const results = detectPIIPhone("Dial +1-202-555-0142");
      expect(results.length).toBe(1);
    });
  });

  describe("SSN detection", () => {
    it("detects SSN with dashes", () => {
      const results = detectPIISSN("SSN: 123-45-6789");
      expect(results.length).toBe(1);
      expect(results[0].detector).toBe("pii-ssn");
      expect(results[0].severity).toBe("high");
    });

    it("detects SSN without dashes", () => {
      const results = detectPIISSN("ID: 123456789");
      expect(results.length).toBe(1);
    });
  });

  describe("Credit card detection", () => {
    it("detects valid Visa number (Luhn)", () => {
      // Visa test number: 4539578763621486
      const results = detectPIICreditCard("Card: 4539-5787-6362-1486");
      expect(results.length).toBe(1);
      expect(results[0].detector).toBe("pii-credit-card");
      expect(results[0].severity).toBe("critical");
    });

    it("rejects invalid card numbers (Luhn fail)", () => {
      const results = detectPIICreditCard("Card: 1234-5678-9012-3456");
      expect(results.length).toBe(0);
    });
  });

  describe("IP address detection", () => {
    it("detects valid IPv4", () => {
      const results = detectPIIIP("Server at 192.168.1.1");
      expect(results.length).toBe(1);
      expect(results[0].detector).toBe("pii-ip");
    });

    it("rejects invalid IPs", () => {
      expect(detectPIIIP("999.999.999.999").length).toBe(0);
    });
  });

  describe("Address detection", () => {
    it("detects street addresses", () => {
      const results = detectPIIAddress("Visit 123 Main Street or 456 Oak Avenue");
      expect(results.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Combined PII", () => {
    it("detects multiple PII types", () => {
      const text = "Name: John, Email: john@test.com, SSN: 123-45-6789";
      const results = detectPII(text);
      expect(results.length).toBeGreaterThanOrEqual(2);
      const detectors = results.map((r) => r.detector);
      expect(detectors).toContain("pii-email");
      expect(detectors).toContain("pii-ssn");
    });
  });
});
