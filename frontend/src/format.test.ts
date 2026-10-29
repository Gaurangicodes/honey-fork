import { describe, expect, it } from "vitest";
import { EVENT_META, FIX_META, VERDICT_META, formatDelta, formatUnits, shortAddress } from "./format";
import type { FixStatus, Verdict } from "./types";

describe("formatUnits", () => {
  it("renders base units with the token decimals", () => {
    expect(formatUnits(500000000000000000000n)).toBe("500");
    expect(formatUnits(1500000000000000000n)).toBe("1.5");
    expect(formatUnits(1n)).toBe("0");
  });

  it("stays exact beyond the safe integer range", () => {
    // 18-decimal balances exceed 2^53, so a Number round-trip would silently
    // change the figure that was actually enforced.
    // 10,000,000.000000000000000001 TST: the whole part must be exact.
    expect(formatUnits("10000000000000000000000001")).toBe("10000000");
    expect(formatUnits(10000000000000000000000001n)).toBe("10000000");
  });

  it("keeps the sign for negative balances", () => {
    expect(formatUnits(-500000000000000000000n)).toBe("-500");
  });

  it("renders a placeholder rather than a wrong number for missing values", () => {
    expect(formatUnits(null)).toBe("—");
    expect(formatUnits(undefined)).toBe("—");
  });
});

describe("formatDelta", () => {
  it("marks inflows explicitly so a recipient gain is not read as a loss", () => {
    expect(formatDelta(500000000000000000000n)).toBe("+500");
    expect(formatDelta(-500000000000000000000n)).toBe("-500");
  });
});

describe("shortAddress", () => {
  it("truncates long addresses but leaves short ones intact", () => {
    expect(shortAddress("0x1111111111111111111111111111111111111111")).toBe("0x1111…1111");
    expect(shortAddress("0xabc")).toBe("0xabc");
  });
});

describe("verdict and fix presentation", () => {
  // Every backend enum value must have a label, or the UI would render a raw
  // enum or an undefined tone.
  it("covers every verdict the verifier can return", () => {
    const verdicts: Verdict[] = [
      "EXPLOIT_SUCCEEDED",
      "ATTEMPT_BLOCKED",
      "ATTACK_NOT_TRIGGERED",
      "TEST_ERROR",
    ];
    for (const verdict of verdicts) {
      expect(VERDICT_META[verdict]?.label).toBeTruthy();
    }
  });

  it("covers every fix status", () => {
    const statuses: FixStatus[] = [
      "VERIFIED",
      "BLOCKED_BUT_REGRESSION",
      "NOT_REPRODUCED",
      "TEST_ERROR",
      "INCOMPLETE",
    ];
    for (const status of statuses) {
      expect(FIX_META[status]?.label).toBeTruthy();
    }
  });

  it("does not describe an untriggered attack as blocked", () => {
    // SRS Appendix B: never label an attack that did not trigger as blocked.
    expect(VERDICT_META.ATTACK_NOT_TRIGGERED.label).not.toMatch(/block/i);
    expect(VERDICT_META.TEST_ERROR.blurb).toMatch(/not a security result/i);
  });

  it("has a label for every event type the backend emits", () => {
    for (const type of [
      "scan_started",
      "payload_received",
      "tool_result",
      "tool_call",
      "policy_decision",
      "transaction_receipt",
      "verifier_verdict",
      "error",
    ]) {
      expect(EVENT_META[type]?.label).toBeTruthy();
    }
  });
});
