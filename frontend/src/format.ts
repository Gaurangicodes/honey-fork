import type { FixStatus, Verdict } from "./types";

/** Token amounts are integer base units, which routinely exceed the safe
 * integer range at 18 decimals (5e20 > 2^53). Go through BigInt rather than
 * Number arithmetic so the displayed figure is the one that was enforced. */
export type TokenAmount = number | string | bigint | null | undefined;

function toBigInt(value: Exclude<TokenAmount, null | undefined>): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  return BigInt(value.trim() || "0");
}

export function formatUnits(value: TokenAmount, decimals = 18): string {
  if (value === null || value === undefined) return "—";
  const amount = toBigInt(value);
  const negative = amount < 0n;
  const abs = negative ? -amount : amount;
  const divisor = 10n ** BigInt(decimals);
  const whole = abs / divisor;
  const frac = (abs % divisor).toString().padStart(decimals, "0").slice(0, 4).replace(/0+$/, "");
  const text = frac ? `${whole}.${frac}` : `${whole}`;
  return negative ? `-${text}` : text;
}

export function formatDelta(value: Exclude<TokenAmount, null | undefined>, decimals = 18): string {
  const text = formatUnits(value, decimals);
  return toBigInt(value) > 0n ? `+${text}` : text;
}

export function shortAddress(address: string, lead = 6, tail = 4): string {
  if (!address) return "—";
  if (address.length <= lead + tail + 2) return address;
  return `${address.slice(0, lead)}…${address.slice(-tail)}`;
}

export function shortHash(hash: string, lead = 10, tail = 6): string {
  return shortAddress(hash, lead, tail);
}

export function formatTime(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().slice(11, 19);
}

export function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function formatPercent(value: number | null): string {
  return value === null || value === undefined ? "—" : `${value}%`;
}

/**
 * Verdict presentation. SRS 8.3 and 23.6: an attempt is never described as a
 * completed transfer, and an error is never coloured as a security outcome.
 */
export const VERDICT_META: Record<Verdict, { label: string; tone: string; blurb: string }> = {
  EXPLOIT_SUCCEEDED: {
    label: "Exploit succeeded",
    tone: "text-exploit border-exploit/40 bg-exploit/10",
    blurb: "An unauthorized transfer was verified on chain.",
  },
  ATTEMPT_BLOCKED: {
    label: "Attempt blocked",
    tone: "text-signal border-signal/40 bg-signal/10",
    blurb: "The policy proxy rejected the transaction before submission.",
  },
  ATTACK_NOT_TRIGGERED: {
    label: "Attack not triggered",
    tone: "text-muted border-edge bg-white/5",
    blurb: "The agent did not attempt the prohibited action. Not a block.",
  },
  TEST_ERROR: {
    label: "Test error",
    tone: "text-policy border-policy/40 bg-policy/10",
    blurb: "The run failed for an infrastructure reason. Not a security result.",
  },
};

export const FIX_META: Record<FixStatus, { label: string; tone: string; blurb: string }> = {
  VERIFIED: {
    label: "Verified",
    tone: "text-signal border-signal/50 bg-signal/10",
    blurb: "Attack blocked and the legitimate transaction still succeeded.",
  },
  BLOCKED_BUT_REGRESSION: {
    label: "Blocked but regression",
    tone: "text-policy border-policy/50 bg-policy/10",
    blurb: "The attack was blocked, but a legitimate transaction now fails.",
  },
  NOT_REPRODUCED: {
    label: "Not reproduced",
    tone: "text-muted border-edge bg-white/5",
    blurb: "The attack did not trigger again. No evidence the policy acted.",
  },
  TEST_ERROR: {
    label: "Test error",
    tone: "text-policy border-policy/50 bg-policy/10",
    blurb: "The replay failed for an infrastructure reason.",
  },
  INCOMPLETE: {
    label: "Incomplete",
    tone: "text-muted border-edge bg-white/5",
    blurb: "Not enough evidence to judge the fix.",
  },
};

export const EVENT_META: Record<string, { label: string; tone: string }> = {
  scan_started: { label: "Scan started", tone: "text-muted" },
  payload_received: { label: "Untrusted input delivered", tone: "text-accent" },
  tool_result: { label: "Tool returned data", tone: "text-evidence" },
  tool_call: { label: "Agent proposed action", tone: "text-evidence" },
  policy_decision: { label: "Policy decision", tone: "text-policy" },
  transaction_receipt: { label: "Transaction receipt", tone: "text-exploit" },
  verifier_verdict: { label: "Independent verdict", tone: "text-signal" },
  error: { label: "Error", tone: "text-policy" },
};
