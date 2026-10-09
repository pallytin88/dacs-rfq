/**
 * Negotiation policies. The language model only ever returns a structured
 * decision; everything here is enforced in code regardless of what it says.
 *
 * - The buyer ceiling is an operator-configured hard cap on top of the Listing
 *   band. Offers, counters and accepts above it are refused before any packet
 *   is signed.
 * - The seller rule policy is a deterministic `RfqLifecyclePolicy` for the
 *   showcase: accept at or above its floor, otherwise counter toward the floor,
 *   and reject when turns run out below the floor. The SDK still enforces the
 *   Listing band on every counter it emits.
 */

import type { RfqLifecyclePolicy, RfqLifecyclePolicyDecision, RfqSessionState } from "@kynesyslabs/dacs/negotiate";
import { compareDecimal, maxDecimal, midpointDecimal, minDecimal } from "./decimal.js";

export interface PriceLimit {
  amount: string;
  currency: string;
}

export type CeilingCheck =
  | { ok: true }
  | { ok: false; reason: string };

export interface BuyerCeilingGuard {
  readonly ceiling: PriceLimit;
  checkAmount: (amount: string, currency: string) => CeilingCheck;
  checkStandingProposal: (session: RfqSessionState) => CeilingCheck;
}

export function createBuyerCeilingGuard(ceiling: PriceLimit): BuyerCeilingGuard {
  compareDecimal(ceiling.amount, "0");
  return {
    ceiling,
    checkAmount(amount, currency) {
      if (currency !== ceiling.currency) {
        return { ok: false, reason: `currency ${currency} does not match the buyer ceiling currency ${ceiling.currency}` };
      }
      let cmp: number;
      try {
        cmp = compareDecimal(amount, ceiling.amount);
      } catch (cause) {
        return { ok: false, reason: cause instanceof Error ? cause.message : "amount is malformed" };
      }
      return cmp <= 0 ? { ok: true } : { ok: false, reason: `amount ${amount} exceeds the buyer ceiling ${ceiling.amount} ${ceiling.currency}` };
    },
    checkStandingProposal(session) {
      const standing = session.standingProposal;
      if (standing === undefined) return { ok: false, reason: "there is no standing proposal to accept" };
      return this.checkAmount(standing.price.amount, standing.price.currency);
    },
  };
}

/** Inclusive Listing band from the session's negotiable pricing. */
export function sessionPriceBand(session: RfqSessionState): { minimum: string; maximum: string; currency: string } | null {
  const pricing = session.pricing;
  if (pricing.kind !== "negotiable") return null;
  const centre = pricing.bandCenter.amount;
  // Band = centre ± pct, inclusive, half-up at the centre's scale (DACS-3 MTR/RFQ rules
  // are re-applied by the SDK; this is only for display and policy targeting).
  const scale = (centre.split(".")[1] ?? "").length;
  const pct = (value: string, p: number, sign: 1 | -1) => {
    const [whole, frac = ""] = value.split(".");
    const units = BigInt(`${whole}${frac}`);
    const scaled = units * BigInt(100 + sign * p);
    const q = scaled / 100n;
    const r = scaled % 100n;
    const rounded = r * 2n >= 100n ? q + 1n : q;
    const digits = rounded.toString().padStart(scale + 1, "0");
    return scale === 0 ? digits : `${digits.slice(0, -scale)}.${digits.slice(-scale)}`;
  };
  return {
    minimum: pct(centre, pricing.minPct, -1),
    maximum: pct(centre, pricing.maxPct, 1),
    currency: pricing.bandCenter.currency,
  };
}

export interface SellerRulePolicyOptions {
  /** Lowest price the seller will accept. Must lie inside the Listing band. */
  floor: PriceLimit;
  /** Fractional digits for counters. */
  maxScale?: number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

/**
 * Deterministic seller policy for the showcase.
 *
 * - Buyer's standing proposal >= floor → accept.
 * - Otherwise counter at the midpoint between the buyer's proposal and the
 *   seller's previous ask (initially the band maximum), never below the floor.
 * - If only one turn remains and the buyer is still below the floor → reject.
 */
export function createSellerRulePolicy(options: SellerRulePolicyOptions): RfqLifecyclePolicy {
  const maxScale = options.maxScale ?? 2;
  const log = options.log ?? (() => {});
  return ({ role, session }): RfqLifecyclePolicyDecision => {
    if (role !== "seller") return { action: "abort", reason: "seller rule policy invoked for a non-seller role" };
    const standing = session.standingProposal;
    const band = sessionPriceBand(session);
    if (standing === undefined || band === null) {
      return { action: "abort", reason: "no standing proposal or non-negotiable pricing" };
    }
    if (standing.price.currency !== options.floor.currency) {
      return { action: "reject", reason: "currency mismatch" };
    }
    const decide = (): RfqLifecyclePolicyDecision => {
      if (standing.proposer !== session.buyer.primaryClaim) {
        // Our own proposal is standing; nothing to do but wait.
        return { action: "abort", reason: "seller proposal already standing" };
      }
      if (compareDecimal(standing.price.amount, options.floor.amount) >= 0) return { action: "accept" };
      const turnsLeft = session.maxTurns - session.turnCount;
      if (turnsLeft <= 1) return { action: "reject", reason: "below seller floor with no turns left" };
      const previousAsk = band.maximum;
      let counter = midpointDecimal(standing.price.amount, previousAsk, maxScale);
      counter = maxDecimal(counter, options.floor.amount);
      counter = minDecimal(counter, band.maximum);
      return {
        action: "counter",
        proposal: { rfqProposalVersion: "1", price: { amount: counter, currency: options.floor.currency } },
      };
    };
    const decision = decide();
    log({ event: "seller-policy", jobId: session.jobId, standing: standing.price.amount, turnCount: session.turnCount, decision });
    return decision;
  };
}
