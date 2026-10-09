/**
 * Showcase presentation: the buyer's deal as a stream of "procurement events"
 * in the contract the DACS Directory's `/try-chat` page renders (Community
 * `reference-implementations/dacs-directory/src/components/try-dacs-contract.ts`,
 * MIT): `{ phase, label, at, txRef?, anchorRef? }` over the phases
 * queued → connecting → discovering → selecting → agreeing → settling →
 * delivering → verifying → complete, mapped onto the five DACS stages.
 *
 * Nothing is stored for this: the stream is derived on demand from the
 * durable lifecycle record and the session index, so a restart cannot lose
 * or reorder it, and every anchor or transaction reference it shows is the
 * one the deal actually produced. Offer and counter *amounts* appear here
 * because the viewer is the buyer's own operator; they are never anchored.
 */

import { contentHash } from "@kynesyslabs/dacs/canonical";
import type { DurableRfqLifecycleRecord } from "@kynesyslabs/dacs/negotiate";
import type { SessionIndexEntry } from "../sessionIndex.js";

export interface ProcurementEvent {
  phase: "queued" | "connecting" | "discovering" | "selecting" | "agreeing" | "settling" | "delivering" | "verifying" | "complete" | "failed";
  label: string;
  at: string;
  txRef?: string;
  anchorRef?: string;
}

export interface ProcurementJob {
  id: string;
  status: "running" | "complete" | "failed";
  phase: ProcurementEvent["phase"];
  events: ProcurementEvent[];
  error?: string;
  failedBeforePayment?: boolean;
  result?: unknown;
}

const iso = (ms: number) => new Date(ms).toISOString();

function priceOf(body: unknown): { amount: string; currency: string } | null {
  const b = body as { proposal?: { price?: { amount: string; currency: string } } } | null;
  return b?.proposal?.price ?? null;
}

/** Derive the event stream for one job from durable state only. */
export function deriveProcurementJob<TSignature>(input: {
  entry: Readonly<SessionIndexEntry>;
  record: Readonly<DurableRfqLifecycleRecord<TSignature>> | null;
  buyerClaim: string;
  sellerDisplayName?: string;
  /** How the private channel is carried, for the viewer; defaults to the interim transport. */
  transportLabel?: string;
  lastError?: string;
}): ProcurementJob {
  const { entry, record } = input;
  const seller = input.sellerDisplayName ?? "the seller";
  const events: ProcurementEvent[] = [];
  const push = (e: ProcurementEvent) => events.push(e);

  push({ phase: "queued", label: `Private RFQ purchase queued for listing ${entry.listingId}@${entry.listingVersion}`, at: iso(entry.openedAt) });
  push({ phase: "connecting", label: `Connecting the buyer wallet and the private channel (${input.transportLabel ?? "interim direct transport; L2PS transport pending"})`, at: iso(entry.openedAt) });
  push({ phase: "discovering", label: `Verified ${seller}'s signed DACS-1 listing from chain`, at: iso(entry.openedAt), anchorRef: `listing:${entry.listingId}@${entry.listingVersion}` });

  if (record === null) {
    return { id: entry.jobId, status: "running", phase: "discovering", events };
  }
  const session = record.session;
  const buyerVet = session.buyer.vetRecordRef;
  const sellerVet = session.seller.vetRecordRef;
  if (sellerVet.anchor.locator !== "pending" && sellerVet.anchor.locator !== "unused") {
    push({ phase: "selecting", label: `Buyer's identity vet of ${seller} anchored`, at: iso(session.startedAt), anchorRef: sellerVet.anchor.locator });
  }
  if (buyerVet.anchor.locator !== "pending" && buyerVet.anchor.locator !== "unused") {
    push({ phase: "selecting", label: `${seller}'s identity vet of the buyer anchored`, at: iso(session.startedAt), anchorRef: buyerVet.anchor.locator });
  }
  push({ phase: "selecting", label: `Buyer opened a signed RFQ channel with ${seller} (channel ${session.channelId})`, at: iso(session.startedAt) });

  for (const message of record.transcript) {
    const mine = message.sender === input.buyerClaim;
    const who = mine ? "Buyer" : seller;
    const price = priceOf(message.body);
    const amount = price === null ? "" : ` ${price.amount} ${price.currency}`;
    const label =
      message.type === "offer" ? `${who} offered${amount} over the RFQ channel`
        : message.type === "counter" ? `${who} countered${amount} over the RFQ channel`
          : message.type === "accept" ? `${who} accepted the standing RFQ proposal`
            : message.type === "reject" ? `${who} rejected the RFQ`
              : `${who} sent ${message.type}`;
    push({ phase: "agreeing", label, at: iso(message.sentAt) });
  }
  const standing = session.standingProposal;
  if (session.status === "accepted" && standing !== undefined) {
    push({ phase: "agreeing", label: `Buyer and ${seller} agreed at ${standing.price.amount} ${standing.price.currency}`, at: iso(session.awaitingSince) });
  }
  if (session.status === "rejected" || session.status === "aborted" || session.status === "timed-out" || session.status === "max-turns") {
    push({ phase: "failed", label: `Negotiation ended: ${session.status}${session.terminalReason ? ` (${session.terminalReason})` : ""}`, at: iso(session.awaitingSince) });
    return { id: entry.jobId, status: "failed", phase: "failed", events, error: session.terminalReason ?? session.status, failedBeforePayment: true };
  }
  const finalized = record.agreement?.finalized;
  if (finalized !== undefined) {
    push({ phase: "agreeing", label: "Dual-signed agreement derived from the accepted proposal and bound to the private channel's last message", at: iso(session.awaitingSince), anchorRef: `agreement-hash:${contentHash(finalized as unknown as Record<string, unknown>)}` });
  }
  const commitment = entry.commitment as { nativeAddress?: string; anchorTxRef?: { writeTxHash?: string }; anchorReceipt?: { transactionRef?: { value?: string } }; committedAt?: number; logicalAddress?: string } | undefined;
  if (commitment !== undefined) {
    push({
      phase: "settling",
      label: "Commitment anchored before payment (hash only; no offer, counter or price on chain)",
      at: iso(commitment.committedAt ?? entry.updatedAt),
      ...(commitment.anchorTxRef?.writeTxHash ? { txRef: commitment.anchorTxRef.writeTxHash } : commitment.anchorReceipt?.transactionRef?.value ? { txRef: commitment.anchorReceipt.transactionRef.value } : {}),
      ...(commitment.nativeAddress ? { anchorRef: commitment.nativeAddress } : {}),
    });
  }
  const settlement = entry.settlement as { status?: string; txHash?: string; amountOs?: string } | undefined;
  if (settlement?.status === "settled" && settlement.txHash) {
    const dem = settlement.amountOs ? `${(Number(BigInt(settlement.amountOs)) / 1e9).toString()} DEM` : "the agreed amount";
    push({ phase: "settling", label: `Paying ${dem} to ${seller} on the native DEM rail behind the wallet spend authority`, at: iso(entry.updatedAt) });
    push({ phase: "settling", label: "Payment broadcast on Demos", at: iso(entry.updatedAt), txRef: settlement.txHash });
    push({ phase: "complete", label: "Deal settled: listing, vet records, commitment and payment are on chain; the negotiation transcript stays private. DACS-5 bundle not part of this showcase.", at: iso(entry.updatedAt) });
    return { id: entry.jobId, status: "complete", phase: "complete", events, result: { agreementHash: finalized ? contentHash(finalized as unknown as Record<string, unknown>) : undefined, commitment: commitment?.nativeAddress, paymentTx: settlement.txHash } };
  }
  if (input.lastError !== undefined) {
    push({ phase: events[events.length - 1]!.phase, label: `Waiting: ${input.lastError}`, at: iso(Date.now()) });
  }
  const phase = commitment !== undefined ? "settling" : finalized !== undefined ? "agreeing" : session.status === "accepted" ? "agreeing" : record.transcript.length > 0 ? "agreeing" : "selecting";
  return { id: entry.jobId, status: "running", phase, events };
}
