/**
 * Step 5: the buyer negotiation service the ChatGPT agent calls as a tool.
 *
 * The service holds the keys, the stores and the outbox. The model only ever
 * supplies structured tool arguments; every amount is validated against the
 * Listing band (by the SDK) and the operator's ceiling (here) before a packet
 * is signed. After acceptance the service advances the deal on its own:
 * co-sign → commit hash on Demos with finality → pay over the rail behind the
 * wallet spend authority. Each advance is idempotent and fails closed.
 */

import { contentHash } from "@kynesyslabs/dacs/canonical";
import type { AttestationRef, IdentityBundle } from "@kynesyslabs/dacs/artifacts";
import { generateCanonicalJobId, isCanonicalJobId } from "@kynesyslabs/dacs/negotiate";
import type {
  DurableRfqLifecycleClient,
  DurableRfqLifecycleRecord,
  DurableRfqLifecycleResult,
  FinalizedAgreementCommitment,
  RfqProposal,
  VerifiedListingInput,
} from "@kynesyslabs/dacs/negotiate";
import { randomBytes } from "node:crypto";
import type { CommitOutcome } from "../commit.js";
import type { BuyerCeilingGuard } from "../policy.js";
import { sessionPriceBand } from "../policy.js";
import type { SessionIndex } from "../sessionIndex.js";
import type { SettleOutcome } from "../settle.js";
import { drainInbox } from "../transport/drain.js";
import type { RfqInboxStore } from "../transport/inboxStore.js";
import type { DurableRfqLifecycleTransport } from "@kynesyslabs/dacs/negotiate";
import type { RfqSessionAnnouncement } from "../transport/open.js";
import { announcementPacketId } from "../transport/open.js";
import type { BuyerVetExchange } from "../live/vetExchange.js";

export interface ListingCatalogEntry {
  verifiedListing: VerifiedListingInput;
  sellerVetRecordRef: AttestationRef;
  sellerClaim: string;
}

export interface ListingSummary {
  listingId: string;
  version: number;
  contentHash: string;
  seller: string;
  title: string;
  category: string;
  pricing: { kind: string; currency?: string; bandCenter?: string; minPct?: number; maxPct?: number };
  maxTurns?: number;
  timeoutSec?: number;
}

export interface BuyerNegotiationServiceOptions<TSignature> {
  buyerClaim: string;
  buyerParty: { identityBundle: IdentityBundle; vetRecordRef: AttestationRef };
  client: DurableRfqLifecycleClient<TSignature>;
  transport: DurableRfqLifecycleTransport<TSignature> & { announce(announcement: Readonly<RfqSessionAnnouncement>): Promise<{ disposition: string; reason?: string }> };
  inbox: RfqInboxStore;
  sessions: SessionIndex;
  catalog: () => Promise<readonly ListingCatalogEntry[]> | readonly ListingCatalogEntry[];
  ceiling: BuyerCeilingGuard;
  /**
   * Live vet exchange. When present it supersedes the static vet refs: the
   * buyer vets the seller on chain before announcing and waits for the
   * seller's vet of the buyer before opening.
   */
  vet?: BuyerVetExchange;
  /** Step 6 hooks; omit to stop after co-signing. */
  commit?: (record: Readonly<DurableRfqLifecycleRecord<TSignature>>, verifiedListing: VerifiedListingInput) => Promise<CommitOutcome>;
  settle?: (record: Readonly<DurableRfqLifecycleRecord<TSignature>>, commitment: FinalizedAgreementCommitment) => Promise<SettleOutcome>;
  nowMs?: () => number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface NegotiationState {
  jobId: string;
  channelId: string;
  listingId: string;
  status: string;
  phase: "negotiating" | "accepted" | "co-signed" | "committed" | "settled" | "terminal";
  expectedSender: string;
  yourTurn: boolean;
  turnCount: number;
  maxTurns: number;
  turnsLeft: number;
  timeLeftMs: number;
  priceBand: { minimum: string; maximum: string; currency: string } | null;
  ceiling: { amount: string; currency: string };
  standingProposal: { amount: string; currency: string; proposer: string; sequence: number } | null;
  transcriptLength: number;
  terminalReason?: string;
  lastError?: string;
}

export interface Receipts {
  jobId: string;
  agreementHash?: string;
  derivedFromChannel?: unknown;
  commitment?: Record<string, unknown>;
  settlement?: Record<string, unknown>;
  transcriptHashes: string[];
}

export class BuyerServiceError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "BuyerServiceError";
  }
}

export interface BuyerNegotiationService {
  findListing(input: { listingId?: string; query?: string }): Promise<ListingSummary[]>;
  openNegotiation(input: { listingId: string }): Promise<NegotiationState>;
  getNegotiationState(input: { jobId: string }): Promise<NegotiationState>;
  makeOffer(input: { jobId: string; amount: string }): Promise<NegotiationState>;
  counterOffer(input: { jobId: string; amount: string }): Promise<NegotiationState>;
  accept(input: { jobId: string }): Promise<NegotiationState>;
  reject(input: { jobId: string; reason?: string }): Promise<NegotiationState>;
  getReceipts(input: { jobId: string }): Promise<Receipts>;
  /** Resume outboxes and drain the inbox; call on process start and periodically. */
  tick(): Promise<void>;
  /** Last advance error recorded for a job, if any (for the showcase view). */
  lastError(jobId: string): string | undefined;
}

function summarize(entry: ListingCatalogEntry): ListingSummary {
  const listing = entry.verifiedListing.listing;
  const rfq = listing.pipeline.find((phase) => phase.kind === "negotiate-rfq") as { parameters?: { maxTurns?: number; timeoutSec?: number } } | undefined;
  const pricing = listing.pricing as { kind: string; bandCenter?: { amount: string; currency: string }; minPct?: number; maxPct?: number };
  return {
    listingId: listing.listingId,
    version: listing.listingVersion,
    contentHash: entry.verifiedListing.pin.contentHash,
    seller: entry.sellerClaim,
    title: listing.offering.title,
    category: listing.offering.category,
    pricing: {
      kind: pricing.kind,
      ...(pricing.bandCenter === undefined ? {} : { currency: pricing.bandCenter.currency, bandCenter: pricing.bandCenter.amount }),
      ...(pricing.minPct === undefined ? {} : { minPct: pricing.minPct }),
      ...(pricing.maxPct === undefined ? {} : { maxPct: pricing.maxPct }),
    },
    ...(rfq?.parameters?.maxTurns === undefined ? {} : { maxTurns: rfq.parameters.maxTurns }),
    ...(rfq?.parameters?.timeoutSec === undefined ? {} : { timeoutSec: rfq.parameters.timeoutSec }),
  };
}

export function createBuyerNegotiationService<TSignature>(
  options: BuyerNegotiationServiceOptions<TSignature>,
): BuyerNegotiationService {
  const nowMs = options.nowMs ?? Date.now;
  const log = options.log ?? (() => {});
  const lastErrors = new Map<string, string>();

  function fail(code: string, message: string): never {
    throw new BuyerServiceError(code, message);
  }

  function requireJobId(jobId: unknown): string {
    if (!isCanonicalJobId(jobId)) fail("job-id-invalid", "jobId must be a canonical ULID");
    if (options.sessions.get(jobId) === null) fail("job-unknown", `no negotiation ${jobId} in this buyer`);
    return jobId;
  }

  function verifiedListingFor(jobId: string): VerifiedListingInput {
    const entry = options.sessions.get(jobId);
    if (entry === null) fail("job-unknown", `no negotiation ${jobId}`);
    return JSON.parse(entry.listingJson) as VerifiedListingInput;
  }

  async function loadRecord(jobId: string): Promise<Readonly<DurableRfqLifecycleRecord<TSignature>>> {
    const status = await options.client.getStatus(jobId);
    if (status.status !== "ok") fail("state-unavailable", `lifecycle store: ${status.status}${"reason" in status ? ` (${status.reason})` : ""}`);
    return status.record;
  }

  function reasonOf(result: DurableRfqLifecycleResult<TSignature>): string {
    return "reason" in result ? result.reason : "";
  }

  function resultOrThrow(result: DurableRfqLifecycleResult<TSignature>, action: string): void {
    if (result.status === "ready" || result.status === "duplicate") return;
    fail(`${action}-${result.status}`, reasonOf(result));
  }

  // Ticks can overlap while commit or settle waits on the chain; one advance per job at a time.
  const inFlight = new Set<string>();
  async function advance(jobId: string): Promise<void> {
    if (inFlight.has(jobId)) return;
    inFlight.add(jobId);
    try { await advanceOnce(jobId); } finally { inFlight.delete(jobId); }
  }
  async function advanceOnce(jobId: string): Promise<void> {
    const entry = options.sessions.get(jobId);
    if (entry === null) return;
    const record = await loadRecord(jobId);
    if (record.session.status !== "accepted") return;
    // 1. Agreement proposal if not started.
    if (record.agreement === undefined) {
      const started = await options.client.startAgreement(jobId);
      if (started.status !== "ready" && started.status !== "duplicate") {
        lastErrors.set(jobId, `startAgreement: ${reasonOf(started)}`);
      }
      return;
    }
    if (record.agreement.finalized === undefined) return; // waiting for the seller contribution
    // 2. Commit.
    if (entry.commitment === undefined) {
      if (options.commit === undefined) return;
      const outcome = await options.commit(record, verifiedListingFor(jobId));
      if (outcome.status !== "committed") {
        lastErrors.set(jobId, `commit: ${outcome.reason}`);
        return;
      }
      options.sessions.setCommitment(jobId, outcome.commitment as unknown as Record<string, unknown>, nowMs());
      log({ event: "deal-committed", jobId, agreementHash: outcome.commitment.agreementHash, nativeAddress: outcome.commitment.nativeAddress });
    }
    // 3. Settle.
    const refreshed = options.sessions.get(jobId)!;
    if (refreshed.settlement === undefined && options.settle !== undefined && refreshed.commitment !== undefined) {
      const outcome = await options.settle(record, refreshed.commitment as unknown as FinalizedAgreementCommitment);
      if (outcome.status !== "settled") {
        lastErrors.set(jobId, `settle: ${outcome.reason}`);
        return;
      }
      options.sessions.setSettlement(jobId, outcome as unknown as Record<string, unknown>, nowMs());
      log({ event: "deal-settled", jobId, txHash: outcome.txHash });
    }
    lastErrors.delete(jobId);
  }

  async function state(jobId: string): Promise<NegotiationState> {
    const entry = options.sessions.get(jobId)!;
    const record = await loadRecord(jobId);
    const session = record.session;
    const now = nowMs();
    const standing = session.standingProposal;
    const phase: NegotiationState["phase"] =
      entry.settlement !== undefined ? "settled"
        : entry.commitment !== undefined ? "committed"
          : record.agreement?.finalized !== undefined ? "co-signed"
            : session.status === "accepted" ? "accepted"
              : session.status === "open" ? "negotiating" : "terminal";
    const lastError = lastErrors.get(jobId);
    return {
      jobId,
      channelId: session.channelId,
      listingId: entry.listingId,
      status: session.status,
      phase,
      expectedSender: session.expectedSender,
      yourTurn: session.status === "open" && session.expectedSender === options.buyerClaim,
      turnCount: session.turnCount,
      maxTurns: session.maxTurns,
      turnsLeft: Math.max(0, session.maxTurns - session.turnCount),
      timeLeftMs: session.status === "open" ? Math.max(0, session.awaitingSince + session.timeoutMs - now) : 0,
      priceBand: sessionPriceBand(session),
      ceiling: { ...options.ceiling.ceiling },
      standingProposal: standing === undefined ? null
        : { amount: standing.price.amount, currency: standing.price.currency, proposer: standing.proposer, sequence: standing.sequence },
      transcriptLength: record.transcript.length,
      ...(session.terminalReason === undefined ? {} : { terminalReason: session.terminalReason }),
      ...(lastError === undefined ? {} : { lastError }),
    };
  }

  async function sync(jobId?: string): Promise<void> {
    const summary = await drainInbox({ inbox: options.inbox, client: options.client, nowMs, log });
    if (summary.stoppedAt !== undefined) {
      log({ event: "buyer-drain-stopped", ...summary.stoppedAt });
    }
    const jobs = jobId === undefined ? options.sessions.list().map((e) => e.jobId) : [jobId];
    for (const id of jobs) {
      const resumed = await options.client.resumeOutbox(id);
      if (resumed.status !== "ready" && resumed.status !== "duplicate") lastErrors.set(id, `outbox: ${reasonOf(resumed)}`);
      await advance(id);
    }
  }

  function proposal(amount: string, currency: string): RfqProposal {
    const check = options.ceiling.checkAmount(amount, currency);
    if (!check.ok) fail("ceiling-exceeded", check.reason);
    return { rfqProposalVersion: "1", price: { amount, currency } };
  }

  return {
    async findListing(input) {
      const entries = await options.catalog();
      const q = input.query?.toLowerCase();
      return entries
        .filter((e) => input.listingId === undefined || e.verifiedListing.listing.listingId === input.listingId)
        .filter((e) => q === undefined || `${e.verifiedListing.listing.offering.title} ${e.verifiedListing.listing.offering.description} ${e.verifiedListing.listing.offering.category}`.toLowerCase().includes(q))
        .map(summarize);
    },

    async openNegotiation(input) {
      const entries = await options.catalog();
      const entry = entries.find((e) => e.verifiedListing.listing.listingId === input.listingId);
      if (entry === undefined) fail("listing-unknown", `listing ${input.listingId} is not in the catalog`);
      const verified = entry.verifiedListing;
      if (verified.pin.contentHash !== contentHash(verified.listing as unknown as Record<string, unknown>)) fail("listing-pin-mismatch", "listing pin does not match its bytes");
      const jobId = generateCanonicalJobId({ timestamp: nowMs() });
      const channelId = `rfq-${jobId.toLowerCase()}-${randomBytes(8).toString("hex")}`;
      const sellerBundle = verified.listing.seller.identity;
      // Vet the seller first (anchored, signed by us); the ref travels in the announcement.
      const sellerVetRef = options.vet === undefined
        ? entry.sellerVetRecordRef
        : await options.vet.vetSeller(jobId, sellerBundle);
      // Announce so the seller can vet us and open before our first turn arrives.
      const announced = await options.transport.announce({
        packetVersion: "1", kind: "open", packetId: announcementPacketId(jobId), jobId, channelId,
        sender: options.buyerClaim, recipient: entry.sellerClaim, listingPin: { ...verified.pin },
        buyer: options.buyerParty, sellerVetRef, announcedAt: nowMs(),
      });
      if (announced.disposition !== "acknowledged") fail("announce-" + announced.disposition, announced.reason ?? announced.disposition);
      const buyerParty = options.vet === undefined
        ? options.buyerParty
        : { identityBundle: options.buyerParty.identityBundle, vetRecordRef: await options.vet.awaitVetOfBuyer(jobId, options.buyerParty.identityBundle) };
      const openInput = {
        jobId,
        verifiedListing: verified,
        buyer: buyerParty,
        seller: { identityBundle: sellerBundle, vetRecordRef: sellerVetRef },
        channelId,
      };
      const opened = await options.client.open(openInput);
      resultOrThrow(opened, "open");
      options.sessions.put({
        jobId, channelId, listingId: verified.listing.listingId, listingVersion: verified.listing.listingVersion,
        counterparty: entry.sellerClaim, listingJson: JSON.stringify(verified), openedAt: nowMs(),
      });
      log({ event: "negotiation-opened", jobId, channelId, listingId: verified.listing.listingId, seller: entry.sellerClaim });
      return state(jobId);
    },

    async getNegotiationState(input) {
      const jobId = requireJobId(input.jobId);
      await sync(jobId);
      return state(jobId);
    },

    async makeOffer(input) {
      const jobId = requireJobId(input.jobId);
      await sync(jobId);
      const band = sessionPriceBand((await loadRecord(jobId)).session);
      const currency = band?.currency ?? options.ceiling.ceiling.currency;
      resultOrThrow(await options.client.sendOffer(jobId, proposal(input.amount, currency)), "offer");
      return state(jobId);
    },

    async counterOffer(input) {
      const jobId = requireJobId(input.jobId);
      await sync(jobId);
      const band = sessionPriceBand((await loadRecord(jobId)).session);
      const currency = band?.currency ?? options.ceiling.ceiling.currency;
      resultOrThrow(await options.client.sendCounter(jobId, proposal(input.amount, currency)), "counter");
      return state(jobId);
    },

    async accept(input) {
      const jobId = requireJobId(input.jobId);
      await sync(jobId);
      const record = await loadRecord(jobId);
      const check = options.ceiling.checkStandingProposal(record.session);
      if (!check.ok) fail("ceiling-exceeded", check.reason);
      if (record.session.standingProposal?.proposer === options.buyerClaim) fail("accept-own-proposal", "cannot accept your own standing proposal");
      resultOrThrow(await options.client.sendAccept(jobId), "accept");
      await advance(jobId);
      return state(jobId);
    },

    async reject(input) {
      const jobId = requireJobId(input.jobId);
      await sync(jobId);
      resultOrThrow(await options.client.sendReject(jobId, input.reason), "reject");
      return state(jobId);
    },

    async getReceipts(input) {
      const jobId = requireJobId(input.jobId);
      await sync(jobId);
      const entry = options.sessions.get(jobId)!;
      const record = await loadRecord(jobId);
      const finalized = record.agreement?.finalized;
      return {
        jobId,
        ...(finalized === undefined ? {} : {
          agreementHash: contentHash(finalized as unknown as Record<string, unknown>),
          derivedFromChannel: (finalized as unknown as { derivedFromChannel?: unknown }).derivedFromChannel,
        }),
        ...(entry.commitment === undefined ? {} : { commitment: entry.commitment }),
        ...(entry.settlement === undefined ? {} : { settlement: entry.settlement }),
        transcriptHashes: record.transcript.map((m) => contentHash(m as unknown as Record<string, unknown>)),
      };
    },

    async tick() {
      await sync();
    },
    lastError(jobId) {
      return lastErrors.get(jobId);
    },
  };
}
