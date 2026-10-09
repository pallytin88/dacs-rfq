/**
 * Seller side for the showcase: accept session announcements that match our
 * Listing, drain received turns, and answer with the rule policy. Runs as a
 * loop; every iteration is idempotent and restart-safe because all state lives
 * in the role stores and the inbox.
 */

import { contentHash } from "@kynesyslabs/dacs/canonical";
import type { AttestationRef, IdentityBundle } from "@kynesyslabs/dacs/artifacts";
import type { DurableRfqLifecycleClient, RfqLifecyclePolicy, VerifiedListingInput } from "@kynesyslabs/dacs/negotiate";
import type { SessionIndex } from "../sessionIndex.js";
import { drainInbox } from "../transport/drain.js";
import type { AnnouncementHandler } from "../transport/drain.js";
import type { RfqInboxStore } from "../transport/inboxStore.js";
import type { RfqSessionAnnouncement } from "../transport/open.js";
import type { Counterparty, SellerVetExchange } from "../live/vetExchange.js";

export interface SellerDaemonOptions<TSignature> {
  sellerClaim: string;
  sellerParty: { identityBundle: IdentityBundle; vetRecordRef: AttestationRef };
  /** The Listings this seller currently offers (exact verified bytes). */
  listings: () => Promise<readonly VerifiedListingInput[]> | readonly VerifiedListingInput[];
  client: DurableRfqLifecycleClient<TSignature>;
  inbox: RfqInboxStore;
  sessions: SessionIndex;
  policy: RfqLifecyclePolicy;
  /** Buyer claims allowed to open sessions; omit to accept any configured transport peer. */
  allowBuyers?: readonly string[] | (() => readonly string[]);
  /** Live vet exchange; when present the daemon verifies the buyer's vet of us and anchors ours of the buyer. */
  vet?: { exchange: SellerVetExchange; resolveBuyer: (claim: string) => Counterparty | null };
  nowMs?: () => number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface SellerDaemon {
  /** One pass: resume outboxes, drain inbox (opening announced sessions), respond where it is our turn. */
  tick(): Promise<{ opened: number; responded: number; errors: string[] }>;
  /** Run `tick` until `signal` aborts. */
  run(intervalMs: number, signal: AbortSignal): Promise<void>;
}

export function createSellerDaemon<TSignature>(options: SellerDaemonOptions<TSignature>): SellerDaemon {
  const nowMs = options.nowMs ?? Date.now;
  const log = options.log ?? (() => {});

  const onOpen: AnnouncementHandler = async (announcement: Readonly<RfqSessionAnnouncement>) => {
    if (announcement.recipient !== options.sellerClaim) return { status: "rejected", reason: "announcement is for another seller" };
    const allowed = typeof options.allowBuyers === "function" ? options.allowBuyers() : options.allowBuyers;
    if (allowed !== undefined && !allowed.includes(announcement.sender)) {
      return { status: "rejected", reason: "buyer is not allowed" };
    }
    const listings = await options.listings();
    const verified = listings.find((l) =>
      l.pin.listingId === announcement.listingPin.listingId &&
      l.pin.version === announcement.listingPin.version &&
      l.pin.contentHash === announcement.listingPin.contentHash &&
      contentHash(l.listing as unknown as Record<string, unknown>) === announcement.listingPin.contentHash);
    if (verified === undefined) return { status: "rejected", reason: "announced listing pin is not one of ours" };
    if (announcement.buyer.identityBundle.presentedBy !== announcement.sender) {
      return { status: "rejected", reason: "buyer bundle does not belong to the announcing sender" };
    }
    let buyerParty = announcement.buyer;
    let sellerParty = { identityBundle: options.sellerParty.identityBundle, vetRecordRef: announcement.sellerVetRef };
    if (options.vet !== undefined) {
      const buyer = options.vet.resolveBuyer(announcement.sender);
      if (buyer === null) return { status: "rejected", reason: "buyer key authority is unknown" };
      const vetted = await options.vet.exchange.verifyVetOfSeller(announcement, options.sellerParty.identityBundle, buyer);
      if (!vetted) return { status: "indeterminate", reason: "buyer's vet of the seller is not yet anchored or does not verify" };
      const ourVetOfBuyer = await options.vet.exchange.vetBuyer(announcement.jobId, announcement.buyer.identityBundle);
      buyerParty = { identityBundle: announcement.buyer.identityBundle, vetRecordRef: ourVetOfBuyer };
    } else {
      sellerParty = options.sellerParty;
    }
    const opened = await options.client.open({
      jobId: announcement.jobId,
      verifiedListing: verified,
      buyer: buyerParty,
      seller: sellerParty,
      channelId: announcement.channelId,
    });
    if (opened.status === "ready" || opened.status === "duplicate") {
      options.sessions.put({
        jobId: announcement.jobId, channelId: announcement.channelId,
        listingId: verified.listing.listingId, listingVersion: verified.listing.listingVersion,
        counterparty: announcement.sender, listingJson: JSON.stringify(verified), openedAt: nowMs(),
      });
      log({ event: "seller-session-opened", jobId: announcement.jobId, buyer: announcement.sender, status: opened.status });
      return { status: opened.status };
    }
    return { status: opened.status === "conflict" ? "rejected" : opened.status, reason: "reason" in opened ? opened.reason : undefined };
  };

  async function tick() {
    const errors: string[] = [];
    let opened = 0;
    let responded = 0;
    const before = new Set(options.sessions.list().map((e) => e.jobId));
    const summary = await drainInbox({ inbox: options.inbox, client: options.client, onOpen, nowMs, log });
    if (summary.stoppedAt !== undefined) errors.push(`drain stopped at ${summary.stoppedAt.packetId}: ${summary.stoppedAt.status} ${summary.stoppedAt.reason ?? ""}`);
    for (const entry of options.sessions.list()) {
      if (!before.has(entry.jobId)) opened += 1;
      const resumed = await options.client.resumeOutbox(entry.jobId);
      if (resumed.status !== "ready" && resumed.status !== "duplicate") {
        errors.push(`${entry.jobId}: outbox ${resumed.status} ${"reason" in resumed ? resumed.reason : ""}`);
        continue;
      }
      const status = await options.client.getStatus(entry.jobId);
      if (status.status !== "ok") { errors.push(`${entry.jobId}: store ${status.status}`); continue; }
      const session = status.record.session;
      if (session.status === "open" && session.expectedSender === options.sellerClaim && session.standingProposal !== undefined) {
        const result = await options.client.respond(entry.jobId, options.policy);
        if (result.status === "ready") responded += 1;
        else if (result.status !== "duplicate") errors.push(`${entry.jobId}: respond ${result.status} ${"reason" in result ? result.reason : ""}`);
      }
    }
    if (errors.length > 0) log({ event: "seller-tick-errors", errors });
    return { opened, responded, errors };
  }

  return {
    tick,
    async run(intervalMs, signal) {
      while (!signal.aborted) {
        try { await tick(); } catch (cause) { log({ event: "seller-tick-crash", reason: cause instanceof Error ? cause.message : String(cause) }); }
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, intervalMs);
          signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
        });
      }
    },
  };
}
