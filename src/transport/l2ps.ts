/**
 * L2PS carrier for the durable RFQ lifecycle (Step 4 of the brief).
 *
 * Every lifecycle packet travels as the payload of an encrypted L2PS subnet
 * transaction: a native send of a token amount from the sender's wallet to the
 * recipient's wallet whose data member carries the same Ed25519-signed
 * `colony-rfq-transport:v0` envelope the interim HTTP transport uses. The
 * subnet key gives confidentiality against everyone outside the subnet; the
 * envelope keeps authenticity and CH-7 binding to the member claim; the host
 * node's signed history read gives durable delivery evidence.
 *
 *  - `publish` returns `acknowledged` only when the host node's history shows
 *    the carrier transaction at or beyond the configured status (default
 *    `confirmed`, i.e. batched into the L1 and settled), `rejected` when the
 *    node executed it as `failed`, otherwise `indeterminate`.
 *  - `reconcile` re-reads the sender's own history: the exact packet present
 *    at or beyond the threshold is `acknowledged`; present but not yet there is
 *    `indeterminate`; absent or failed is `absent` (the history read is a
 *    signed request to the host node, which this deployment operates).
 *  - The feeder turns history entries addressed to this member into inbox
 *    rows exactly as the HTTP server does, so `drainInbox` is unchanged.
 *
 * Nothing here reads a subnet key: the client abstraction owns encryption.
 */

import type { DurableRfqLifecycleTransport, RfqLifecyclePacket, RfqLifecycleTransportResult } from "@kynesyslabs/dacs/negotiate";
import { createEnvelope, packetHashHex, verifyEnvelope } from "./envelope.js";
import type { PeerKeyTable, RfqTransportEnvelope, TransportIdentity } from "./envelope.js";
import type { RfqInboxStore } from "./inboxStore.js";
import type { RfqSessionAnnouncement } from "./open.js";

export const L2PS_CARRIER_VERSION = "colony-rfq-l2ps:v0" as const;
/** How far ahead of the reader's clock a carrier may be dated. */
const FUTURE_SKEW_MS = 60_000;
export type L2psAckStatus = "pending" | "batched" | "confirmed";
const STATUS_RANK: Record<string, number> = { pending: 0, batched: 1, confirmed: 2 };
const PACKET_KINDS: ReadonlySet<string> = new Set(["turn", "agreement-proposal", "agreement-contribution", "open"]);

/** One subnet history row as the node's history table holds it (decrypted for the reader). */
export interface L2psHistoryEntry {
  hash: string;
  from: string;
  to: string;
  status: string;
  timestamp: number;
  /** Decrypted inner transaction content; the carrier sits at `data[1].rfq`. */
  content?: { data?: unknown } | null;
}

/** The slice of a subnet client the carrier needs. Encryption and signing live behind it. */
export interface L2psCarrierClient {
  /** This member's 0x-prefixed wallet address on the subnet chain. */
  address(): string;
  /** Encrypt and submit one carrier transaction; resolves once the node accepted it for execution. */
  send(input: Readonly<{ to: string; carrier: Readonly<Record<string, unknown>> }>): Promise<{ innerHash: string }>;
  /** Signed read of this member's own subnet history, newest first. */
  history(options?: Readonly<{ since?: number; limit?: number }>): Promise<readonly L2psHistoryEntry[]>;
}

export interface L2psCarrierRecord {
  carrier: typeof L2PS_CARRIER_VERSION;
  envelope: RfqTransportEnvelope<"rfq-packet">;
}

export function carrierOf(entry: Readonly<L2psHistoryEntry>): L2psCarrierRecord | null {
  const data = entry.content?.data;
  if (!Array.isArray(data) || data.length < 2) return null;
  const payload = data[1];
  if (payload === null || typeof payload !== "object") return null;
  const rfq = (payload as { rfq?: unknown }).rfq;
  if (rfq === null || typeof rfq !== "object") return null;
  const record = rfq as { carrier?: unknown; envelope?: unknown };
  if (record.carrier !== L2PS_CARRIER_VERSION || record.envelope === null || typeof record.envelope !== "object") return null;
  return record as L2psCarrierRecord;
}

const sameAddress = (a: string, b: string): boolean => a.replace(/^0x/i, "").toLowerCase() === b.replace(/^0x/i, "").toLowerCase();

export interface L2psTransportOptions {
  self: TransportIdentity;
  peers: PeerKeyTable;
  /** Member claim → 0x wallet address on the subnet chain. */
  addresses: ReadonlyMap<string, string>;
  /** One subnet for every peer (two-party deployments). */
  client?: L2psCarrierClient;
  /** Or a subnet per peer: the client for the subnet this recipient is a member of. */
  clientFor?: (recipient: string) => L2psCarrierClient | undefined;
  /** History status that counts as durable acceptance. Default `confirmed`. */
  ackStatus?: L2psAckStatus;
  ackTimeoutMs?: number;
  pollIntervalMs?: number;
  nowMs?: () => number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

type PublishResult = Exclude<RfqLifecycleTransportResult, { disposition: "absent" }>;

export interface L2psTransport<TSignature = unknown> extends DurableRfqLifecycleTransport<TSignature> {
  announce(announcement: Readonly<RfqSessionAnnouncement>): Promise<PublishResult>;
}

export function createL2psTransport<TSignature = unknown>(options: L2psTransportOptions): L2psTransport<TSignature> {
  const nowMs = options.nowMs ?? Date.now;
  const log = options.log ?? (() => {});
  const threshold = STATUS_RANK[options.ackStatus ?? "confirmed"]!;
  const ackTimeoutMs = options.ackTimeoutMs ?? 90_000;
  const pollIntervalMs = options.pollIntervalMs ?? 1_000;
  const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

  if (options.client === undefined && options.clientFor === undefined) throw new Error("an L2PS client or clientFor is required");
  const clientFor = (recipient: string): L2psCarrierClient | undefined => options.clientFor?.(recipient) ?? options.client;

  function reached(status: string): boolean {
    return (STATUS_RANK[status] ?? -1) >= threshold;
  }

  async function findOwn(client: L2psCarrierClient, predicate: (entry: L2psHistoryEntry, carrier: L2psCarrierRecord) => boolean): Promise<{ entry: L2psHistoryEntry; carrier: L2psCarrierRecord } | null> {
    const self = client.address();
    const entries = await client.history({ limit: 200 });
    for (const entry of entries) {
      if (!sameAddress(entry.from, self)) continue;
      const carrier = carrierOf(entry);
      if (carrier !== null && predicate(entry, carrier)) return { entry, carrier };
    }
    return null;
  }

  async function carry(record: Record<string, unknown>, recipient: string, packetId: string): Promise<PublishResult> {
    if (!options.peers.has(recipient)) return { disposition: "rejected", reason: "recipient is not a configured peer" };
    const to = options.addresses.get(recipient);
    if (to === undefined) return { disposition: "rejected", reason: "recipient has no subnet address" };
    const client = clientFor(recipient);
    if (client === undefined) return { disposition: "rejected", reason: "recipient has no subnet on this node" };
    const packetHash = packetHashHex(record);
    const envelope = await createEnvelope({ type: "rfq-packet", audience: recipient, payload: { packet: record, packetHash }, nowMs: nowMs() }, options.self);
    const carrier: L2psCarrierRecord = { carrier: L2PS_CARRIER_VERSION, envelope };
    let innerHash: string;
    try {
      ({ innerHash } = await client.send({ to, carrier: carrier as unknown as Record<string, unknown> }));
    } catch (cause) {
      // The node may or may not have taken it: only history can say.
      return { disposition: "indeterminate", reason: cause instanceof Error ? cause.message : "subnet send failed" };
    }
    log({ event: "l2ps-carrier-sent", packetId, innerHash });
    const deadline = nowMs() + ackTimeoutMs;
    let lastStatus = "unseen";
    while (nowMs() < deadline) {
      let found: { entry: L2psHistoryEntry; carrier: L2psCarrierRecord } | null;
      try {
        found = await findOwn(client, (entry) => entry.hash === innerHash);
      } catch (cause) {
        return { disposition: "indeterminate", reason: cause instanceof Error ? cause.message : "subnet history unavailable" };
      }
      if (found !== null) {
        lastStatus = found.entry.status;
        if (found.entry.status === "failed") return { disposition: "rejected", reason: "host node executed the carrier transaction as failed" };
        if (reached(found.entry.status)) return { disposition: "acknowledged" };
      }
      await wait(pollIntervalMs);
    }
    return { disposition: "indeterminate", reason: `carrier ${innerHash.slice(0, 16)} status ${lastStatus} below ${options.ackStatus ?? "confirmed"} at deadline` };
  }

  return {
    async announce(announcement) {
      const outcome = await carry(announcement as unknown as Record<string, unknown>, announcement.recipient, announcement.packetId);
      log({ event: "transport-announce", jobId: announcement.jobId, recipient: announcement.recipient, ...outcome });
      return outcome;
    },
    async publish(packet) {
      const outcome = await carry(packet as unknown as Record<string, unknown>, packet.recipient, packet.packetId);
      log({ event: "transport-publish", packetId: packet.packetId, recipient: packet.recipient, ...outcome });
      return outcome;
    },
    async reconcile(packet) {
      const record = packet as unknown as Record<string, unknown>;
      const packetHash = packetHashHex(record);
      const client = clientFor(packet.recipient);
      if (client === undefined) return { disposition: "rejected", reason: "recipient has no subnet on this node" };
      let found: { entry: L2psHistoryEntry; carrier: L2psCarrierRecord } | null;
      try {
        found = await findOwn(client, (_entry, carrier) => {
          const payload = carrier.envelope.payload as { packet?: Record<string, unknown>; packetHash?: string };
          return payload.packet?.["packetId"] === packet.packetId && payload.packetHash === packetHash;
        });
      } catch (cause) {
        return { disposition: "indeterminate", reason: cause instanceof Error ? cause.message : "subnet history unavailable" };
      }
      const outcome: RfqLifecycleTransportResult = found === null || found.entry.status === "failed"
        ? { disposition: "absent" }
        : reached(found.entry.status)
          ? { disposition: "acknowledged" }
          : { disposition: "indeterminate", reason: `carrier status ${found.entry.status}` };
      log({ event: "transport-reconcile", packetId: packet.packetId, recipient: packet.recipient, ...outcome });
      return outcome;
    },
  } satisfies L2psTransport<TSignature>;
}

function validatePacketShape(packet: Record<string, unknown>, sender: string, self: string): string | null {
  if (packet["packetVersion"] !== "1") return "packetVersion must be \"1\"";
  for (const key of ["packetId", "jobId", "channelId", "sender", "recipient"]) {
    if (typeof packet[key] !== "string" || (packet[key] as string).length === 0) return `${key} is malformed`;
  }
  if (!PACKET_KINDS.has(String(packet["kind"]))) return "packet kind is unknown";
  if (packet["sender"] !== sender) return "packet sender does not match envelope sender";
  if (packet["recipient"] !== self) return "packet recipient is not this role";
  return null;
}

export interface L2psInboxFeederOptions {
  self: TransportIdentity;
  peers: PeerKeyTable;
  client: L2psCarrierClient;
  inbox: RfqInboxStore;
  nowMs?: () => number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface L2psInboxFeeder {
  /** Read history once and admit every new carrier addressed to this member. */
  poll(): Promise<{ stored: number; duplicates: number; rejected: number }>;
}

/**
 * Mirrors the HTTP server's admission: authenticate the envelope against the
 * peer table, check the packet shape, then persist into the inbox. The
 * envelope is verified as of its own issue time because the chain, not the
 * wire, is the durable medium here; replay and duplicates remain the inbox's
 * job (packetId is the primary key).
 */
export function createL2psInboxFeeder(options: L2psInboxFeederOptions): L2psInboxFeeder {
  const nowMs = options.nowMs ?? Date.now;
  const log = options.log ?? (() => {});
  const seen = new Set<string>();
  return {
    async poll() {
      const summary = { stored: 0, duplicates: 0, rejected: 0 };
      const self = options.client.address();
      const entries = await options.client.history({ limit: 200 });
      // Oldest first so arrival order in the inbox follows the chain.
      for (const entry of [...entries].reverse()) {
        if (seen.has(entry.hash) || !sameAddress(entry.to, self) || entry.status === "failed") continue;
        const carrier = carrierOf(entry);
        if (carrier === null) { seen.add(entry.hash); continue; }
        const envelope = carrier.envelope as unknown as { issuedAt?: number };
        // The chain, not the wire, is the durable medium: a carrier is read back
        // long after it was issued, so its expiry is checked as of its own issue
        // time (the signed lifetime is still capped), and replay is the inbox's
        // job (nonce + packetId). What is refused here is a carrier dated ahead
        // of this reader's clock beyond the allowed skew.
        if (typeof envelope.issuedAt === "number" && envelope.issuedAt > nowMs() + FUTURE_SKEW_MS) {
          log({ event: "l2ps-carrier-rejected", innerHash: entry.hash, reason: "carrier issued in the future" });
          seen.add(entry.hash); summary.rejected += 1; continue;
        }
        const verified = verifyEnvelope(carrier.envelope, {
          expectedAudience: options.self.claim, peers: options.peers, expectedType: "rfq-packet",
          nowMs: typeof envelope.issuedAt === "number" ? envelope.issuedAt : nowMs(),
        });
        if (!verified.ok) {
          log({ event: "l2ps-carrier-rejected", innerHash: entry.hash, reason: verified.reason });
          seen.add(entry.hash); summary.rejected += 1; continue;
        }
        const { packet, packetHash } = verified.envelope.payload as { packet: Record<string, unknown>; packetHash: string };
        const shapeError = validatePacketShape(packet, verified.envelope.sender, options.self.claim);
        if (shapeError !== null) {
          log({ event: "l2ps-carrier-rejected", innerHash: entry.hash, reason: shapeError });
          seen.add(entry.hash); summary.rejected += 1; continue;
        }
        const admission = options.inbox.admit({
          packet, packetHash, envelopeId: verified.envelope.envelopeId, nonce: verified.envelope.nonce,
          nonceExpiresAt: verified.envelope.expiresAt, sender: verified.envelope.sender, nowMs: nowMs(),
        });
        seen.add(entry.hash);
        log({ event: "transport-packet", packetId: packet["packetId"], disposition: admission.outcome, sender: verified.envelope.sender, innerHash: entry.hash });
        if (admission.outcome === "stored") summary.stored += 1;
        else if (admission.outcome === "duplicate" || admission.outcome === "replay") summary.duplicates += 1;
        else summary.rejected += 1;
      }
      return summary;
    },
  };
}

export type { RfqLifecyclePacket };
