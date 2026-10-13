/**
 * Sending side of the interim transport, implementing the SDK's
 * `DurableRfqLifecycleTransport` contract:
 *
 * - `publish` returns `acknowledged` only when the recipient's signed
 *   acknowledgement says the exact packet bytes are durably stored (fresh
 *   store or byte-identical duplicate). Anything unverifiable (network error,
 *   timeout, unsigned or mismatched response) is `indeterminate`, never a
 *   retry decision.
 * - `reconcile` asks the recipient's durable inbox about the packetId. A signed
 *   `absent` from the recipient is the only path to `absent`; the SDK may then
 *   resend the same packetId and bytes.
 */

import type { DurableRfqLifecycleTransport, RfqLifecyclePacket, RfqLifecycleTransportResult } from "@kynesyslabs/dacs/negotiate";
import { createEnvelope, packetHashHex, verifyEnvelope } from "./envelope.js";
import type { PeerKeyTable, RfqAckPayload, TransportIdentity } from "./envelope.js";
import type { RfqSessionAnnouncement } from "./open.js";

export type RfqHttpFetch = (input: string, init: RequestInit) => Promise<Response>;

export interface RfqHttpTransportOptions {
  self: TransportIdentity;
  peers: PeerKeyTable;
  /** Recipient claim → endpoint URL (full path). */
  endpoints: ReadonlyMap<string, string>;
  fetch?: RfqHttpFetch;
  nowMs?: () => number;
  requestTimeoutMs?: number;
  maxResponseBytes?: number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

type PublishResult = Exclude<RfqLifecycleTransportResult, { disposition: "absent" }>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export interface RfqHttpTransport<TSignature = unknown> extends DurableRfqLifecycleTransport<TSignature> {
  /** Announce a session to the seller before the first turn (see transport/open.ts). */
  announce(announcement: Readonly<RfqSessionAnnouncement>): Promise<PublishResult>;
}

export function createRfqHttpTransport<TSignature = unknown>(
  options: RfqHttpTransportOptions,
): RfqHttpTransport<TSignature> {
  const nowMs = options.nowMs ?? Date.now;
  const doFetch: RfqHttpFetch = options.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = options.requestTimeoutMs ?? 10_000;
  const maxResponse = options.maxResponseBytes ?? 65_536;
  const log = options.log ?? (() => {});

  type Exchange =
    | { status: "ack"; ack: RfqAckPayload }
    | { status: "rejected"; reason: string }
    | { status: "indeterminate"; reason: string };

  async function exchange(
    recipient: string,
    type: "rfq-packet" | "rfq-lookup",
    payload: Record<string, unknown>,
    packetId: string,
  ): Promise<Exchange> {
    const endpoint = options.endpoints.get(recipient);
    if (endpoint === undefined) return { status: "rejected", reason: "recipient has no configured endpoint" };
    if (!options.peers.has(recipient)) return { status: "rejected", reason: "recipient is not a configured peer" };
    const envelope = await createEnvelope(
      { type, audience: recipient, payload: payload as never, nowMs: nowMs() },
      options.self,
    );
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await doFetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json; charset=utf-8", accept: "application/json" },
        body: JSON.stringify(envelope),
        signal: controller.signal,
      });
    } catch (cause) {
      clearTimeout(timer);
      return { status: "indeterminate", reason: cause instanceof Error ? cause.message : "request failed" };
    }
    let text: string;
    try {
      text = await response.text();
    } catch (cause) {
      return { status: "indeterminate", reason: cause instanceof Error ? cause.message : "response unreadable" };
    } finally {
      clearTimeout(timer);
    }
    if (text.length > maxResponse) return { status: "indeterminate", reason: "response too large" };
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return { status: "indeterminate", reason: `non-JSON response (HTTP ${response.status})` };
    }
    if (response.status !== 200) {
      // The recipient refused to authenticate us or is unavailable. We cannot
      // know whether anything was stored; only a signed answer can say.
      const reason = isRecord(body) && typeof body["reason"] === "string" ? body["reason"] : `HTTP ${response.status}`;
      return { status: "indeterminate", reason };
    }
    const verified = verifyEnvelope(body, {
      expectedAudience: options.self.claim,
      peers: options.peers,
      nowMs: nowMs(),
      expectedType: "rfq-ack",
    });
    if (!verified.ok) return { status: "indeterminate", reason: `acknowledgement not authenticated: ${verified.reason}` };
    if (verified.envelope.sender !== recipient) return { status: "indeterminate", reason: "acknowledgement signed by another peer" };
    const ack = verified.envelope.payload as RfqAckPayload;
    if (ack.inReplyTo !== envelope.envelopeId) return { status: "indeterminate", reason: "acknowledgement is not bound to this request" };
    if (ack.packetId !== packetId) return { status: "indeterminate", reason: "acknowledgement names another packet" };
    return { status: "ack", ack };
  }

  async function publishRecord(record: Record<string, unknown>, recipient: string, packetId: string): Promise<PublishResult> {
    const packetHash = packetHashHex(record);
    const result = await exchange(recipient, "rfq-packet", { packet: record, packetHash }, packetId);
    if (result.status !== "ack") return { disposition: result.status, reason: result.reason };
    const ack = result.ack;
    switch (ack.disposition) {
      case "stored":
      case "duplicate":
        return ack.packetHash === packetHash
          ? { disposition: "acknowledged" as const }
          : { disposition: "rejected" as const, reason: "recipient holds different bytes for this packetId" };
      case "conflict":
        return { disposition: "rejected" as const, reason: ack.reason ?? "packetId conflict" };
      case "rejected":
        return { disposition: "rejected" as const, reason: ack.reason ?? "recipient rejected the packet" };
      default:
        return { disposition: "indeterminate" as const, reason: `unexpected acknowledgement ${ack.disposition}` };
    }
  }

  return {
    async announce(announcement) {
      const outcome = await publishRecord(announcement as unknown as Record<string, unknown>, announcement.recipient, announcement.packetId);
      log({ event: "transport-announce", jobId: announcement.jobId, recipient: announcement.recipient, ...outcome });
      return outcome;
    },
    async publish(packet) {
      const record = packet as unknown as Record<string, unknown>;
      const packetHash = packetHashHex(record);
      const result = await exchange(packet.recipient, "rfq-packet", { packet: record, packetHash }, packet.packetId);
      const outcome: PublishResult = (() => {
        if (result.status !== "ack") return { disposition: result.status, reason: result.reason };
        const ack = result.ack;
        switch (ack.disposition) {
          case "stored":
          case "duplicate":
            return ack.packetHash === packetHash
              ? { disposition: "acknowledged" as const }
              : { disposition: "rejected" as const, reason: "recipient holds different bytes for this packetId" };
          case "conflict":
            return { disposition: "rejected" as const, reason: ack.reason ?? "packetId conflict" };
          case "rejected":
            return { disposition: "rejected" as const, reason: ack.reason ?? "recipient rejected the packet" };
          default:
            return { disposition: "indeterminate" as const, reason: `unexpected acknowledgement ${ack.disposition}` };
        }
      })();
      log({ event: "transport-publish", packetId: packet.packetId, recipient: packet.recipient, ...outcome });
      return outcome;
    },
    async reconcile(packet) {
      const record = packet as unknown as Record<string, unknown>;
      const packetHash = packetHashHex(record);
      const result = await exchange(packet.recipient, "rfq-lookup", { packetId: packet.packetId, packetHash }, packet.packetId);
      const outcome: RfqLifecycleTransportResult = (() => {
        if (result.status !== "ack") return { disposition: result.status, reason: result.reason };
        const ack = result.ack;
        switch (ack.disposition) {
          case "present":
            return ack.packetHash === packetHash
              ? { disposition: "acknowledged" as const }
              : { disposition: "rejected" as const, reason: "recipient holds different bytes for this packetId" };
          case "absent":
            return { disposition: "absent" as const };
          case "conflict":
            return { disposition: "rejected" as const, reason: ack.reason ?? "packetId conflict" };
          case "rejected":
            return { disposition: "rejected" as const, reason: ack.reason ?? "recipient rejected the lookup" };
          default:
            return { disposition: "indeterminate" as const, reason: `unexpected acknowledgement ${ack.disposition}` };
        }
      })();
      log({ event: "transport-reconcile", packetId: packet.packetId, recipient: packet.recipient, ...outcome });
      return outcome;
    },
  } satisfies RfqHttpTransport<TSignature>;
}

export type { RfqLifecyclePacket };
