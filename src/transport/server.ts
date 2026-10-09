/**
 * Receiving side of the interim transport.
 *
 * Serves `POST /colony-rfq/v0/messages`. Every request is a signed envelope
 * from a configured peer addressed to this role. A packet is persisted in the
 * inbox (same transaction as its nonce) BEFORE the signed acknowledgement is
 * produced; a lookup is answered from that same store. Plain HTTP binds to
 * loopback only; anything else requires TLS material.
 */

import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { Server as HttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import {
  RFQ_TRANSPORT_MAX_BODY_BYTES,
  RFQ_TRANSPORT_PATH,
  createEnvelope,
  verifyEnvelope,
} from "./envelope.js";
import type {
  PeerKeyTable,
  RfqAckPayload,
  RfqTransportEnvelope,
  TransportIdentity,
} from "./envelope.js";
import type { RfqInboxStore } from "./inboxStore.js";

const PACKET_KINDS: ReadonlySet<string> = new Set(["turn", "agreement-proposal", "agreement-contribution", "open"]);
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export interface RfqTransportServerOptions {
  self: TransportIdentity;
  peers: PeerKeyTable;
  inbox: RfqInboxStore;
  nowMs?: () => number;
  hostname?: string;
  port?: number;
  tls?: { key: string | Buffer; cert: string | Buffer };
  maxBodyBytes?: number;
  /** Called after a packet is durably stored and acknowledged. */
  onPacketStored?: (packetId: string) => void;
  /** Public GET documents, e.g. the §6.3.5 well-known files; served byte-exact. */
  staticDocuments?: () => Readonly<Record<string, string>>;
  /** Tester registration: POST /colony-rfq/v0/register, GET /colony-rfq/v0/register/<claim>. */
  registration?: {
    submit(body: unknown): Promise<{ status: number; body: unknown }>;
    status(claim: string): Promise<{ status: number; body: unknown }>;
  };
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface RfqTransportServer {
  readonly endpoint: string;
  readonly port: number;
  readonly server: HttpServer | HttpsServer;
  close: () => Promise<void>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readBody(request: IncomingMessage, maxBytes: number): Promise<Buffer | "too-large"> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        request.removeAllListeners("data");
        resolve("too-large");
        request.resume();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(bytes.length),
    "cache-control": "no-store",
  });
  response.end(bytes);
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

export async function startRfqTransportServer(options: RfqTransportServerOptions): Promise<RfqTransportServer> {
  const hostname = options.hostname ?? "127.0.0.1";
  if (options.tls === undefined && !LOOPBACK.has(hostname)) {
    throw new Error("plain HTTP is restricted to loopback; supply TLS key and cert for other bindings");
  }
  const nowMs = options.nowMs ?? Date.now;
  const log = options.log ?? (() => {});
  const maxBody = options.maxBodyBytes ?? RFQ_TRANSPORT_MAX_BODY_BYTES;

  const ack = async (envelope: RfqTransportEnvelope, payload: RfqAckPayload) =>
    createEnvelope({ type: "rfq-ack", audience: envelope.sender, payload, nowMs: nowMs() }, options.self);

  const handle = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    if (request.method === "GET" && options.staticDocuments !== undefined) {
      const path = (request.url ?? "/").split("?")[0]!;
      const body = options.staticDocuments()[path];
      if (body !== undefined) {
        const bytes = Buffer.from(body, "utf8");
        response.writeHead(200, { "content-type": "application/json; charset=utf-8", "content-length": String(bytes.length), "cache-control": "public, max-age=60" });
        response.end(bytes);
        return;
      }
    }
    if (options.registration !== undefined && (request.url ?? "").startsWith("/colony-rfq/v0/register")) {
      const rest = (request.url ?? "").slice("/colony-rfq/v0/register".length).split("?")[0]!;
      if (request.method === "GET" && rest.startsWith("/") && rest.length > 1) {
        const view = await options.registration.status(decodeURIComponent(rest.slice(1)));
        writeJson(response, view.status, view.body);
        return;
      }
      if (request.method === "POST" && rest === "") {
        const raw = await readBody(request, maxBody);
        if (raw === "too-large") { writeJson(response, 413, { error: "body-too-large" }); return; }
        let parsed: unknown;
        try { parsed = JSON.parse(raw.toString("utf8")); } catch { writeJson(response, 400, { error: "body-not-json" }); return; }
        const outcome = await options.registration.submit(parsed);
        writeJson(response, outcome.status, outcome.body);
        return;
      }
      writeJson(response, 404, { error: "not-found" });
      return;
    }
    if (request.method !== "POST" || request.url !== RFQ_TRANSPORT_PATH) {
      writeJson(response, 404, { error: "not-found" });
      return;
    }
    const body = await readBody(request, maxBody);
    if (body === "too-large") {
      writeJson(response, 413, { error: "body-too-large" });
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString("utf8"));
    } catch {
      writeJson(response, 400, { error: "body-not-json" });
      return;
    }
    const verified = verifyEnvelope(parsed, {
      expectedAudience: options.self.claim,
      peers: options.peers,
      nowMs: nowMs(),
    });
    if (!verified.ok) {
      log({ event: "transport-envelope-rejected", reason: verified.reason });
      writeJson(response, 401, { error: "envelope-not-authenticated", reason: verified.reason });
      return;
    }
    const envelope = verified.envelope;
    const now = nowMs();

    if (envelope.type === "rfq-packet") {
      const { packet, packetHash } = envelope.payload as { packet: Record<string, unknown>; packetHash: string };
      const shapeError = validatePacketShape(packet, envelope.sender, options.self.claim);
      const packetId = typeof packet["packetId"] === "string" ? packet["packetId"] : "";
      if (shapeError !== null) {
        writeJson(response, 200, await ack(envelope, {
          inReplyTo: envelope.envelopeId, disposition: "rejected", packetId, reason: shapeError,
        }));
        return;
      }
      let admission;
      try {
        admission = options.inbox.admit({
          packet, packetHash, envelopeId: envelope.envelopeId, nonce: envelope.nonce,
          nonceExpiresAt: envelope.expiresAt, sender: envelope.sender, nowMs: now,
        });
      } catch (cause) {
        // Store unavailable: do not acknowledge anything.
        log({ event: "transport-inbox-unavailable", reason: cause instanceof Error ? cause.message : String(cause) });
        writeJson(response, 503, { error: "inbox-unavailable" });
        return;
      }
      if (admission.outcome === "replay") {
        writeJson(response, 401, { error: "envelope-replayed" });
        return;
      }
      const disposition = admission.outcome;
      log({ event: "transport-packet", packetId, disposition, sender: envelope.sender });
      writeJson(response, 200, await ack(envelope, {
        inReplyTo: envelope.envelopeId, disposition, packetId, packetHash,
        ...(admission.outcome === "conflict" ? { reason: admission.reason } : {}),
      }));
      if (admission.outcome === "stored") options.onPacketStored?.(packetId);
      return;
    }

    if (envelope.type === "rfq-lookup") {
      const { packetId, packetHash } = envelope.payload as { packetId: string; packetHash: string };
      let fresh: boolean;
      try {
        fresh = options.inbox.recordNonce(envelope.nonce, envelope.sender, envelope.expiresAt, now);
      } catch {
        writeJson(response, 503, { error: "inbox-unavailable" });
        return;
      }
      if (!fresh) {
        writeJson(response, 401, { error: "envelope-replayed" });
        return;
      }
      const found = options.inbox.lookup(packetId);
      const payload: RfqAckPayload = found === null
        ? { inReplyTo: envelope.envelopeId, disposition: "absent", packetId }
        : found.packetHash === packetHash
          ? { inReplyTo: envelope.envelopeId, disposition: "present", packetId, packetHash: found.packetHash }
          : { inReplyTo: envelope.envelopeId, disposition: "conflict", packetId, packetHash: found.packetHash,
              reason: "packetId is bound to different bytes" };
      log({ event: "transport-lookup", packetId, disposition: payload.disposition, sender: envelope.sender });
      writeJson(response, 200, await ack(envelope, payload));
      return;
    }

    writeJson(response, 200, await ack(envelope, {
      inReplyTo: envelope.envelopeId, disposition: "rejected", packetId: "", reason: "acknowledgements are not accepted here",
    }));
  };

  const listener = (request: IncomingMessage, response: ServerResponse) => {
    handle(request, response).catch((cause) => {
      log({ event: "transport-handler-error", reason: cause instanceof Error ? cause.message : String(cause) });
      if (!response.headersSent) writeJson(response, 500, { error: "internal" });
      else response.destroy();
    });
  };
  const server = options.tls === undefined
    ? createHttpServer(listener)
    : createHttpsServer({ key: options.tls.key, cert: options.tls.cert }, listener);
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, hostname, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  const scheme = options.tls === undefined ? "http" : "https";
  const host = address.family === "IPv6" ? `[${address.address}]` : address.address;
  return {
    endpoint: `${scheme}://${host}:${address.port}${RFQ_TRANSPORT_PATH}`,
    port: address.port,
    server,
    close: () => new Promise<void>((resolve, reject) => {
      server.closeAllConnections?.();
      server.close((error) => (error ? reject(error) : resolve()));
    }),
  };
}

export function isRecordValue(value: unknown): value is Record<string, unknown> {
  return isRecord(value);
}
