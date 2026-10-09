/**
 * Interim direct transport envelope — "private negotiation, L2PS transport coming".
 *
 * This is a colony-local, mutually authenticated carrier for the SDK's opaque
 * `RfqLifecyclePacket` bytes. It is NOT a DACS wire format and uses its own
 * domain separators so nothing here can be confused with a DACS artifact.
 * Confidentiality comes from TLS on the hop (plain HTTP is loopback-only);
 * authenticity and replay protection come from the Ed25519 envelope below.
 *
 * Signed bytes: UTF8("colony-rfq-transport:v0:") || ASCII(lowercase-hex sha256(JCS(unsigned)))
 */

import { randomBytes } from "node:crypto";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs/canonical";
import { ed25519Verify, publicKeyFromRaw } from "@kynesyslabs/dacs/crypto";
import { signBytes } from "../signer.js";
import type { Ed25519Signer } from "../signer.js";
import { decodeCanonicalBase64Url, encodeCanonicalBase64Url } from "../channelSignature.js";

export const RFQ_TRANSPORT_VERSION = "0" as const;
export const RFQ_TRANSPORT_PATH = "/colony-rfq/v0/messages" as const;
export const RFQ_TRANSPORT_DOMAIN = "colony-rfq-transport:v0:" as const;
export const RFQ_TRANSPORT_ID_DOMAIN = "colony-rfq-transport-id:v0:" as const;
export const RFQ_TRANSPORT_MAX_LIFETIME_MS = 300_000;
export const RFQ_TRANSPORT_MAX_FUTURE_SKEW_MS = 60_000;
export const RFQ_TRANSPORT_MAX_BODY_BYTES = 262_144;
export const RFQ_TRANSPORT_LABEL =
  "interim direct transport (colony-rfq-transport:v0); L2PS transport pending" as const;

export type RfqTransportMessageType = "rfq-packet" | "rfq-lookup" | "rfq-ack";

export type RfqTransportAckDisposition =
  | "stored"
  | "duplicate"
  | "present"
  | "absent"
  | "conflict"
  | "rejected";

export interface RfqPacketPayload {
  packet: Record<string, unknown>;
  packetHash: string;
}

export interface RfqLookupPayload {
  packetId: string;
  packetHash: string;
}

export interface RfqAckPayload {
  inReplyTo: string;
  disposition: RfqTransportAckDisposition;
  packetId: string;
  packetHash?: string;
  reason?: string;
}

export interface RfqTransportPayloadByType {
  "rfq-packet": RfqPacketPayload;
  "rfq-lookup": RfqLookupPayload;
  "rfq-ack": RfqAckPayload;
}

export interface RfqTransportUnsignedEnvelope<T extends RfqTransportMessageType = RfqTransportMessageType> {
  envelopeVersion: typeof RFQ_TRANSPORT_VERSION;
  envelopeId: string;
  type: T;
  sender: string;
  audience: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
  payload: RfqTransportPayloadByType[T];
}

export interface RfqTransportSignature {
  algorithm: "ed25519";
  signer: string;
  value: string;
}

export interface RfqTransportEnvelope<T extends RfqTransportMessageType = RfqTransportMessageType>
  extends RfqTransportUnsignedEnvelope<T> {
  signature: RfqTransportSignature;
}

export type TransportIdentity = Ed25519Signer;

/** Fixed peer table: canonical claim → raw Ed25519 public key. */
export type PeerKeyTable = ReadonlyMap<string, Uint8Array>;

const HEX64 = /^[0-9a-f]{64}$/;
const TYPES: ReadonlySet<string> = new Set(["rfq-packet", "rfq-lookup", "rfq-ack"]);
const DISPOSITIONS: ReadonlySet<string> = new Set([
  "stored", "duplicate", "present", "absent", "conflict", "rejected",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.length > 0;
const safeTime = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export function packetHashHex(packet: Readonly<Record<string, unknown>>): string {
  return sha256Hex(canonicalize(packet));
}

export function generateNonce(): string {
  return randomBytes(32).toString("base64url");
}

function envelopeId(input: {
  type: string; sender: string; audience: string; nonce: string; issuedAt: number; payloadHash: string;
}): string {
  return sha256Hex(`${RFQ_TRANSPORT_ID_DOMAIN}${canonicalize(input)}`);
}

function withoutSignature(envelope: Record<string, unknown>): Record<string, unknown> {
  const unsigned: Record<string, unknown> = {};
  for (const key of Object.keys(envelope)) if (key !== "signature") unsigned[key] = envelope[key];
  return unsigned;
}

export function envelopeSignedBytes(unsigned: Readonly<Record<string, unknown>>): Uint8Array {
  return Buffer.from(`${RFQ_TRANSPORT_DOMAIN}${sha256Hex(canonicalize(unsigned))}`, "utf8");
}

export interface CreateEnvelopeInput<T extends RfqTransportMessageType> {
  type: T;
  audience: string;
  payload: RfqTransportPayloadByType[T];
  nowMs: number;
  lifetimeMs?: number;
  nonce?: string;
}

export async function createEnvelope<T extends RfqTransportMessageType>(
  input: CreateEnvelopeInput<T>,
  identity: TransportIdentity,
): Promise<RfqTransportEnvelope<T>> {
  const lifetime = Math.min(input.lifetimeMs ?? RFQ_TRANSPORT_MAX_LIFETIME_MS, RFQ_TRANSPORT_MAX_LIFETIME_MS);
  const nonce = input.nonce ?? generateNonce();
  const payloadHash = sha256Hex(canonicalize(input.payload as unknown as Record<string, unknown>));
  const unsigned: RfqTransportUnsignedEnvelope<T> = {
    envelopeVersion: RFQ_TRANSPORT_VERSION,
    envelopeId: envelopeId({
      type: input.type, sender: identity.claim, audience: input.audience, nonce,
      issuedAt: input.nowMs, payloadHash,
    }),
    type: input.type,
    sender: identity.claim,
    audience: input.audience,
    issuedAt: input.nowMs,
    expiresAt: input.nowMs + lifetime,
    nonce,
    payload: input.payload,
  };
  const value = encodeCanonicalBase64Url(
    await signBytes(identity, envelopeSignedBytes(unsigned as unknown as Record<string, unknown>)),
  );
  return { ...unsigned, signature: { algorithm: "ed25519", signer: identity.claim, value } };
}

function validatePayload(type: RfqTransportMessageType, payload: unknown): string | null {
  if (!isRecord(payload)) return "payload is not an object";
  const keys = Object.keys(payload);
  switch (type) {
    case "rfq-packet": {
      if (keys.length !== 2 || !isRecord(payload["packet"]) || !HEX64.test(String(payload["packetHash"]))) {
        return "rfq-packet payload is malformed";
      }
      if (packetHashHex(payload["packet"]) !== payload["packetHash"]) return "packetHash does not match packet";
      return null;
    }
    case "rfq-lookup":
      return keys.length === 2 && nonEmpty(payload["packetId"]) && HEX64.test(String(payload["packetHash"]))
        ? null : "rfq-lookup payload is malformed";
    case "rfq-ack": {
      const allowed = ["inReplyTo", "disposition", "packetId", "packetHash", "reason"];
      if (!keys.every((key) => allowed.includes(key))) return "rfq-ack payload has unexpected members";
      if (!HEX64.test(String(payload["inReplyTo"])) || !nonEmpty(payload["packetId"]) ||
          !DISPOSITIONS.has(String(payload["disposition"]))) return "rfq-ack payload is malformed";
      if ("packetHash" in payload && !HEX64.test(String(payload["packetHash"]))) return "rfq-ack packetHash is malformed";
      if ("reason" in payload && typeof payload["reason"] !== "string") return "rfq-ack reason is malformed";
      return null;
    }
  }
}

export interface VerifyEnvelopeOptions {
  expectedAudience: string;
  peers: PeerKeyTable;
  nowMs: number;
  /** Required when verifying an acknowledgement. */
  expectedType?: RfqTransportMessageType;
}

export type VerifyEnvelopeResult =
  | { ok: true; envelope: RfqTransportEnvelope }
  | { ok: false; reason: string };

/** Structural, temporal, peer and signature checks. Nonce replay is the store's job. */
export function verifyEnvelope(value: unknown, options: VerifyEnvelopeOptions): VerifyEnvelopeResult {
  if (!isRecord(value)) return { ok: false, reason: "envelope is not an object" };
  const expected = ["envelopeVersion", "envelopeId", "type", "sender", "audience", "issuedAt", "expiresAt", "nonce", "payload", "signature"];
  const keys = Object.keys(value);
  if (keys.length !== expected.length || !expected.every((key) => keys.includes(key))) {
    return { ok: false, reason: "envelope has an unexpected member set" };
  }
  if (value["envelopeVersion"] !== RFQ_TRANSPORT_VERSION) return { ok: false, reason: "unknown envelope version" };
  if (!TYPES.has(String(value["type"]))) return { ok: false, reason: "unknown envelope type" };
  const type = value["type"] as RfqTransportMessageType;
  if (options.expectedType !== undefined && type !== options.expectedType) {
    return { ok: false, reason: `expected ${options.expectedType} envelope` };
  }
  if (!nonEmpty(value["sender"]) || !nonEmpty(value["audience"]) || value["sender"] === value["audience"]) {
    return { ok: false, reason: "sender or audience is malformed" };
  }
  if (value["audience"] !== options.expectedAudience) return { ok: false, reason: "envelope is addressed to another party" };
  if (!safeTime(value["issuedAt"]) || !safeTime(value["expiresAt"])) return { ok: false, reason: "envelope times are malformed" };
  if (value["expiresAt"] <= value["issuedAt"] || value["expiresAt"] - value["issuedAt"] > RFQ_TRANSPORT_MAX_LIFETIME_MS) {
    return { ok: false, reason: "envelope lifetime is invalid" };
  }
  if (value["issuedAt"] > options.nowMs + RFQ_TRANSPORT_MAX_FUTURE_SKEW_MS) return { ok: false, reason: "envelope is from the future" };
  if (value["expiresAt"] < options.nowMs) return { ok: false, reason: "envelope has expired" };
  if (decodeCanonicalBase64Url(value["nonce"]) === null || (value["nonce"] as string).length < 40) {
    return { ok: false, reason: "nonce is malformed" };
  }
  const payloadError = validatePayload(type, value["payload"]);
  if (payloadError !== null) return { ok: false, reason: payloadError };
  const payloadHash = sha256Hex(canonicalize(value["payload"] as Record<string, unknown>));
  const expectedId = envelopeId({
    type, sender: value["sender"], audience: value["audience"], nonce: value["nonce"] as string,
    issuedAt: value["issuedAt"], payloadHash,
  });
  if (value["envelopeId"] !== expectedId) return { ok: false, reason: "envelopeId does not bind the envelope" };

  const signature = value["signature"];
  if (!isRecord(signature) || Object.keys(signature).length !== 3 || signature["algorithm"] !== "ed25519" ||
      signature["signer"] !== value["sender"]) {
    return { ok: false, reason: "signature envelope is malformed" };
  }
  const sigBytes = decodeCanonicalBase64Url(signature["value"]);
  if (sigBytes === null || sigBytes.length !== 64) return { ok: false, reason: "signature value is malformed" };
  const peerKey = options.peers.get(value["sender"]);
  if (peerKey === undefined) return { ok: false, reason: "sender is not a configured peer" };
  const verified = ed25519Verify(envelopeSignedBytes(withoutSignature(value)), sigBytes, publicKeyFromRaw(peerKey));
  return verified
    ? { ok: true, envelope: value as unknown as RfqTransportEnvelope }
    : { ok: false, reason: "envelope signature does not verify" };
}
