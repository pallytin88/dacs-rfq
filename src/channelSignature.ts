/**
 * Channel message signature profiles for the DACS RFQ lifecycle.
 *
 * Two profiles live here on purpose:
 *
 * 1. `dacs-canonical-channel-message:v1` — the normative DACS-3 v0.6 wire
 *    (DACS-Standard PR #367, CH-7/CH-8). A `CanonicalChannelMessage` carries
 *    the exclusive `canonicalChannelMessageVersion: "1"` discriminator and a
 *    `{ signatureVersion: "1", signer, algorithm, value }` envelope. The signed
 *    bytes are `UTF8("dacs-canonical-channel-message:v1:") ||
 *    ASCII(lowercase-hex sha256(JCS(unsigned_message)))`, with `value` as SIG-6
 *    unpadded Base64URL. `signCanonicalChannelMessage` / `readCanonicalChannelMessage`
 *    implement that end to end and are checked against the Standard's
 *    `canonical-channel-message-v0.6.json` corpus. The frozen historical wire is
 *    readable only through the explicitly selected `importLegacyChannelMessage`.
 *
 * 2. `provisional-rfq-sig:v0` — PROVISIONAL, NOT THE DACS STANDARD FORMAT.
 *    `@kynesyslabs/dacs` at 46c3e6a3 rejects the canonical discriminator in
 *    `validateMessage` / `unsignedEnvelope` (dacs-sdk#330), so the lifecycle
 *    client can only carry the seven-field historical envelope today. This
 *    profile applies the same construction (hex-ASCII digest framing, Base64URL
 *    value, version-1 signature envelope) to the SDK's seven-field envelope hash
 *    under a deliberately distinct domain prefix, so its bytes can never be
 *    mistaken for canonical ones. It is selected by configuration, recorded in
 *    logs, and will be removed once the SDK accepts the canonical type.
 *
 * Ed25519 and ECDSA secp256k1 (canonical DER, low-S) are implemented. SR-1
 * aggregate signatures are reported as `indeterminate` (recognised algorithm,
 * no verifier available) rather than silently rejected or accepted.
 */

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs/canonical";
import { ed25519Verify, publicKeyFromRaw } from "@kynesyslabs/dacs/crypto";
import { canonicalDemosAgentPublicKey } from "@kynesyslabs/dacs/identity";
import type {
  ChannelMessageSigningInput,
  ChannelMessageSignatureVerificationInput,
  RfqTurnBody,
} from "@kynesyslabs/dacs/negotiate";

export type VerificationDecision = "pass" | "fail" | "indeterminate" | "error";

export const CANONICAL_PROFILE_ID = "dacs-canonical-channel-message:v1" as const;
export const CANONICAL_DOMAIN = "dacs-canonical-channel-message:v1:" as const;
/** Frozen historical domain; `legacy-import` only. New producers MUST NOT emit it. */
export const LEGACY_DOMAIN = "dacs-channelmsg:v1:" as const;

export const PROVISIONAL_PROFILE_ID = "provisional-rfq-sig:v0" as const;
/** Deliberately distinct from every registered DACS domain separator. */
export const PROVISIONAL_DOMAIN = "provisional-rfq-sig:v0:" as const;

export type ChannelSignatureProfileId =
  | typeof CANONICAL_PROFILE_ID
  | typeof PROVISIONAL_PROFILE_ID;

export const CHANNEL_SIGNATURE_ALGORITHMS = Object.freeze([
  "ed25519",
  "ecdsa-secp256k1",
  "sr1-aggregate",
] as const);
export type ChannelSignatureAlgorithm = typeof CHANNEL_SIGNATURE_ALGORITHMS[number];

/** The version-1 signature envelope (DACS-3 v0.6 §8.3.3). */
export interface ChannelMessageSignatureV1 {
  signatureVersion: "1";
  signer: string;
  algorithm: ChannelSignatureAlgorithm;
  value: string;
}

export const CHANNEL_MESSAGE_TYPES = Object.freeze([
  "offer",
  "counter",
  "accept",
  "reject",
  "sealed-envelope-commit",
  "sealed-envelope-reveal",
  "abort",
] as const);

export interface UnsignedCanonicalChannelMessage {
  canonicalChannelMessageVersion: "1";
  channelId: string;
  sequence: number;
  sender: string;
  sentAt: number;
  type: typeof CHANNEL_MESSAGE_TYPES[number];
  body: unknown;
  refs?: { repliesTo?: number };
  /** CH-8 / SIG-5: unknown members are retained and signed. */
  [unknown: string]: unknown;
}

export interface CanonicalChannelMessage extends UnsignedCanonicalChannelMessage {
  signature: ChannelMessageSignatureV1;
}

/** CH-6 replay context supplied by the verifier-owned session state. Exact keys. */
export interface ChannelReadContext {
  sessionChannelId: string;
  lastSequence: number;
  priorChannelIds: readonly string[];
}

/**
 * Verifier-owned profile authority bound to the exact session and participant
 * set (DACS-3 v0.6 corrective profile boundary). Message-adjacent input can
 * never supply or replace it.
 */
export interface ChannelProfileAuthority {
  authenticated: boolean;
  sessionId: string;
  participantIdentities: readonly string[];
  releasePin: string;
  moduleVersions: Readonly<Record<string, string>>;
}

export interface ExpectedProfile {
  releasePin: string;
  moduleVersions: Readonly<Record<string, string>>;
}

export const DACS_V06_PROFILE: ExpectedProfile = Object.freeze({
  releasePin: "0d92f6642bdbd96655c8bb9a150b984d6be8bb67",
  moduleVersions: Object.freeze({
    core: "0.3", dacs1: "0.8", dacs2: "0.6", dacs3: "0.6", dacs4: "0.8", dacs5: "0.7",
  }),
});

/** Resolves a canonical claim identity to its authenticated primary key. */
export type MemberKeyResolution =
  | { status: "resolved"; algorithm: "ed25519"; publicKey: Uint8Array }
  | { status: "resolved"; algorithm: "ecdsa-secp256k1"; publicKey: Uint8Array }
  | { status: "resolved"; algorithm: "sr1-aggregate"; publicKey?: Uint8Array }
  | { status: "unresolved" };

export type MemberKeyResolver = (
  claim: string,
) => MemberKeyResolution | Promise<MemberKeyResolution>;

/** Fixed CH-1 member set plus the key authority for each member (adapter use). */
export interface ChannelMemberAuthority {
  members: readonly string[];
  resolve: MemberKeyResolver;
}

/** Authority for a canonical `current-read`: profile plus key resolution. */
export interface CanonicalReadAuthority {
  /** The verifier's own fixed CH-1 roster, established before negotiation. */
  members: readonly string[];
  /** `undefined` when no verifier-owned authority is available (indeterminate). */
  profile: unknown;
  expectedProfile: ExpectedProfile;
  resolve: MemberKeyResolver;
}

import { signBytes } from "./signer.js";
import type { Ed25519Signer } from "./signer.js";

/** @deprecated name kept for readability; any Ed25519Signer works. */
export type ChannelSigner = Ed25519Signer;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128_LOWER = /^[0-9a-f]{128}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const KEY_CLAIM = /^key:([0-9a-f]{64})$/;
/** DACS-1 registered claim schemes; the historical generic `cci:` is refused. */
const REGISTERED_SCHEMES: ReadonlySet<string> = new Set(["key", "did", "cci-web2", "cci-xm", "domain", "lei"]);

const hasOwn = (value: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** SIG-6: unpadded Base64URL that round-trips byte-exactly. */
export function decodeCanonicalBase64Url(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0 || !BASE64URL.test(value)) return null;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? new Uint8Array(bytes) : null;
}

export function encodeCanonicalBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** CF-3: the identity part of a claim, ignoring advisory `?qualifier` suffixes. */
export function canonicalIdentity(claim: string): string {
  const q = claim.indexOf("?");
  return q === -1 ? claim : claim.slice(0, q);
}

function claimScheme(claim: string): string | null {
  const colon = claim.indexOf(":");
  return colon <= 0 ? null : claim.slice(0, colon);
}

/** Default resolver: `key:<raw ed25519 hex>` and canonical Demos agent claims. */
export function defaultMemberKeyResolver(claim: string): MemberKeyResolution {
  const identity = canonicalIdentity(claim);
  const keyClaim = KEY_CLAIM.exec(identity);
  if (keyClaim !== null) {
    return { status: "resolved", algorithm: "ed25519", publicKey: Buffer.from(keyClaim[1]!, "hex") };
  }
  const demos = canonicalDemosAgentPublicKey(identity);
  if (demos !== null && demos.length === 32) {
    return { status: "resolved", algorithm: "ed25519", publicKey: demos };
  }
  return { status: "unresolved" };
}

/**
 * Resolver for the historical `cci:<raw ed25519 hex>` claims carried by the
 * frozen Demos wire. Only `importLegacyChannelMessage` should be given this;
 * a current reader never accepts the generic `cci:` scheme.
 */
export function legacyMemberKeyResolver(claim: string): MemberKeyResolution {
  const legacy = LEGACY_CCI_CLAIM.exec(canonicalIdentity(claim));
  if (legacy !== null) {
    return { status: "resolved", algorithm: "ed25519", publicKey: Buffer.from(legacy[1]!, "hex") };
  }
  return defaultMemberKeyResolver(claim);
}

/** Build a member authority from an explicit claim → raw Ed25519 key table. */
export function staticMemberAuthority(
  table: ReadonlyMap<string, Uint8Array>,
): ChannelMemberAuthority {
  return {
    // Live view: peers admitted after construction (tester registrations) are members too.
    get members() { return [...table.keys()]; },
    resolve: (claim) => {
      const key = table.get(canonicalIdentity(claim));
      return key === undefined
        ? { status: "unresolved" }
        : { status: "resolved", algorithm: "ed25519", publicKey: key };
    },
  };
}

function messageHashHex(unsigned: Record<string, unknown>): string {
  return sha256Hex(canonicalize(unsigned));
}

export function canonicalSignedBytes(messageHash: string): Uint8Array {
  return Buffer.from(`${CANONICAL_DOMAIN}${messageHash}`, "utf8");
}

export function legacySignedBytes(messageHashBytes: Uint8Array): Uint8Array {
  return Buffer.concat([Buffer.from(LEGACY_DOMAIN, "utf8"), Buffer.from(messageHashBytes)]);
}

export function provisionalSignedBytes(envelopeHash: string): Uint8Array {
  return Buffer.from(`${PROVISIONAL_DOMAIN}${envelopeHash}`, "utf8");
}

/* ----------------------------- secp256k1 helpers --------------------------- */

const SECP256K1_P = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const SECP256K1_SPKI_PREFIX = Buffer.from("3056301006072a8648ce3d020106052b8104000a034200", "hex");

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/** Decompress a SEC1 compressed secp256k1 point into a Node KeyObject. */
function secp256k1PublicKey(compressed: Uint8Array): KeyObject | null {
  if (compressed.length !== 33 || (compressed[0] !== 2 && compressed[0] !== 3)) return null;
  const x = BigInt(`0x${Buffer.from(compressed.subarray(1)).toString("hex")}`);
  if (x >= SECP256K1_P) return null;
  const rhs = (modPow(x, 3n, SECP256K1_P) + 7n) % SECP256K1_P;
  let y = modPow(rhs, (SECP256K1_P + 1n) / 4n, SECP256K1_P);
  if ((y * y) % SECP256K1_P !== rhs) return null;
  if ((y & 1n) !== BigInt(compressed[0]! & 1)) y = SECP256K1_P - y;
  const point = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(x.toString(16).padStart(64, "0"), "hex"),
    Buffer.from(y.toString(16).padStart(64, "0"), "hex"),
  ]);
  try {
    return createPublicKey({ key: Buffer.concat([SECP256K1_SPKI_PREFIX, point]), format: "der", type: "spki" });
  } catch {
    return null;
  }
}

/** Strict DER ECDSA signature with low-S; returns null when not canonical. */
function parseCanonicalDerSignature(der: Uint8Array): { r: bigint; s: bigint } | null {
  const b = Buffer.from(der);
  if (b.length < 8 || b[0] !== 0x30 || b[1] !== b.length - 2) return null;
  let offset = 2;
  const readInt = (): bigint | null => {
    if (b[offset] !== 0x02) return null;
    const len = b[offset + 1]!;
    const start = offset + 2;
    const end = start + len;
    if (len === 0 || end > b.length) return null;
    const bytes = b.subarray(start, end);
    if (bytes[0]! & 0x80) return null; // negative
    if (len > 1 && bytes[0] === 0 && !(bytes[1]! & 0x80)) return null; // non-minimal
    offset = end;
    return BigInt(`0x${bytes.toString("hex")}`);
  };
  const r = readInt();
  if (r === null) return null;
  const s = readInt();
  if (s === null || offset !== b.length) return null;
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s >= SECP256K1_N) return null;
  if (s > SECP256K1_N / 2n) return null; // low-S
  return { r, s };
}

function verifyEcdsaSecp256k1(signedBytes: Uint8Array, signature: Uint8Array, compressedKey: Uint8Array): VerificationDecision {
  const key = secp256k1PublicKey(compressedKey);
  if (key === null) return "indeterminate";
  if (parseCanonicalDerSignature(signature) === null) return "fail";
  try {
    return nodeVerify("sha256", signedBytes, { key, dsaEncoding: "der" }, signature) ? "pass" : "fail";
  } catch {
    return "fail";
  }
}

/* ------------------------------ validation --------------------------------- */

function validateSignatureEnvelope(
  value: unknown,
): { ok: true; signature: ChannelMessageSignatureV1 } | { ok: false; reason: string } {
  if (!isRecord(value)) return { ok: false, reason: "signature envelope is not an object" };
  const keys = Object.keys(value);
  const expected = ["signatureVersion", "signer", "algorithm", "value"];
  if (keys.length !== expected.length || !expected.every((key) => hasOwn(value, key))) {
    return { ok: false, reason: "signature envelope has an unexpected member set" };
  }
  if (value["signatureVersion"] !== "1") {
    return { ok: false, reason: "unknown signature envelope version" };
  }
  // A signer that does not parse under the current registered grammar is
  // malformed input (`error`); only a well-formed signer naming another party
  // reaches the CH-7 comparison that yields an attributable `fail`.
  if (typeof value["signer"] !== "string" || value["signer"].length === 0) {
    return { ok: false, reason: "signature signer is malformed" };
  }
  const signerScheme = claimScheme(canonicalIdentity(value["signer"]));
  if (signerScheme === null || !REGISTERED_SCHEMES.has(signerScheme)) {
    return { ok: false, reason: "signature signer scheme is not registered" };
  }
  if (!CHANNEL_SIGNATURE_ALGORITHMS.includes(value["algorithm"] as ChannelSignatureAlgorithm)) {
    return { ok: false, reason: "unknown signature algorithm" };
  }
  if (decodeCanonicalBase64Url(value["value"]) === null) {
    return { ok: false, reason: "signature value is not canonical unpadded Base64URL" };
  }
  return { ok: true, signature: value as unknown as ChannelMessageSignatureV1 };
}

const LEGACY_CCI_CLAIM = /^cci:([0-9a-f]{64})$/;
const LEGACY_DID_CLAIM = /^did:[a-z0-9]+:[A-Za-z0-9._-]+$/;

/**
 * CH-10 frozen historical ClaimReference grammar, closed to exactly the two
 * spellings the archived corpus carries (the Standard reference reader's
 * `parse_historical_claim_ref`): `cci:<64 lowercase hex>` and a pre-profile
 * `did:<method>:<id>`; whole value lowercase, no `?` qualifier. Only
 * `legacy-import` may use it; every other spelling, registered or not, rejects.
 */
function isHistoricalClaim(value: string): boolean {
  if (value !== value.toLowerCase() || value.includes("?")) return false;
  return LEGACY_CCI_CLAIM.test(value) || LEGACY_DID_CLAIM.test(value);
}

function validateCommonMembers(value: Record<string, unknown>, arm: "current-read" | "legacy-import" = "current-read"): string | null {
  if (typeof value["channelId"] !== "string" || value["channelId"].length === 0) return "channelId is malformed";
  if (!isPositiveInteger(value["sequence"])) return "sequence is malformed";
  if (typeof value["sender"] !== "string" || value["sender"].length === 0) return "sender is malformed";
  if (arm === "legacy-import") {
    if (!isHistoricalClaim(value["sender"])) return "sender is outside the frozen historical registry";
  } else {
    const scheme = claimScheme(canonicalIdentity(value["sender"]));
    if (scheme === null || !REGISTERED_SCHEMES.has(scheme)) return "sender claim scheme is not registered";
  }
  if (!isNonNegativeInteger(value["sentAt"])) return "sentAt is malformed";
  if (!CHANNEL_MESSAGE_TYPES.includes(value["type"] as never)) return "type is malformed";
  if (!hasOwn(value, "body")) return "body is missing";
  if (hasOwn(value, "refs")) {
    const refs = value["refs"];
    if (!isRecord(refs)) return "refs must be an object when present";
    if (Object.keys(refs).some((key) => key !== "repliesTo")) return "refs has an unexpected member";
    if (hasOwn(refs, "repliesTo") && !isPositiveInteger(refs["repliesTo"])) return "repliesTo must be a positive integer";
  }
  if (!hasOwn(value, "signature")) return "signature is missing";
  return null;
}

/** Structural validation of a current-read message (selection rule 1, CH-7). */
function validateCanonicalStructure(
  value: unknown,
): { ok: true; message: CanonicalChannelMessage } | { ok: false; reason: string } {
  if (!isRecord(value)) return { ok: false, reason: "message is not an object" };
  if (!hasOwn(value, "canonicalChannelMessageVersion")) {
    return { ok: false, reason: "current-read requires canonicalChannelMessageVersion" };
  }
  if (value["canonicalChannelMessageVersion"] !== "1") {
    return { ok: false, reason: "unknown canonical channel message version" };
  }
  const common = validateCommonMembers(value);
  if (common !== null) return { ok: false, reason: common };
  const envelope = validateSignatureEnvelope(value["signature"]);
  if (!envelope.ok) return envelope;
  return { ok: true, message: value as unknown as CanonicalChannelMessage };
}

function validateContext(ctx: unknown): { ok: true; ctx: ChannelReadContext } | { ok: false; reason: string } {
  if (!isRecord(ctx)) return { ok: false, reason: "read context is not an object" };
  const keys = Object.keys(ctx);
  const expected = ["sessionChannelId", "lastSequence", "priorChannelIds"];
  if (keys.length !== expected.length || !expected.every((key) => hasOwn(ctx, key))) {
    return { ok: false, reason: "read context carries unexpected members; membership comes only from verifier-owned authority" };
  }
  if (typeof ctx["sessionChannelId"] !== "string" || ctx["sessionChannelId"].length === 0) {
    return { ok: false, reason: "sessionChannelId is malformed" };
  }
  if (!isNonNegativeInteger(ctx["lastSequence"])) return { ok: false, reason: "lastSequence is malformed" };
  const prior = ctx["priorChannelIds"];
  if (!Array.isArray(prior) || !prior.every((id) => typeof id === "string")) {
    return { ok: false, reason: "priorChannelIds is malformed" };
  }
  return { ok: true, ctx: ctx as unknown as ChannelReadContext };
}

type ProfileCheck =
  | { ok: true; members: readonly string[] }
  | { ok: false; decision: Exclude<VerificationDecision, "pass">; reason: string };

function checkProfile(profile: unknown, expected: ExpectedProfile, sessionChannelId: string, roster: readonly string[]): ProfileCheck {
  if (profile === undefined || profile === null) {
    return { ok: false, decision: "indeterminate", reason: "verifier-owned profile authority is unavailable" };
  }
  if (!isRecord(profile)) return { ok: false, decision: "error", reason: "profile authority is malformed" };
  if (profile["authenticated"] !== true) {
    return { ok: false, decision: "error", reason: "profile authority is not authenticated" };
  }
  const versions = profile["moduleVersions"];
  if (!isRecord(versions)) return { ok: false, decision: "error", reason: "profile module tuple is malformed" };
  const expectedModules = Object.keys(expected.moduleVersions);
  const actualModules = Object.keys(versions);
  if (actualModules.length !== expectedModules.length || !expectedModules.every((m) => hasOwn(versions, m))) {
    return { ok: false, decision: "error", reason: "profile module tuple is partial" };
  }
  const participants = profile["participantIdentities"];
  if (!Array.isArray(participants) || participants.length === 0 || !participants.every((p) => typeof p === "string" && p.length > 0)) {
    return { ok: false, decision: "error", reason: "participant identities are malformed" };
  }
  const identities = (participants as string[]).map(canonicalIdentity);
  if (new Set(identities).size !== identities.length) {
    return { ok: false, decision: "error", reason: "participant identities are not duplicate-free" };
  }
  if (typeof profile["sessionId"] !== "string" || profile["sessionId"] !== sessionChannelId) {
    return { ok: false, decision: "fail", reason: "profile authority is bound to another session" };
  }
  if (profile["releasePin"] !== expected.releasePin) {
    return { ok: false, decision: "fail", reason: "profile authority names a different release pin" };
  }
  if (expectedModules.some((m) => versions[m] !== expected.moduleVersions[m])) {
    return { ok: false, decision: "fail", reason: "profile module versions differ from the expected tuple" };
  }
  const rosterIdentities = roster.map(canonicalIdentity);
  if (new Set(rosterIdentities).size !== rosterIdentities.length) {
    return { ok: false, decision: "error", reason: "verifier roster is not duplicate-free" };
  }
  const rosterSet = new Set(rosterIdentities);
  if (identities.length !== rosterSet.size || !identities.every((id) => rosterSet.has(id))) {
    return { ok: false, decision: "fail", reason: "profile authority does not bind the exact authenticated participants" };
  }
  return { ok: true, members: identities };
}

function withoutSignature(message: Record<string, unknown>): Record<string, unknown> {
  const unsigned: Record<string, unknown> = {};
  for (const key of Object.keys(message)) {
    if (key !== "signature") unsigned[key] = message[key];
  }
  return unsigned;
}

function countMember(members: readonly string[], identity: string): number {
  return members.filter((member) => canonicalIdentity(member) === identity).length;
}

/* --------------------------------- producer -------------------------------- */

/**
 * Sign a canonical message (CH-7/CH-8). The unsigned input must already carry
 * the discriminator; every member it carries is retained and signed.
 */
export async function signCanonicalChannelMessage(
  unsigned: Readonly<UnsignedCanonicalChannelMessage>,
  signer: ChannelSigner,
): Promise<CanonicalChannelMessage> {
  if (unsigned.canonicalChannelMessageVersion !== "1") {
    throw new Error("canonical channel message requires canonicalChannelMessageVersion \"1\"");
  }
  if (canonicalIdentity(unsigned.sender) !== canonicalIdentity(signer.claim)) {
    throw new Error("signature.signer must identify the sender");
  }
  const hash = messageHashHex(unsigned as unknown as Record<string, unknown>);
  const value = encodeCanonicalBase64Url(await signBytes(signer, canonicalSignedBytes(hash)));
  return {
    ...(unsigned as CanonicalChannelMessage),
    signature: { signatureVersion: "1", signer: signer.claim, algorithm: "ed25519", value },
  };
}

/* ---------------------------------- readers -------------------------------- */

export interface CanonicalReadResult {
  decision: VerificationDecision;
  reason?: string;
  message?: CanonicalChannelMessage;
  messageHash?: string;
}

async function verifyMemberSignature(
  sender: string,
  declared: ChannelSignatureAlgorithm,
  signature: Uint8Array,
  signedBytes: Uint8Array,
  members: readonly string[],
  resolve: MemberKeyResolver,
): Promise<{ decision: VerificationDecision; reason?: string }> {
  const identity = canonicalIdentity(sender);
  const occurrences = countMember(members, identity);
  if (occurrences === 0) return { decision: "fail", reason: "sender is not a channel member" };
  if (occurrences > 1) return { decision: "error", reason: "member set is not duplicate-free" };
  const resolved = await resolve(identity);
  if (resolved.status === "unresolved") {
    return { decision: "indeterminate", reason: "member key authority is unavailable" };
  }
  if (resolved.algorithm !== declared) {
    return { decision: "fail", reason: "declared algorithm does not match the member key" };
  }
  switch (resolved.algorithm) {
    case "ed25519": {
      if (signature.length !== 64) return { decision: "fail", reason: "signature value is not 64 bytes" };
      return ed25519Verify(signedBytes, signature, publicKeyFromRaw(resolved.publicKey))
        ? { decision: "pass" }
        : { decision: "fail", reason: "signature does not verify" };
    }
    case "ecdsa-secp256k1": {
      const decision = verifyEcdsaSecp256k1(signedBytes, signature, resolved.publicKey);
      return decision === "pass" ? { decision } : { decision, reason: "ECDSA signature does not verify canonically" };
    }
    case "sr1-aggregate":
      return { decision: "indeterminate", reason: "sr1-aggregate verification is not implemented" };
  }
}

/**
 * `current-read` of a canonical message: context and profile authority first,
 * then structural selection, CH-6 replay gates, CH-7 membership and key
 * binding, then CH-8 signature verification. Never falls back to the
 * historical arm.
 */
export async function readCanonicalChannelMessage(
  value: unknown,
  ctx: unknown,
  authority: CanonicalReadAuthority,
): Promise<CanonicalReadResult> {
  const context = validateContext(ctx);
  if (!context.ok) return { decision: "error", reason: context.reason };
  const profile = checkProfile(authority.profile, authority.expectedProfile, context.ctx.sessionChannelId, authority.members);
  if (!profile.ok) return { decision: profile.decision, reason: profile.reason };

  const structural = validateCanonicalStructure(value);
  if (!structural.ok) return { decision: "error", reason: structural.reason };
  const message = structural.message;

  // CH-6: channel binding and monotonic sequence.
  if (message.channelId !== context.ctx.sessionChannelId) {
    return { decision: "fail", reason: "message channelId does not match the session channel" };
  }
  if (context.ctx.priorChannelIds.includes(message.channelId)) {
    return { decision: "fail", reason: "session channelId was used by a prior session" };
  }
  if (message.sequence <= context.ctx.lastSequence) {
    return { decision: "fail", reason: "sequence is not strictly increasing" };
  }

  // CH-7: signer identifies the sender (CF-3 ignores advisory qualifiers).
  if (canonicalIdentity(message.signature.signer) !== canonicalIdentity(message.sender)) {
    return { decision: "fail", reason: "signature.signer does not identify the sender" };
  }
  const signature = decodeCanonicalBase64Url(message.signature.value);
  if (signature === null) return { decision: "error", reason: "signature value is malformed" };

  const unsigned = withoutSignature(message as unknown as Record<string, unknown>);
  const hash = messageHashHex(unsigned);
  const verified = await verifyMemberSignature(
    message.sender, message.signature.algorithm, signature, canonicalSignedBytes(hash),
    profile.members, authority.resolve,
  );
  return verified.decision === "pass"
    ? { decision: "pass", message, messageHash: hash }
    : { decision: verified.decision, reason: verified.reason };
}

export interface LegacyChannelMessage {
  channelId: string;
  sequence: number;
  sender: string;
  sentAt: number;
  type: typeof CHANNEL_MESSAGE_TYPES[number];
  body: unknown;
  refs?: { repliesTo?: number };
  signature: string;
}

/**
 * Explicit `legacy-import` of the frozen historical wire (CH-10): no
 * discriminator, bare 128-character lowercase-hex signature, raw-digest
 * framing under `dacs-channelmsg:v1:`. Read/import only. A current reader
 * MUST NOT reach this through shape detection.
 */
export async function importLegacyChannelMessage(
  value: unknown,
  ctx: unknown,
  authority: CanonicalReadAuthority,
): Promise<CanonicalReadResult & { message?: never; legacy?: LegacyChannelMessage }> {
  const context = validateContext(ctx);
  if (!context.ok) return { decision: "error", reason: context.reason };
  // The corrective profile boundary is legacyImportExempt; the historical arm
  // binds only to the verifier's own roster.
  const roster = authority.members.map(canonicalIdentity);
  if (new Set(roster).size !== roster.length) return { decision: "error", reason: "verifier roster is not duplicate-free" };
  if (!isRecord(value)) return { decision: "error", reason: "message is not an object" };
  if (hasOwn(value, "canonicalChannelMessageVersion")) {
    return { decision: "error", reason: "legacy-import refuses a discriminated current message" };
  }
  const allowed = ["channelId", "sequence", "sender", "sentAt", "type", "body", "refs", "signature"];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    return { decision: "error", reason: "historical message has an unexpected member" };
  }
  const common = validateCommonMembers(value, "legacy-import");
  if (common !== null) return { decision: "error", reason: common };
  if (typeof value["signature"] !== "string" || !HEX128_LOWER.test(value["signature"])) {
    return { decision: "error", reason: "historical signature must be exactly 128 lowercase hex characters" };
  }
  const message = value as unknown as LegacyChannelMessage;
  if (message.channelId !== context.ctx.sessionChannelId) {
    return { decision: "fail", reason: "message channelId does not match the session channel" };
  }
  if (context.ctx.priorChannelIds.includes(message.channelId)) {
    return { decision: "fail", reason: "session channelId was used by a prior session" };
  }
  if (message.sequence <= context.ctx.lastSequence) {
    return { decision: "fail", reason: "sequence is not strictly increasing" };
  }
  const digest = createHash("sha256").update(canonicalize(withoutSignature(value)), "utf8").digest();
  const verified = await verifyMemberSignature(
    message.sender, "ed25519", Buffer.from(message.signature, "hex"), legacySignedBytes(digest),
    roster, authority.resolve,
  );
  return verified.decision === "pass"
    ? { decision: "pass", legacy: message, messageHash: digest.toString("hex") }
    : { decision: verified.decision, reason: verified.reason };
}

/* -------------------------------------------------------------------------- */
/* Adapter for the @kynesyslabs/dacs lifecycle seams                           */
/* -------------------------------------------------------------------------- */

export interface ChannelSignatureAdapterOptions {
  /**
   * Requested profile. On an SDK that frames CH-8 bytes itself (dacs-sdk#330
   * and later) the adapter always signs and verifies the canonical profile,
   * whatever is requested, and logs it. On an older SDK the canonical profile
   * throws and `provisional-rfq-sig:v0` is the only option.
   */
  profile: ChannelSignatureProfileId;
  signer: ChannelSigner;
  authority: ChannelMemberAuthority;
  /** Receives one structured line per sign/verify; wire to the role's logger. */
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface ChannelSignatureAdapter {
  readonly profileId: ChannelSignatureProfileId;
  signChannelMessage: (
    input: Readonly<ChannelMessageSigningInput<RfqTurnBody>>,
  ) => Promise<ChannelMessageSignatureV1>;
  verifyChannelMessage: (
    input: Readonly<ChannelMessageSignatureVerificationInput<RfqTurnBody, ChannelMessageSignatureV1>>,
  ) => Promise<VerificationDecision>;
}

/**
 * Build the `signChannelMessage` / `verifyChannelMessage` pair for
 * `createDurableRfqLifecycleClient`. The SDK hands us its seven-field unsigned
 * envelope and its lowercase-hex SHA-256 of the JCS bytes; we never rebuild
 * either, so the verifier covers exactly what the admission layer admitted.
 */
/** An SDK at or after dacs-sdk#330 supplies the CH-8 bytes and the operation itself. */
function sdkSuppliesFraming(input: object): boolean {
  const candidate = input as { signedBytes?: unknown; operation?: unknown };
  return candidate.signedBytes instanceof Uint8Array && typeof candidate.operation === "string";
}

export function createChannelSignatureAdapter(
  options: ChannelSignatureAdapterOptions,
): ChannelSignatureAdapter {
  const profileId = options.profile;
  const log = options.log ?? (() => {});

  return {
    profileId,
    async signChannelMessage(input) {
      if (!HEX64.test(input.envelopeHash)) throw new Error("envelope hash is malformed");
      if (input.unsignedEnvelope.sender !== options.signer.claim) {
        throw new Error("signer claim does not match the envelope sender");
      }
      const canonical = sdkSuppliesFraming(input);
      if (profileId === CANONICAL_PROFILE_ID && !canonical) {
        throw new Error(
          "the installed @kynesyslabs/dacs predates dacs-sdk#330 and cannot carry " +
            "CanonicalChannelMessage; select provisional-rfq-sig:v0",
        );
      }
      if (canonical && String(input.operation) !== "current-read") {
        throw new Error(`refusing to produce a ${String(input.operation)} channel message`);
      }
      // Canonical: sign exactly the CH-8 bytes the SDK framed over the
      // discriminated envelope. Provisional (older SDK): our own domain.
      const bytes = canonical ? input.signedBytes : provisionalSignedBytes(input.envelopeHash);
      const value = encodeCanonicalBase64Url(await signBytes(options.signer, bytes));
      log({
        event: "channel-message-signed",
        profile: canonical ? CANONICAL_PROFILE_ID : PROVISIONAL_PROFILE_ID,
        channelId: input.unsignedEnvelope.channelId,
        sequence: input.unsignedEnvelope.sequence,
        envelopeHash: input.envelopeHash,
      });
      return { signatureVersion: "1", signer: options.signer.claim, algorithm: "ed25519", value };
    },
    async verifyChannelMessage(input) {
      const decision = sdkSuppliesFraming(input)
        ? await verifyCanonicalSeam(input, options.authority)
        : await verifyProvisional(input, options.authority);
      log({
        event: "channel-message-verified",
        profile: profileId,
        channelId: input.message.channelId,
        sequence: input.message.sequence,
        sender: input.message.sender,
        decision: decision.decision,
        ...(decision.reason === undefined ? {} : { reason: decision.reason }),
      });
      return decision.decision;
    },
  };
}

/** Verification on an SDK that frames CH-8 bytes itself (dacs-sdk#330 and later). */
async function verifyCanonicalSeam(
  input: Readonly<ChannelMessageSignatureVerificationInput<RfqTurnBody, unknown>>,
  authority: ChannelMemberAuthority,
): Promise<{ decision: VerificationDecision; reason?: string }> {
  const operation = String(input.operation);
  if (operation !== "current-read") return { decision: "error", reason: `unsupported operation ${operation}` };
  const envelope = validateSignatureEnvelope(input.message.signature);
  if (!envelope.ok) return { decision: "error", reason: envelope.reason };
  const signature = envelope.signature;
  if (canonicalIdentity(signature.signer) !== canonicalIdentity(input.message.sender)) {
    return { decision: "fail", reason: "signature.signer does not identify the sender" };
  }
  const bytes = decodeCanonicalBase64Url(signature.value);
  if (bytes === null) return { decision: "error", reason: "signature value is malformed" };
  const expected = canonicalSignedBytes(input.envelopeHash);
  if (Buffer.compare(Buffer.from(input.signedBytes), Buffer.from(expected)) !== 0) {
    return { decision: "error", reason: "SDK signed bytes are not the CH-8 framing of the envelope hash" };
  }
  // CH-7: on current-read the SDK has already resolved the sender to a CH-1
  // member and hands it over as `member`; the key is resolved for that
  // member, never for the self-declared sender or `signature.signer`.
  const member = (input as { member?: unknown }).member;
  const subject = typeof member === "string" ? member : input.message.sender;
  if (typeof member === "string" && canonicalIdentity(member) !== canonicalIdentity(input.message.sender)) {
    return { decision: "fail", reason: "resolved member does not identify the sender" };
  }
  return verifyMemberSignature(
    subject, signature.algorithm, bytes, expected, authority.members, authority.resolve,
  );
}

async function verifyProvisional(
  input: Readonly<ChannelMessageSignatureVerificationInput<RfqTurnBody, unknown>>,
  authority: ChannelMemberAuthority,
): Promise<{ decision: VerificationDecision; reason?: string }> {
  if (!HEX64.test(input.envelopeHash)) return { decision: "error", reason: "envelope hash is malformed" };
  const envelope = validateSignatureEnvelope(input.message.signature);
  if (!envelope.ok) return { decision: "error", reason: envelope.reason };
  const signature = envelope.signature;
  if (signature.signer !== input.message.sender) {
    return { decision: "fail", reason: "signature.signer does not equal sender" };
  }
  const bytes = decodeCanonicalBase64Url(signature.value);
  if (bytes === null) return { decision: "error", reason: "signature value is malformed" };
  // Defence in depth: the SDK already hashed the admitted envelope; confirm the
  // hash we are about to trust is the hash of the envelope we were given.
  const recomputed = sha256Hex(canonicalize(input.unsignedEnvelope as unknown as Record<string, unknown>));
  if (recomputed !== input.envelopeHash) {
    return { decision: "error", reason: "envelope hash does not match the unsigned envelope" };
  }
  return verifyMemberSignature(
    input.message.sender, signature.algorithm, bytes, provisionalSignedBytes(input.envelopeHash),
    authority.members, authority.resolve,
  );
}

/** Stable fingerprint of a profile selection for config and log correlation. */
export function profileFingerprint(profile: ChannelSignatureProfileId): string {
  const domain = profile === CANONICAL_PROFILE_ID ? CANONICAL_DOMAIN : PROVISIONAL_DOMAIN;
  return createHash("sha256").update(`${profile}|${domain}`, "utf8").digest("hex").slice(0, 16);
}
