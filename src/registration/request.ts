/**
 * A tester's registration request: its Demos agent claim (which is its
 * Ed25519 key), the X25519 key the credential should be sealed to, a time
 * and a nonce, signed by the claim. Nothing else is needed to admit an agent:
 * DACS-2 vetting happens when it announces a session.
 */

import { canonicalize, sha256Hex } from "@kynesyslabs/dacs/canonical";
import { ed25519Verify, publicKeyFromRaw } from "@kynesyslabs/dacs/crypto";
import { canonicalDemosAgentPublicKey } from "@kynesyslabs/dacs/identity";
import { randomBytes } from "node:crypto";
import { decodeCanonicalBase64Url, encodeCanonicalBase64Url } from "../channelSignature.js";
import { signBytes } from "../signer.js";
import type { Ed25519Signer } from "../signer.js";

export const REGISTRATION_DOMAIN = "colony-rfq-registration:v0:" as const;
export const REGISTRATION_PATH = "/colony-rfq/v0/register" as const;
export const REGISTRATION_MAX_AGE_MS = 300_000;

export interface RegistrationRequest {
  registrationVersion: "1";
  claim: string;
  /** X25519 public key the credential will be sealed to, 64 hex. */
  encryptionPublicKey: string;
  requestedAt: number;
  nonce: string;
  signature: { algorithm: "ed25519"; signer: string; value: string };
}

const HEX64 = /^[0-9a-f]{64}$/;
const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

function signedBytes(unsigned: Readonly<Record<string, unknown>>): Uint8Array {
  return Buffer.from(`${REGISTRATION_DOMAIN}${sha256Hex(canonicalize(unsigned))}`, "utf8");
}

export async function buildRegistrationRequest(signer: Ed25519Signer, encryptionPublicKey: string, nowMs: number): Promise<RegistrationRequest> {
  if (!HEX64.test(encryptionPublicKey)) throw new Error("encryption public key must be 64 lowercase hex");
  const unsigned = { registrationVersion: "1" as const, claim: signer.claim, encryptionPublicKey, requestedAt: nowMs, nonce: randomBytes(16).toString("base64url") };
  const value = encodeCanonicalBase64Url(await signBytes(signer, signedBytes(unsigned)));
  return { ...unsigned, signature: { algorithm: "ed25519", signer: signer.claim, value } };
}

export function verifyRegistrationRequest(value: unknown, nowMs: number): { ok: true; request: RegistrationRequest } | { ok: false; reason: string } {
  if (!isRecord(value)) return { ok: false, reason: "request is not an object" };
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "claim,encryptionPublicKey,nonce,registrationVersion,requestedAt,signature") return { ok: false, reason: "request has an unexpected member set" };
  if (value["registrationVersion"] !== "1") return { ok: false, reason: "unknown registration version" };
  const claim = value["claim"];
  if (typeof claim !== "string") return { ok: false, reason: "claim is malformed" };
  const key = canonicalDemosAgentPublicKey(claim);
  if (key === null) return { ok: false, reason: "claim is not a canonical Demos agent claim" };
  if (typeof value["encryptionPublicKey"] !== "string" || !HEX64.test(value["encryptionPublicKey"])) return { ok: false, reason: "encryption public key is malformed" };
  if (typeof value["nonce"] !== "string" || value["nonce"].length < 16) return { ok: false, reason: "nonce is malformed" };
  const at = value["requestedAt"];
  if (!Number.isSafeInteger(at) || (at as number) > nowMs + 60_000 || (at as number) < nowMs - REGISTRATION_MAX_AGE_MS) return { ok: false, reason: "request time is out of window" };
  const signature = value["signature"];
  if (!isRecord(signature) || signature["algorithm"] !== "ed25519" || signature["signer"] !== claim) return { ok: false, reason: "signature envelope is malformed" };
  const raw = decodeCanonicalBase64Url(signature["value"]);
  if (raw === null || raw.length !== 64) return { ok: false, reason: "signature value is malformed" };
  const { signature: _s, ...unsigned } = value;
  if (!ed25519Verify(signedBytes(unsigned), raw, publicKeyFromRaw(key))) return { ok: false, reason: "signature does not verify against the claim" };
  return { ok: true, request: value as unknown as RegistrationRequest };
}
