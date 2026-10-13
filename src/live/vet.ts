/**
 * DACS-2 vet records for the showcase: each party signs a
 * `CompositeVerificationRecord` about the other (empty buyer requirement,
 * overall `pass`) and anchors it at the composite verification address for
 * the job. The `AttestationRef` each side needs for `open()` is derived from
 * the record the *other* side anchored, read back from chain and verified.
 *
 * Exchange order (buyer initiates):
 *   1. buyer signs+anchors vet-of-seller  → sellerVetRef (buyer knows it)
 *   2. buyer announces the session carrying sellerVetRef
 *   3. seller verifies that record on chain, signs+anchors vet-of-buyer, opens
 *   4. buyer reads the seller's record for the buyer from chain, verifies, opens
 */

import { canonicalize, contentHash, sha256Hex } from "@kynesyslabs/dacs/canonical";
import type { AttestationRef, CompositeVerificationRecord, IdentityBundle } from "@kynesyslabs/dacs/artifacts";
import { ARTIFACT_SEPARATORS } from "@kynesyslabs/dacs/artifacts";
import { compositeVerificationAddress } from "@kynesyslabs/dacs";
import { ed25519Verify, publicKeyFromRaw, signedBytes } from "@kynesyslabs/dacs/crypto";
import { identityBundleHash } from "@kynesyslabs/dacs/identity";
import { signBytes } from "../signer.js";
import type { Ed25519Signer } from "../signer.js";
import type { AnchorStore } from "./anchors.js";

export const EMPTY_REQUIREMENT = Object.freeze({ requirementVersion: "1" as const, required: [] as never[] });

export async function signVetRecord(input: {
  jobId: string;
  evaluatedParty: string;
  bundle: Readonly<IdentityBundle>;
  verifier: Ed25519Signer;
  generatedAt: number;
}): Promise<CompositeVerificationRecord> {
  const unsigned = {
    recordVersion: "1" as const,
    jobId: input.jobId,
    evaluatedParty: input.evaluatedParty,
    bundleHash: identityBundleHash(input.bundle),
    requirementHash: sha256Hex(canonicalize(EMPTY_REQUIREMENT)),
    freshness: [],
    supplementary: [],
    dealSpecific: [],
    overallDecision: "pass" as const,
    generatedAt: input.generatedAt,
  };
  const signature = await signBytes(input.verifier, signedBytes(ARTIFACT_SEPARATORS.CompositeVerificationRecord, contentHash(unsigned)));
  return { ...unsigned, signature: { algorithm: "ed25519", signer: input.verifier.claim, value: Buffer.from(signature).toString("base64url") } };
}

export function verifyVetRecord(record: unknown, expected: {
  jobId: string; evaluatedParty: string; bundle: Readonly<IdentityBundle>; verifier: string; verifierPublicKey: Uint8Array;
}): record is CompositeVerificationRecord {
  if (record === null || typeof record !== "object") return false;
  const r = record as CompositeVerificationRecord;
  if (r.recordVersion !== "1" || r.jobId !== expected.jobId || r.evaluatedParty !== expected.evaluatedParty) return false;
  if (r.bundleHash !== identityBundleHash(expected.bundle) || r.overallDecision !== "pass") return false;
  if (r.signature?.algorithm !== "ed25519" || r.signature.signer !== expected.verifier) return false;
  const { signature, ...unsigned } = r;
  try {
    return ed25519Verify(
      signedBytes(ARTIFACT_SEPARATORS.CompositeVerificationRecord, contentHash(unsigned as unknown as Record<string, unknown>)),
      Uint8Array.from(Buffer.from(signature.value, "base64url")),
      publicKeyFromRaw(expected.verifierPublicKey),
    );
  } catch {
    return false;
  }
}

export function vetRefFor(record: Readonly<CompositeVerificationRecord>): AttestationRef {
  return {
    anchor: { kind: "storage-program", locator: compositeVerificationAddress(record.jobId, record.evaluatedParty) },
    contentHash: contentHash(record as unknown as Record<string, unknown>),
    signer: record.signature.signer,
  };
}

/** Sign and anchor our vet of the counterparty; returns the ref the counterparty will use. */
export async function publishVetOf(input: {
  store: AnchorStore;
  verifier: Ed25519Signer;
  jobId: string;
  evaluatedParty: string;
  bundle: Readonly<IdentityBundle>;
  nowMs: number;
}): Promise<{ record: CompositeVerificationRecord; ref: AttestationRef }> {
  const record = await signVetRecord({ jobId: input.jobId, evaluatedParty: input.evaluatedParty, bundle: input.bundle, verifier: input.verifier, generatedAt: input.nowMs });
  const anchored = await input.store.anchorArtifact({
    writer: input.verifier.claim,
    logicalAddress: compositeVerificationAddress(input.jobId, input.evaluatedParty),
    artifact: record as unknown as Record<string, unknown>,
  });
  const ref = vetRefFor(record);
  if (canonicalize(anchored.ref) !== canonicalize(ref)) throw new Error("anchored vet ref mismatch");
  return { record, ref };
}

/**
 * Read the counterparty's vet record about `evaluatedParty` (us) from chain,
 * verify it, and derive the ref. `null` when not yet anchored.
 */
export async function readVetBy(input: {
  store: AnchorStore;
  jobId: string;
  evaluatedParty: string;
  evaluatedBundle: Readonly<IdentityBundle>;
  verifier: string;
  verifierAddressHex: string;
  verifierPublicKey: Uint8Array;
}): Promise<AttestationRef | null | "indeterminate" | "invalid"> {
  const read = await input.store.readOwnedAnchor(compositeVerificationAddress(input.jobId, input.evaluatedParty), input.verifierAddressHex);
  if (read === null) return null;
  if (read === "indeterminate") return "indeterminate";
  const ok = verifyVetRecord(read.value, {
    jobId: input.jobId, evaluatedParty: input.evaluatedParty, bundle: input.evaluatedBundle,
    verifier: input.verifier, verifierPublicKey: input.verifierPublicKey,
  });
  return ok ? vetRefFor(read.value as unknown as CompositeVerificationRecord) : "invalid";
}
