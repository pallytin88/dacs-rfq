/**
 * Step 6 commitment leg: take the co-signed agreement the lifecycle client
 * produced and anchor its hash on Demos with finality via the SDK's
 * `commitRfqAgreement`. Only the `FinalityCommitmentRecord` (hash, parties,
 * pattern, timestamps, signature) goes on chain; the agreement body does not.
 */

import { canonicalize, contentHash, sha256Hex } from "@kynesyslabs/dacs/canonical";
import type { AgreementArtifact, AnchorReceipt, FinalityCommitmentRecord } from "@kynesyslabs/dacs/artifacts";
import type { BuildComponentSignatureOptions } from "@kynesyslabs/dacs/artifacts";
import { ed25519Verify, publicKeyFromRaw } from "@kynesyslabs/dacs/crypto";
import { commitRfqAgreement, finalityCommitmentAddress } from "@kynesyslabs/dacs/negotiate";
import type {
  AnchoredFinalityCommitment,
  CommitmentSignatureVerifier,
  DurableRfqLifecycleRecord,
  FinalityCommitmentProvider,
  FinalizedAgreementCommitment,
  VerifiedListingInput,
} from "@kynesyslabs/dacs/negotiate";
import type { MemberKeyResolver } from "./channelSignature.js";

export interface CommitNegotiatedAgreementOptions<TSignature> {
  record: Readonly<DurableRfqLifecycleRecord<TSignature>>;
  verifiedListing: VerifiedListingInput;
  /** The buyer orchestrates the commitment for the showcase. */
  orchestrator: string;
  commitmentSigner: BuildComponentSignatureOptions;
  provider: FinalityCommitmentProvider;
  verifySignature: CommitmentSignatureVerifier;
  nowMs?: () => number;
}

export type CommitOutcome =
  | { status: "committed"; commitment: FinalizedAgreementCommitment }
  | { status: "not-ready"; reason: string }
  | { status: "failed"; reason: string };

/** Build a commitment signature verifier from a member key resolver (Ed25519 only). */
export function createCommitmentSignatureVerifier(resolve: MemberKeyResolver): CommitmentSignatureVerifier {
  return async (input) => {
    const resolved = await resolve(input.signer);
    if (resolved.status === "unresolved") return "indeterminate";
    if (resolved.algorithm !== "ed25519" || input.algorithm !== "ed25519") return "indeterminate";
    try {
      const signature = Buffer.from(input.value, "base64url");
      if (signature.toString("base64url") !== input.value || signature.length !== 64) return "invalid";
      return ed25519Verify(input.signedBytes, signature, publicKeyFromRaw(resolved.publicKey)) ? "valid" : "invalid";
    } catch {
      return "error";
    }
  };
}

export async function commitNegotiatedAgreement<TSignature>(
  options: CommitNegotiatedAgreementOptions<TSignature>,
): Promise<CommitOutcome> {
  const record = options.record;
  const finalized = record.agreement?.finalized;
  if (record.session.status !== "accepted") return { status: "not-ready", reason: `session is ${record.session.status}` };
  if (finalized === undefined) return { status: "not-ready", reason: "agreement is not yet co-signed" };
  // The lifecycle record is deeply frozen; the SDK's commitment input must be
  // an owned, writable JSON value, so clone before handing it over.
  const agreement = structuredClone(finalized) as AgreementArtifact;
  const rfqSession = structuredClone(record.session);
  const verifiedListing = structuredClone(options.verifiedListing);
  const buyerParty = agreement.parties.find((p) => p.role === "buyer");
  const sellerParty = agreement.parties.find((p) => p.role === "seller");
  if (buyerParty === undefined || sellerParty === undefined) return { status: "failed", reason: "agreement parties are incomplete" };
  try {
    const commitment = await commitRfqAgreement(
      {
        agreement,
        verifiedListing,
        rfqSession,
        session: {
          jobId: agreement.jobId,
          listingRef: { ...agreement.listingRef },
          phaseKind: "commit-agreement",
          orchestrator: options.orchestrator,
          buyer: { primaryClaim: buyerParty.primaryClaim, bundleHash: buyerParty.bundleHash, vetRecordRef: structuredClone(buyerParty.vetRecordRef) },
          seller: { primaryClaim: sellerParty.primaryClaim, bundleHash: sellerParty.bundleHash, vetRecordRef: structuredClone(sellerParty.vetRecordRef) },
        },
        createdAt: (options.nowMs ?? Date.now)(),
        commitmentSigner: options.commitmentSigner,
      },
      options.provider,
      options.verifySignature,
    );
    return { status: "committed", commitment };
  } catch (cause) {
    return { status: "failed", reason: cause instanceof Error ? cause.message : String(cause) };
  }
}

/* ------------------------- in-memory provider (tests) ----------------------- */

export interface InMemoryFinalityProviderOptions {
  writer: string;
  nowMs?: () => number;
  substrate?: string;
}

/** Deterministic local provider: anchors records in a map and fakes finality. */
export function createInMemoryFinalityProvider(options: InMemoryFinalityProviderOptions): FinalityCommitmentProvider & {
  anchored: ReadonlyMap<string, AnchoredFinalityCommitment>;
} {
  const anchored = new Map<string, AnchoredFinalityCommitment>();
  const nowMs = options.nowMs ?? Date.now;
  let height = 100;
  return {
    anchored,
    async resolve(logicalAddress) {
      const existing = anchored.get(logicalAddress);
      return existing === undefined ? { disposition: "absent" } : { disposition: "present", anchored: structuredClone(existing) };
    },
    async submit(logicalAddress, record) {
      const existing = anchored.get(logicalAddress);
      if (existing !== undefined) {
        if (canonicalize(existing.record as Record<string, unknown>) !== canonicalize(record as unknown as Record<string, unknown>)) {
          throw new Error("logical address already bound to a different record");
        }
        return structuredClone(existing);
      }
      const nativeAddress = `stor:${contentHash(record as unknown as Record<string, unknown>).slice(0, 32)}`;
      const now = nowMs();
      height += 1;
      const receipt: AnchorReceipt = {
        receiptVersion: "1",
        substrate: options.substrate ?? "demos:local",
        finalityProfile: "demos-bft-final",
        logicalAddress,
        nativeAddress,
        contentHash: contentHash(record as unknown as Record<string, unknown>),
        transactionRef: { kind: "demos", value: `tx-${height}` },
        writer: options.writer,
        nonce: String(height),
        state: "finalized",
        observationDisposition: "established",
        observedAt: now,
        blockRef: { id: `block-${height}`, height: String(height), timestamp: now - 1 },
        evidence: { kind: "demos-finality-proof", value: `proof-${height}` },
      };
      const entry: AnchoredFinalityCommitment = {
        record,
        nativeAddress,
        anchorTxRef: { kind: "storage-program", address: nativeAddress, writeTxHash: "a".repeat(64) },
        anchorReceipt: receipt,
      };
      anchored.set(logicalAddress, entry);
      return structuredClone(entry);
    },
    async verifyAnchorReceipt(candidate) {
      const existing = anchored.get(candidate.anchorReceipt.logicalAddress);
      if (existing === undefined) return "indeterminate";
      return canonicalize(existing.anchorReceipt as unknown as Record<string, unknown>) ===
        canonicalize(candidate.anchorReceipt as unknown as Record<string, unknown>) &&
        candidate.anchorReceipt.contentHash === contentHash(candidate.record as Record<string, unknown>)
        ? "valid" : "invalid";
    },
  };
}

/* ------------------------- Demos provider (dacs-node) ----------------------- */

/** The subset of dacs-node's `DacsDemosAdapterV1` the commitment needs. */
export interface DemosCommitmentAdapter {
  anchorWriteOnce(
    name: string,
    value: object,
    options?: { metadata?: { logicalAddress: string; contentHash: string; envelopeHash: string } },
  ): Promise<{ address: string; txRef?: string }>;
  readAnchor(address: string): Promise<Record<string, unknown> | null>;
  resolveAnchorByName(name: string, expectedOwner: string): Promise<
    { status: "present"; address: string } | { status: "absent" } | { status: "indeterminate"; reason: string }
  >;
  resolveDemosAnchorReceipt(input: Readonly<{ logicalAddress: string; nativeAddress: string; contentHash: string; writer: string }>): Promise<AnchorReceipt | null>;
  verifyDemosAnchorReceipt(receipt: Readonly<AnchorReceipt>): Promise<boolean>;
}

export interface DemosFinalityProviderOptions {
  adapter: DemosCommitmentAdapter;
  /** Writer claim (the orchestrator) and its Demos address hex for owner checks. */
  writer: string;
  writerAddressHex: string;
}

/**
 * Finality provider on a live Demos node, mirroring dacs-node's own
 * resolution pattern: write-once at `dacs3:commit:{jobId}`, read back, obtain
 * the authenticated receipt, and verify it independently.
 */
export function createDemosFinalityProvider(options: DemosFinalityProviderOptions): FinalityCommitmentProvider {
  const { adapter } = options;
  async function anchoredAt(logicalAddress: string, nativeAddress: string): Promise<AnchoredFinalityCommitment | { reason: string }> {
    const raw = await adapter.readAnchor(nativeAddress);
    if (raw === null) return { reason: "commitment-native-readback-unavailable" };
    const receipt = await adapter.resolveDemosAnchorReceipt({
      logicalAddress, nativeAddress, contentHash: contentHash(raw), writer: options.writer,
    });
    if (receipt === null) return { reason: "commitment-receipt-unavailable" };
    return {
      record: raw,
      nativeAddress,
      anchorTxRef: { kind: "storage-program", address: nativeAddress, writeTxHash: receipt.transactionRef.value },
      anchorReceipt: receipt,
    };
  }
  return {
    async resolve(logicalAddress) {
      try {
        const resolved = await adapter.resolveAnchorByName(logicalAddress, options.writerAddressHex);
        if (resolved.status === "absent") return { disposition: "absent" };
        if (resolved.status !== "present") return { disposition: "indeterminate", reason: resolved.reason };
        const anchored = await anchoredAt(logicalAddress, resolved.address);
        return "reason" in anchored ? { disposition: "indeterminate", reason: anchored.reason } : { disposition: "present", anchored };
      } catch (cause) {
        return { disposition: "indeterminate", reason: cause instanceof Error ? cause.message : "commitment-resolution-unavailable" };
      }
    },
    async submit(logicalAddress, record: FinalityCommitmentRecord) {
      if (logicalAddress !== finalityCommitmentAddress(record.jobId) || record.signature.signer !== options.writer) {
        throw new Error("commitment submission is not bound to this writer and job");
      }
      // Bind the write to the portable receipt the way `demosAnchorStore` does:
      // the SDK authenticates a receipt either by exact stored-value hash or by
      // this metadata triple carried in the signed transaction. Without it a
      // signed record (whose contentHash strips the signature) never matches.
      const artifact = record as unknown as Record<string, unknown>;
      const metadata = { logicalAddress, contentHash: contentHash(artifact), envelopeHash: sha256Hex(canonicalize(artifact)) };
      const ref = await adapter.anchorWriteOnce(logicalAddress, structuredClone(artifact), { metadata });
      const anchored = await anchoredAt(logicalAddress, ref.address);
      if ("reason" in anchored) throw new Error(anchored.reason);
      return anchored;
    },
    async verifyAnchorReceipt(candidate) {
      if (candidate.anchorReceipt.writer !== options.writer ||
          candidate.anchorReceipt.nativeAddress !== candidate.nativeAddress ||
          candidate.anchorReceipt.contentHash !== contentHash(candidate.record as Record<string, unknown>)) return "invalid";
      try {
        if (await adapter.verifyDemosAnchorReceipt(candidate.anchorReceipt) !== true) return "invalid";
        const readback = await adapter.readAnchor(candidate.nativeAddress);
        return readback !== null && canonicalize(readback) === canonicalize(candidate.record as Record<string, unknown>)
          ? "valid" : "indeterminate";
      } catch {
        return "error";
      }
    },
  };
}
