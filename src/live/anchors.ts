/**
 * Write-once anchoring of DACS artifacts on Demos, with the portable
 * `AnchorReceipt` derived from the adapter's authenticated write evidence.
 * Mirrors the SDK's funded two-agent run so every record we publish carries
 * the same receipt shape as the fixed-price flow.
 */

import { canonicalize, contentHash, sha256Hex } from "@kynesyslabs/dacs/canonical";
import type { AnchorReceipt, AttestationRef } from "@kynesyslabs/dacs/artifacts";
import { AnchorWaitError, demosWriteEvidenceToAnchorReceipt } from "@kynesyslabs/dacs/substrate";
import type { DemosAdapter } from "@kynesyslabs/dacs/substrate";

export interface AnchoredArtifact {
  ref: AttestationRef;
  receipt: AnchorReceipt;
  nativeAddress: string;
}

export interface AnchorStore {
  /** Write-once by logical name; returns the native address and receipt. */
  anchorArtifact(input: { writer: string; logicalAddress: string; artifact: Record<string, unknown>; refSigner?: string }): Promise<AnchoredArtifact>;
  /** Read a named anchor owned by `ownerAddressHex`; null when authoritatively absent. */
  readOwnedAnchor(logicalAddress: string, ownerAddressHex: string): Promise<{ nativeAddress: string; value: Record<string, unknown> } | null | "indeterminate">;
}

export function demosAnchorStore(adapter: DemosAdapter, log?: (e: Record<string, unknown>) => void): AnchorStore {
  return {
    async anchorArtifact(input) {
      const hash = contentHash(input.artifact);
      const metadata = {
        logicalAddress: input.logicalAddress,
        contentHash: hash,
        envelopeHash: sha256Hex(canonicalize(input.artifact)),
      };
      let anchored: Awaited<ReturnType<DemosAdapter["anchorWriteOnce"]>> | undefined;
      for (let attempt = 1; attempt <= 3; attempt += 1) {
        try {
          anchored = await adapter.anchorWriteOnce(input.logicalAddress, structuredClone(input.artifact), { metadata });
          break;
        } catch (error) {
          if (!(error instanceof AnchorWaitError) || error.receipt.name !== input.logicalAddress || attempt === 3) throw error;
          log?.({ event: "anchor-write-recovery", attempt, code: error.code, logicalAddress: input.logicalAddress });
          await new Promise((resolve) => setTimeout(resolve, 1_000));
        }
      }
      if (anchored === undefined || anchored.demosEvidence === undefined) throw new Error("anchor write produced no evidence");
      const receipt = demosWriteEvidenceToAnchorReceipt({
        logicalAddress: input.logicalAddress,
        contentHash: hash,
        writer: input.writer,
        evidence: anchored.demosEvidence,
      });
      log?.({ event: "anchored", logicalAddress: input.logicalAddress, nativeAddress: anchored.address, txRef: anchored.txRef });
      return {
        ref: { anchor: { kind: "storage-program", locator: input.logicalAddress }, contentHash: hash, signer: input.refSigner ?? input.writer },
        receipt,
        nativeAddress: anchored.address,
      };
    },
    async readOwnedAnchor(logicalAddress, ownerAddressHex) {
      const resolved = await adapter.resolveAnchorByName(logicalAddress, ownerAddressHex);
      if (resolved.status === "absent") return null;
      if (resolved.status !== "present") return "indeterminate";
      const value = await adapter.readAnchor(resolved.address);
      return value === null ? "indeterminate" : { nativeAddress: resolved.address, value };
    },
  };
}

const NATIVE_LOCATOR = /^stor-[0-9a-f]{40}$/;

/**
 * Reader for listing/vet references that may be either a native `stor-`
 * locator (as the Directory and the announcement carry them) or a logical
 * name (as `publish-listing` prints it). The node only reads native
 * addresses, so a logical name is resolved against its expected owner first;
 * an `indeterminate` resolution throws rather than reading as absent.
 */
export function anchorReaderByRef(
  chain: { readAnchor(address: string): Promise<Record<string, unknown> | null> },
  store: Pick<AnchorStore, "readOwnedAnchor">,
  ownerAddressHex: string,
): (ref: string) => Promise<Record<string, unknown> | null> {
  return async (ref) => {
    if (NATIVE_LOCATOR.test(ref)) return chain.readAnchor(ref);
    const owned = await store.readOwnedAnchor(ref, ownerAddressHex);
    if (owned === "indeterminate") throw new Error(`anchor ${ref} could not be resolved authoritatively`);
    return owned === null ? null : owned.value;
  };
}

/** Deterministic in-memory store for offline tests of the live wiring. */
export function inMemoryAnchorStore(): AnchorStore & { anchors: Map<string, { owner: string; value: Record<string, unknown> }> } {
  const anchors = new Map<string, { owner: string; value: Record<string, unknown> }>();
  let height = 0;
  return {
    anchors,
    async anchorArtifact(input) {
      const hash = contentHash(input.artifact);
      const existing = anchors.get(input.logicalAddress);
      if (existing !== undefined && canonicalize(existing.value) !== canonicalize(input.artifact)) {
        throw new Error(`logical address ${input.logicalAddress} already bound to different bytes`);
      }
      if (existing === undefined) anchors.set(input.logicalAddress, { owner: input.writer, value: structuredClone(input.artifact) });
      height += 1;
      const nativeAddress = `stor-${sha256Hex(input.logicalAddress).slice(0, 40)}`;
      const now = Date.now();
      const receipt: AnchorReceipt = {
        receiptVersion: "1", substrate: "demos:local", finalityProfile: "demos-bft-final", logicalAddress: input.logicalAddress,
        nativeAddress, contentHash: hash, transactionRef: { kind: "demos", value: `tx-${height}` }, writer: input.writer,
        nonce: String(height), state: "finalized", observationDisposition: "established", observedAt: now,
        blockRef: { id: `block-${height}`, height: String(height), timestamp: now - 1 }, evidence: { kind: "demos-finality-proof", value: `proof-${height}` },
      };
      return { ref: { anchor: { kind: "storage-program", locator: input.logicalAddress }, contentHash: hash, signer: input.refSigner ?? input.writer }, receipt, nativeAddress };
    },
    async readOwnedAnchor(logicalAddress, ownerAddressHex) {
      const entry = anchors.get(logicalAddress);
      if (entry === undefined) return null;
      // owner is a claim in-memory; accept either the claim or its address hex
      if (entry.owner !== ownerAddressHex && !entry.owner.endsWith(ownerAddressHex)) return null;
      return { nativeAddress: `stor-${sha256Hex(logicalAddress).slice(0, 40)}`, value: structuredClone(entry.value) };
    },
  };
}
