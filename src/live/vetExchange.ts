/**
 * The pre-negotiation vet exchange both roles run before `open()`.
 * Backed by any `AnchorStore` (Demos live, or in-memory for tests).
 */

import type { AttestationRef, IdentityBundle } from "@kynesyslabs/dacs/artifacts";
import type { Ed25519Signer } from "../signer.js";
import type { RfqSessionAnnouncement } from "../transport/open.js";
import type { AnchorStore } from "./anchors.js";
import { publishVetOf, readVetBy, verifyVetRecord } from "./vet.js";

export interface Counterparty {
  claim: string;
  addressHex: string;
  publicKey: Uint8Array;
}

export interface BuyerVetExchange {
  /** Step 1: sign and anchor our vet of the seller. */
  vetSeller(jobId: string, sellerBundle: Readonly<IdentityBundle>): Promise<AttestationRef>;
  /** Step 4: wait for the seller's vet of us to land on chain and verify it. */
  awaitVetOfBuyer(jobId: string, buyerBundle: Readonly<IdentityBundle>): Promise<AttestationRef>;
}

export interface SellerVetExchange {
  /** Step 3a: confirm the buyer's announced vet of us is anchored and valid. */
  verifyVetOfSeller(announcement: Readonly<RfqSessionAnnouncement>, sellerBundle: Readonly<IdentityBundle>, buyer: Counterparty): Promise<boolean>;
  /** Step 3b: sign and anchor our vet of the buyer. */
  vetBuyer(jobId: string, buyerBundle: Readonly<IdentityBundle>): Promise<AttestationRef>;
}

export function createBuyerVetExchange(input: {
  store: AnchorStore;
  self: Ed25519Signer;
  seller: Counterparty;
  nowMs?: () => number;
  pollMs?: number;
  timeoutMs?: number;
  log?: (e: Record<string, unknown>) => void;
}): BuyerVetExchange {
  const nowMs = input.nowMs ?? Date.now;
  return {
    async vetSeller(jobId, sellerBundle) {
      const { ref } = await publishVetOf({ store: input.store, verifier: input.self, jobId, evaluatedParty: input.seller.claim, bundle: sellerBundle, nowMs: nowMs() });
      input.log?.({ event: "vet-published", jobId, evaluatedParty: input.seller.claim, locator: ref.anchor.locator });
      return ref;
    },
    async awaitVetOfBuyer(jobId, buyerBundle) {
      const deadline = Date.now() + (input.timeoutMs ?? 120_000);
      for (;;) {
        const result = await readVetBy({
          store: input.store, jobId, evaluatedParty: input.self.claim, evaluatedBundle: buyerBundle,
          verifier: input.seller.claim, verifierAddressHex: input.seller.addressHex, verifierPublicKey: input.seller.publicKey,
        });
        if (result === "invalid") throw new Error("seller's vet record of the buyer does not verify");
        if (result !== null && result !== "indeterminate") {
          input.log?.({ event: "vet-received", jobId, verifier: input.seller.claim, locator: result.anchor.locator });
          return result;
        }
        if (Date.now() > deadline) throw new Error("timed out waiting for the seller's vet record");
        await new Promise((resolve) => setTimeout(resolve, input.pollMs ?? 2_000));
      }
    },
  };
}

export function createSellerVetExchange(input: {
  store: AnchorStore;
  self: Ed25519Signer;
  nowMs?: () => number;
  log?: (e: Record<string, unknown>) => void;
}): SellerVetExchange {
  const nowMs = input.nowMs ?? Date.now;
  return {
    async verifyVetOfSeller(announcement, sellerBundle, buyer) {
      const read = await input.store.readOwnedAnchor(announcement.sellerVetRef.anchor.locator, buyer.addressHex);
      if (read === null || read === "indeterminate") return false;
      const ok = verifyVetRecord(read.value, {
        jobId: announcement.jobId, evaluatedParty: input.self.claim, bundle: sellerBundle,
        verifier: buyer.claim, verifierPublicKey: buyer.publicKey,
      });
      return ok && announcement.sellerVetRef.signer === buyer.claim;
    },
    async vetBuyer(jobId, buyerBundle) {
      const { ref } = await publishVetOf({ store: input.store, verifier: input.self, jobId, evaluatedParty: buyerBundle.presentedBy, bundle: buyerBundle, nowMs: nowMs() });
      input.log?.({ event: "vet-published", jobId, evaluatedParty: buyerBundle.presentedBy, locator: ref.anchor.locator });
      return ref;
    },
  };
}
