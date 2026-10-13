/**
 * DACS-1 Listing for a private RFQ offer: built, signed with the seller's
 * Demos key under `dacs-listing:v1:`, anchored write-once at the normative
 * listing address, and on the buyer side discovered from chain and validated
 * with the SDK's `validateListingArtifact` before it is pinned.
 */

import { contentHash, listingAddress } from "@kynesyslabs/dacs/canonical";
import type { IdentityBundle, Listing, ListingDraft } from "@kynesyslabs/dacs/artifacts";
import { ed25519Verify, publicKeyFromRaw, signedBytes } from "@kynesyslabs/dacs/crypto";
import { discoverListings, validateListingArtifact } from "@kynesyslabs/dacs";
import type { ListingValidationDeps } from "@kynesyslabs/dacs";
import type { VerifiedListingInput } from "@kynesyslabs/dacs/negotiate";
import { signBytes } from "../signer.js";
import type { Ed25519Signer } from "../signer.js";
import type { AnchorStore } from "./anchors.js";
import { verifyIdentityBundle } from "./identity.js";

export const LISTING_DOMAIN = "dacs-listing:v1:" as const;

export interface RfqListingSpec {
  listingId: string;
  listingVersion?: number;
  displayName: string;
  publicEndpoint: string;
  title: string;
  description: string;
  category: string;
  tags?: string[];
  bandCenter: { amount: string; currency: string };
  minPct: number;
  maxPct: number;
  maxTurns: number;
  timeoutSec: number;
  deadlineSecAfterCommit?: number;
  validityMs?: number;
}

export function buildRfqListingDraft(sellerIdentity: IdentityBundle, spec: RfqListingSpec, nowMs: number): ListingDraft {
  return {
    dacsVersion: "1",
    listingVersion: spec.listingVersion ?? 1,
    listingId: spec.listingId,
    requiredCapabilities: ["SR-2", "SR-4"],
    seller: { identity: structuredClone(sellerIdentity), displayName: spec.displayName, publicEndpoint: spec.publicEndpoint },
    offering: {
      title: spec.title, description: spec.description, category: spec.category, tags: spec.tags ?? ["rfq"],
      deliverable: { kind: "storage-program", accessModel: "public" },
    },
    buyerRequirement: { requirementVersion: "1", required: [] },
    pipeline: [
      { kind: "negotiate-rfq", parameters: { maxTurns: spec.maxTurns, timeoutSec: spec.timeoutSec } },
      { kind: "commit-agreement" },
      { kind: "deliver-storage-program" },
    ],
    pricing: { kind: "negotiable", bandCenter: { ...spec.bandCenter }, minPct: spec.minPct, maxPct: spec.maxPct },
    terms: { deadlineSecAfterCommit: spec.deadlineSecAfterCommit ?? 3_600 },
    validity: { notBefore: nowMs - 60_000, notAfter: nowMs + (spec.validityMs ?? 7 * 24 * 3_600_000) },
  } as ListingDraft;
}

export async function signListing(draft: ListingDraft, seller: Ed25519Signer): Promise<Listing> {
  const signature = await signBytes(seller, signedBytes(LISTING_DOMAIN, contentHash(draft as unknown as Record<string, unknown>)));
  return { ...draft, signature: { algorithm: "ed25519", signer: seller.claim, value: Buffer.from(signature).toString("base64url") } } as Listing;
}

export interface PublishedListing {
  listing: Listing;
  logicalAddress: string;
  nativeAddress: string;
  pin: { listingId: string; version: number; contentHash: string };
}

export async function publishListing(store: AnchorStore, seller: Ed25519Signer, listing: Listing): Promise<PublishedListing> {
  const logicalAddress = listingAddress(seller.claim, listing.listingId, listing.listingVersion);
  const anchored = await store.anchorArtifact({ writer: seller.claim, logicalAddress, artifact: listing as unknown as Record<string, unknown> });
  return {
    listing,
    logicalAddress,
    nativeAddress: anchored.nativeAddress,
    pin: { listingId: listing.listingId, version: listing.listingVersion, contentHash: anchored.ref.contentHash },
  };
}

export function listingValidationDeps(input: { sellerClaim: string; sellerPublicKey: Uint8Array; nowMs: () => number }): ListingValidationDeps {
  return {
    nowMs: input.nowMs,
    verifyListingSignature: ({ signedBytes: bytes, signature }) =>
      signature.signer === input.sellerClaim && signature.algorithm === "ed25519" &&
      ed25519Verify(bytes, Uint8Array.from(Buffer.from(signature.value, "base64url")), publicKeyFromRaw(input.sellerPublicKey)),
    revocation: {
      surfaces: [{ kind: "well-known", status: "active", integrity: "verified" }],
      readMarker: async () => null,
      verifyMarkerSignature: () => false,
    },
    verifyIdentityPresentation: ({ bundle }) => bundle.presentedBy === input.sellerClaim && verifyIdentityBundle(bundle, input.sellerPublicKey),
    verifySellerControl: ({ bundle, signer }) =>
      signer === input.sellerClaim && bundle.presentedBy === signer && bundle.claims.some(({ ref }) => ref === signer),
  };
}

/** Buyer side: read the listing by logical ref, verify signature and structure, pin the bytes. */
export async function discoverVerifiedListing(input: {
  readAnchor: (ref: string) => Promise<Record<string, unknown> | null>;
  listingRef: string;
  sellerClaim: string;
  sellerPublicKey: Uint8Array;
  nowMs: () => number;
}): Promise<VerifiedListingInput> {
  const deps = listingValidationDeps({ sellerClaim: input.sellerClaim, sellerPublicKey: input.sellerPublicKey, nowMs: input.nowMs });
  const discovered = await discoverListings([input.listingRef], input.readAnchor, {
    verify: (bytes, signature, publicKey) => ed25519Verify(bytes, signature, publicKeyFromRaw(publicKey)),
    resolvePublicKey: (claim) => (claim === input.sellerClaim ? input.sellerPublicKey : null),
    validateListing: (raw) => validateListingArtifact(raw, deps),
    nowMs: input.nowMs,
  });
  if (discovered.length !== 1) throw new Error(`listing ${input.listingRef} did not verify`);
  const listing = discovered[0]!.listing as Listing;
  return {
    disposition: "verified",
    listing,
    pin: { listingId: listing.listingId, version: listing.listingVersion, contentHash: contentHash(listing as unknown as Record<string, unknown>) },
  };
}
