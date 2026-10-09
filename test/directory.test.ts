import { generateKeyPairSync } from "node:crypto";
import { describe, expect, test } from "vitest";
import { rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { demosAgentClaimRef } from "@kynesyslabs/dacs/identity";
import {
  buildIdentityBundle, buildRfqListingDraft, createDirectoryCatalog, inMemoryAnchorStore, keyObjectSigner, publishListing, signListing,
} from "../src/index.js";

const NOW = 1_780_000_000_000;
const sellerKeys = generateKeyPairSync("ed25519");
const SELLER = demosAgentClaimRef(rawPublicKey(sellerKeys.publicKey));
const sellerSigner = keyObjectSigner(SELLER, sellerKeys.privateKey);

describe("directory-backed catalog", () => {
  test("offers only listings the chain verifies, filtered to RFQ and to the configured seller", async () => {
    const chain = inMemoryAnchorStore();
    const identity = await buildIdentityBundle(sellerSigner, NOW, false);
    const listing = await signListing(buildRfqListingDraft(identity, {
      listingId: "dir-rfq", displayName: "S", publicEndpoint: "https://s.example/dacs", title: "Quote", description: "d", category: "data.finance",
      bandCenter: { amount: "10", currency: "DEM" }, minPct: 20, maxPct: 20, maxTurns: 6, timeoutSec: 60,
    }, NOW), sellerSigner);
    const published = await publishListing(chain, sellerSigner, listing);
    const summaries = [
      { listingId: "dir-rfq", version: 1, contentHash: published.pin.contentHash, anchor: { kind: "storage-program", locator: published.logicalAddress },
        seller: { primaryClaim: SELLER }, artifactProfile: "dacs-v0.1", status: "active", offering: { title: "Quote", category: "data.finance", negotiation: ["negotiate-rfq"] }, pricing: { kind: "negotiable" } },
      // same bytes, but the directory claims a different hash → skipped
      { listingId: "dir-rfq", version: 1, contentHash: "f".repeat(64), anchor: { kind: "storage-program", locator: published.logicalAddress },
        seller: { primaryClaim: SELLER }, artifactProfile: "dacs-v0.1", status: "active", offering: { title: "Quote", category: "data.finance", negotiation: ["negotiate-rfq"] }, pricing: { kind: "negotiable" } },
      // fixed-price listing → not RFQ → skipped
      { listingId: "fixed", version: 1, contentHash: "a".repeat(64), anchor: { kind: "storage-program", locator: "stor:nope" },
        seller: { primaryClaim: SELLER }, artifactProfile: "dacs-v0.1", status: "active", offering: { title: "F", category: "x", negotiation: ["negotiate-fixed-price"] }, pricing: { kind: "fixed" } },
      // anchor missing on chain → skipped
      { listingId: "ghost", version: 1, contentHash: "b".repeat(64), anchor: { kind: "storage-program", locator: "stor:missing" },
        seller: { primaryClaim: SELLER }, artifactProfile: "dacs-v0.1", status: "active", offering: { title: "G", category: "x", negotiation: ["negotiate-rfq"] }, pricing: { kind: "negotiable" } },
    ];
    const requested: string[] = [];
    const fakeFetch = (async (input: string | URL | Request) => {
      requested.push(String(input));
      return new Response(JSON.stringify({ listings: summaries }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    const skipped: string[] = [];
    const catalog = createDirectoryCatalog({
      directoryUrl: "https://directory.test", sellers: [SELLER], fetch: fakeFetch, nowMs: () => NOW,
      readAnchor: async (ref) => chain.anchors.get(ref)?.value ?? null,
      log: (e) => { if (e["event"] === "directory-skip") skipped.push(String(e["listingId"])); },
    });
    const entries = await catalog();
    expect(requested[0]).toContain("/api/dacs/listings?");
    expect(requested[0]).toContain(`primaryClaim=${encodeURIComponent(SELLER)}`);
    expect(entries.map((e) => `${e.verifiedListing.listing.listingId}@${e.verifiedListing.listing.listingVersion}`)).toEqual(["dir-rfq@1"]);
    expect(entries[0]!.verifiedListing.pin).toEqual(published.pin);
    expect(skipped.sort()).toEqual(["dir-rfq", "ghost"]);
  });
});
