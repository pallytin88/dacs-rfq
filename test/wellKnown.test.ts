import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { sha256Hex } from "@kynesyslabs/dacs/canonical";
import { rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { demosAgentClaimRef } from "@kynesyslabs/dacs/identity";
import {
  buildIdentityBundle, buildRfqListingDraft, buildWellKnownFiles, createRfqInboxStore, inMemoryAnchorStore, keyObjectSigner,
  publishListing, signListing, startRfqTransportServer,
} from "../src/index.js";

const NOW = 1_780_000_000_000;
const keys = generateKeyPairSync("ed25519");
const SELLER = demosAgentClaimRef(rawPublicKey(keys.publicKey));
const signer = keyObjectSigner(SELLER, keys.privateKey);
const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => { for (const fn of cleanups.splice(0).reverse()) await fn(); });

describe("§6.3.5 well-known discovery surface", () => {
  test("agent.json binds listings.json by hash and lists the anchored RFQ listing; the transport serves both", async () => {
    const chain = inMemoryAnchorStore();
    const identity = await buildIdentityBundle(signer, NOW, false);
    const listing = await signListing(buildRfqListingDraft(identity, {
      listingId: "wk-rfq", displayName: "S", publicEndpoint: "https://seller.example/dacs", title: "Quote", description: "d", category: "data.finance",
      bandCenter: { amount: "10", currency: "DEM" }, minPct: 20, maxPct: 20, maxTurns: 6, timeoutSec: 60,
    }, NOW), signer);
    const published = await publishListing(chain, signer, listing);
    expect(published.nativeAddress).toMatch(/^stor-[0-9a-f]{40}$/);
    const files = buildWellKnownFiles({ sellerClaim: SELLER, displayName: "SuperColony seller", domain: "seller.example", listings: [{ listing, locator: published.nativeAddress, status: "active" }], generatedAt: NOW });
    const agent = JSON.parse(files["/.well-known/agent.json"]);
    const index = JSON.parse(files["/.well-known/dacs/listings.json"]);
    expect(agent.dacs).toMatchObject({ dacsVersion: "1", listings: { indexUrl: "https://seller.example/.well-known/dacs/listings.json" } });
    expect(agent.dacs.listings.indexHash).toBe(`sha256-${sha256Hex(files["/.well-known/dacs/listings.json"])}`);
    expect(agent.skills).toEqual([{ id: "wk-rfq", name: "Quote", description: "d", tags: ["rfq"] }]);
    expect(index).toMatchObject({ indexVersion: "1", seller: SELLER });
    expect(index.listings[0]).toMatchObject({ listingId: "wk-rfq", version: 1, contentHash: published.pin.contentHash, anchor: { kind: "storage-program", locator: published.nativeAddress }, status: "active" });
    expect(index.listings[0].summary.priceHint).toContain("negotiable");

    const dir = mkdtempSync(join(tmpdir(), "dacs-rfq-wk-"));
    cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
    const inbox = createRfqInboxStore({ path: join(dir, "transport.db") });
    cleanups.push(() => inbox.close());
    const server = await startRfqTransportServer({ self: signer, peers: new Map([[SELLER, rawPublicKey(keys.publicKey)]]), inbox, staticDocuments: () => files });
    cleanups.push(() => server.close());
    const base = server.endpoint.replace(/\/colony-rfq\/v0\/messages$/, "");
    const served = await (await fetch(`${base}/.well-known/dacs/listings.json`)).text();
    expect(served).toBe(files["/.well-known/dacs/listings.json"]); // byte-exact, so indexHash still binds
    expect((await fetch(`${base}/.well-known/agent.json`)).status).toBe(200);
    expect((await fetch(`${base}/.well-known/nope.json`)).status).toBe(404);
  });
});
