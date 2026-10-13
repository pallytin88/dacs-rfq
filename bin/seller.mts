#!/usr/bin/env -S node --import tsx
/**
 * Live seller process (testnet).
 *
 *   tsx bin/seller.mts publish-listing   sign + anchor the RFQ listing, print LISTING_REF
 *   tsx bin/seller.mts run               serve the transport, vet announced buyers, negotiate
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Listing } from "@kynesyslabs/dacs/artifacts";
import {
  anchorReaderByRef, buildIdentityBundle, buildRfqListingDraft, buildWellKnownFiles, createSellerDaemon, createSellerRulePolicy, createSellerVetExchange,
  discoverVerifiedListing, publishListing, signListing,
} from "../src/index.js";
import { bootstrapRole, counterpartyFromClaim, loadConfig, log } from "./common.mts";

const command = process.argv[2] ?? "run";
const env = loadConfig();
const port = Number(env["SELLER_TRANSPORT_PORT"] ?? 47101);
const role = await bootstrapRole("seller", env, port);
const identityPath = join(role.root, "identity-bundle.json");
const listingPath = join(role.root, "listing.json");

async function sellerIdentity() {
  if (existsSync(identityPath)) return JSON.parse(readFileSync(identityPath, "utf8"));
  const bundle = await buildIdentityBundle(role.actor.signer, Date.now(), false);
  writeFileSync(identityPath, JSON.stringify(bundle), { mode: 0o600 });
  return bundle;
}

if (command === "publish-listing") {
  const identity = await sellerIdentity();
  const draft = buildRfqListingDraft(identity, {
    listingId: env["LISTING_ID"] ?? `rfq-showcase-${Date.now().toString(36)}`,
    displayName: "SuperColony showcase seller",
    publicEndpoint: env["SELLER_PUBLIC_ENDPOINT"] ?? "https://seller.supercolony.example/dacs",
    title: "Private market data quote",
    description: "One attested JSON payload; price negotiated privately over DACS-3 RFQ.",
    category: "data.finance",
    bandCenter: { amount: env["LISTING_BAND_CENTER_DEM"] ?? "10", currency: "DEM" },
    minPct: 20, maxPct: 20, maxTurns: 6, timeoutSec: 300,
  }, Date.now());
  const listing = await signListing(draft, role.actor.signer);
  const published = await publishListing(role.chain, role.actor.signer, listing);
  writeFileSync(listingPath, JSON.stringify({ listing, logicalAddress: published.logicalAddress, nativeAddress: published.nativeAddress, pin: published.pin }), { mode: 0o600 });
  // §6.3.5 discovery surface, ready to host byte-exact on the public domain.
  const domain = (env["SELLER_PUBLIC_ENDPOINT"] ?? "https://seller.supercolony.example/dacs").replace(/^https?:\/\//, "").split("/")[0]!;
  const files = buildWellKnownFiles({ sellerClaim: role.actor.claim, displayName: "SuperColony showcase seller", domain, listings: [{ listing, locator: published.nativeAddress, status: "active" }] });
  const wk = join(role.root, "well-known");
  mkdirSync(join(wk, "dacs"), { recursive: true, mode: 0o700 });
  writeFileSync(join(wk, "agent.json"), files["/.well-known/agent.json"]);
  writeFileSync(join(wk, "dacs", "listings.json"), files["/.well-known/dacs/listings.json"]);
  log({ event: "well-known-written", dir: wk, indexHash: files.indexHash, domain });
  log({ event: "listing-published", logicalAddress: published.logicalAddress, nativeAddress: published.nativeAddress, pin: published.pin });
  process.stdout.write(`LISTING_REF=${published.logicalAddress}\n`);
  await role.server.close();
  process.exit(0);
}

if (command === "run") {
  if (!existsSync(listingPath)) throw new Error("run `publish-listing` first");
  const stored = JSON.parse(readFileSync(listingPath, "utf8")) as { listing: Listing; logicalAddress: string };
  const verified = await discoverVerifiedListing({
    readAnchor: anchorReaderByRef(role.actor.adapter, role.chain, role.actor.addressHex), listingRef: stored.logicalAddress,
    sellerClaim: role.actor.claim, sellerPublicKey: role.actor.publicKey, nowMs: () => Date.now(),
  });
  const identity = await sellerIdentity();
  const daemon = createSellerDaemon({
    sellerClaim: role.actor.claim,
    sellerParty: { identityBundle: identity, vetRecordRef: { anchor: { kind: "storage-program", locator: "pending" }, contentHash: "0".repeat(64) } },
    listings: () => [verified], client: role.client, inbox: role.inbox, sessions: role.sessions,
    policy: createSellerRulePolicy({ floor: { amount: env["SELLER_FLOOR_DEM"] ?? "9.5", currency: "DEM" }, log }),
    allowBuyers: () => [role.counterpart.claim, ...role.extraPeers.map((p) => p.claim), ...role.syncAdmitted()],
    vet: { exchange: createSellerVetExchange({ store: role.chain, self: role.actor.signer, log }), resolveBuyer: (claim) => (claim !== role.actor.claim && role.peers.has(claim) ? counterpartyFromClaim(claim) : null) },
    log,
  });
  const controller = new AbortController();
  process.on("SIGINT", () => controller.abort());
  process.on("SIGTERM", () => controller.abort());
  log({ event: "seller-running", listing: stored.logicalAddress, transport: role.server.endpoint });
  await daemon.run(Number(env["SELLER_TICK_MS"] ?? 3_000), controller.signal);
  await role.server.close();
  process.exit(0);
}

throw new Error(`unknown command ${command}`);
