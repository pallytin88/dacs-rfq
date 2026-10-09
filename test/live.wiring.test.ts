/**
 * The live wiring with the chain swapped for an in-memory anchor store:
 * a Listing is built, signed with the seller's key, anchored and rediscovered
 * through the SDK's own `validateListingArtifact`; both parties run the vet
 * exchange through the announcement path; and the full showcase completes with
 * every vet record and the commitment anchored.
 */

import { generateKeyPairSync, randomBytes } from "node:crypto";
import { anchorReaderByRef } from "../src/live/anchors.js";
import { createDemosFinalityProvider } from "../src/commit.js";
import { sha256Hex } from "@kynesyslabs/dacs/canonical";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { canonicalize, contentHash } from "@kynesyslabs/dacs/canonical";
import { ed25519Sign, ed25519Verify, rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { demosAgentClaimRef } from "@kynesyslabs/dacs/identity";
import { createDurableRfqLifecycleClient } from "@kynesyslabs/dacs/negotiate";
import { createInMemoryWalletSpendStateStore, createWalletSpendAuthorityV1 } from "@kynesyslabs/dacs/rails";
import type { PayDemRail } from "@kynesyslabs/dacs/rails";
import type { SettleResult } from "@kynesyslabs/dacs";
import {
  CANONICAL_PROFILE_ID, buildIdentityBundle, buildRfqListingDraft, commitNegotiatedAgreement, createBuyerCeilingGuard,
  createBuyerNegotiationService, createBuyerVetExchange, createChannelSignatureAdapter, createCommitmentSignatureVerifier,
  createInMemoryFinalityProvider, createRfqHttpTransport, createRfqInboxStore, createSellerDaemon, createSellerRulePolicy,
  createSellerVetExchange, createSessionIndex, demosAddressFromClaim, discoverVerifiedListing, inMemoryAnchorStore,
  keyObjectSigner, openRoleStores, publishListing, settleWithPayDem, signListing, startBuyerMcpServer, startRfqTransportServer,
  staticMemberAuthority, verifyIdentityBundle,
} from "../src/index.js";
import type { ChannelMessageSignatureV1, Counterparty } from "../src/index.js";

const NOW = 1_780_000_000_000;
const buyerKeys = generateKeyPairSync("ed25519");
const sellerKeys = generateKeyPairSync("ed25519");
const buyerPub = rawPublicKey(buyerKeys.publicKey);
const sellerPub = rawPublicKey(sellerKeys.publicKey);
const BUYER = demosAgentClaimRef(buyerPub);
const SELLER = demosAgentClaimRef(sellerPub);
const buyerSigner = keyObjectSigner(BUYER, buyerKeys.privateKey);
const sellerSigner = keyObjectSigner(SELLER, sellerKeys.privateKey);
const peers = new Map<string, Uint8Array>([[BUYER, buyerPub], [SELLER, sellerPub]]);
const authority = staticMemberAuthority(peers);
const buyerCounterparty: Counterparty = { claim: BUYER, addressHex: Buffer.from(buyerPub).toString("hex"), publicKey: buyerPub };
const sellerCounterparty: Counterparty = { claim: SELLER, addressHex: Buffer.from(sellerPub).toString("hex"), publicKey: sellerPub };

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => { for (const fn of cleanups.splice(0).reverse()) await fn(); });

describe("live wiring against an in-memory chain", () => {
  test("listing: signed with the seller key, anchored, and rediscovered through SDK validation", async () => {
    const chain = inMemoryAnchorStore();
    const sellerIdentity = await buildIdentityBundle(sellerSigner, NOW, false);
    expect(verifyIdentityBundle(sellerIdentity, sellerPub)).toBe(true);
    expect(verifyIdentityBundle(sellerIdentity, buyerPub)).toBe(false);
    const draft = buildRfqListingDraft(sellerIdentity, {
      listingId: "live-rfq-quote", displayName: "Showcase seller", publicEndpoint: "https://seller.example/dacs",
      title: "Private quote", description: "Negotiated privately", category: "data.finance",
      bandCenter: { amount: "10", currency: "DEM" }, minPct: 20, maxPct: 20, maxTurns: 6, timeoutSec: 120,
    }, NOW);
    const listing = await signListing(draft, sellerSigner);
    const published = await publishListing(chain, sellerSigner, listing);
    expect(published.logicalAddress).toContain("live-rfq-quote");
    const verified = await discoverVerifiedListing({
      readAnchor: async (ref) => chain.anchors.get(ref)?.value ?? null,
      listingRef: published.logicalAddress, sellerClaim: SELLER, sellerPublicKey: sellerPub, nowMs: () => NOW,
    });
    expect(verified.pin).toEqual(published.pin);
    expect(canonicalize(verified.listing as unknown as Record<string, unknown>)).toBe(canonicalize(listing as unknown as Record<string, unknown>));
    // A listing signed by the wrong key is refused.
    const forged = await signListing(draft, buyerSigner);
    const forgedChain = inMemoryAnchorStore();
    const forgedPub = await publishListing(forgedChain, sellerSigner, { ...forged, signature: { ...forged.signature, signer: SELLER } });
    await expect(discoverVerifiedListing({
      readAnchor: async (ref) => forgedChain.anchors.get(ref)?.value ?? null,
      listingRef: forgedPub.logicalAddress, sellerClaim: SELLER, sellerPublicKey: sellerPub, nowMs: () => NOW,
    })).rejects.toThrow(/did not verify/);
  });

  test("showcase with the vet exchange: both vet records anchored before the first turn, deal commits and settles", async () => {
    const chain = inMemoryAnchorStore();
    const base = mkdtempSync(join(tmpdir(), "dacs-rfq-live-"));
    cleanups.push(() => rmSync(base, { recursive: true, force: true }));
    const sellerIdentity = await buildIdentityBundle(sellerSigner, NOW, false);
    const buyerIdentity = await buildIdentityBundle(buyerSigner, NOW, true);
    const listing = await signListing(buildRfqListingDraft(sellerIdentity, {
      listingId: "live-rfq-quote", displayName: "Showcase seller", publicEndpoint: "https://seller.example/dacs",
      title: "Private quote", description: "Negotiated privately", category: "data.finance",
      bandCenter: { amount: "10", currency: "DEM" }, minPct: 20, maxPct: 20, maxTurns: 6, timeoutSec: 120,
    }, NOW), sellerSigner);
    const published = await publishListing(chain, sellerSigner, listing);
    const verifiedListing = await discoverVerifiedListing({
      readAnchor: async (ref) => chain.anchors.get(ref)?.value ?? null,
      listingRef: published.logicalAddress, sellerClaim: SELLER, sellerPublicKey: sellerPub, nowMs: () => NOW,
    });

    async function role(roleName: "buyer" | "seller", peerEndpoint: () => string) {
      const claim = roleName === "buyer" ? BUYER : SELLER;
      const signer = roleName === "buyer" ? buyerSigner : sellerSigner;
      const stores = await openRoleStores<ChannelMessageSignatureV1>({ role: roleName, root: join(base, roleName), integrityKeyPath: join(base, "keys", `${roleName}.key`), createIntegrityKey: true });
      const inbox = createRfqInboxStore({ path: stores.transportDbPath });
      const sessions = createSessionIndex({ path: join(base, roleName, "sessions.db") });
      const server = await startRfqTransportServer({ self: signer, peers, inbox });
      const counterpart = roleName === "buyer" ? SELLER : BUYER;
      const transport = createRfqHttpTransport<ChannelMessageSignatureV1>({
        self: signer, peers, endpoints: new Map([[counterpart, "lazy"]]),
        fetch: (input, init) => fetch(input === "lazy" ? peerEndpoint() : input, init), requestTimeoutMs: 2_000,
      });
      const signature = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer, authority });
      const client = createDurableRfqLifecycleClient<ChannelMessageSignatureV1>({
        role: roleName, store: stores.lifecycle, transport, reserveChannelId: (input) => stores.reservation.reserve(input),
        signChannelMessage: signature.signChannelMessage, verifyChannelMessage: signature.verifyChannelMessage,
        agreementSigner: { party: claim, algorithm: "ed25519", sign: (bytes: Uint8Array) => signer.sign(bytes) },
        verifyAgreementContribution: (input) => {
          const key = peers.get(input.party);
          return key !== undefined && ed25519Verify(input.signedBytes, Buffer.from(input.value, "base64url"), (await0(key))) ? "valid" : "invalid";
        },
        nowMs: () => NOW,
      });
      cleanups.push(async () => { await server.close(); inbox.close(); sessions.close(); stores.close(); });
      return { claim, signer, stores, inbox, sessions, server, transport, client };
    }
    function await0(key: Uint8Array) { return (require0().publicKeyFromRaw as (k: Uint8Array) => import("node:crypto").KeyObject)(key); }
    function require0() { return { publicKeyFromRaw: (k: Uint8Array) => (globalThis as unknown as { __pk: (k: Uint8Array) => import("node:crypto").KeyObject }).__pk(k) }; }
    (globalThis as unknown as { __pk: unknown }).__pk = (await import("@kynesyslabs/dacs/crypto")).publicKeyFromRaw;

    let sellerEndpoint = "";
    let buyerEndpoint = "";
    const seller = await role("seller", () => buyerEndpoint);
    const buyer = await role("buyer", () => sellerEndpoint);
    sellerEndpoint = seller.server.endpoint;
    buyerEndpoint = buyer.server.endpoint;

    const daemon = createSellerDaemon({
      sellerClaim: SELLER, sellerParty: { identityBundle: sellerIdentity, vetRecordRef: { anchor: { kind: "storage-program", locator: "unused" }, contentHash: "0".repeat(64) } },
      listings: () => [verifiedListing], client: seller.client, inbox: seller.inbox, sessions: seller.sessions,
      policy: createSellerRulePolicy({ floor: { amount: "9.5", currency: "DEM" } }), nowMs: () => NOW,
      vet: { exchange: createSellerVetExchange({ store: chain, self: sellerSigner, nowMs: () => NOW }), resolveBuyer: (claim) => (claim === BUYER ? buyerCounterparty : null) },
    });
    const finality = createInMemoryFinalityProvider({ writer: BUYER, nowMs: () => NOW + 5_000 });
    const rail: PayDemRail = {
      address: demosAddressFromClaim(BUYER)!,
      async settle(params) {
        await params.assertCurrentBeforeBroadcast?.();
        return { ok: true, txHash: randomBytes(32).toString("hex"), chainId: "demos:testnet", payer: demosAddressFromClaim(BUYER)!, payee: params.recipient } as SettleResult;
      },
    };
    const spend = createWalletSpendAuthorityV1({
      policyVersion: "1", policyId: "live-buyer", wallet: demosAddressFromClaim(BUYER)!, chainId: "demos:testnet",
      maximumConcurrentEffects: 1, maximumRetainedReservations: 100,
      assets: [{ asset: "DEM", maximumPerOrderDebit: "20000000000", maximumNetworkFeeDebit: "1000000000", minimumReserve: "0",
        rollingWindowMs: 3_600_000, maximumRollingEffects: 10, maximumRollingDebit: "100000000000", maximumCumulativeDebit: "1000000000000", maximumCounterpartyDebit: "100000000000" }],
    }, { store: createInMemoryWalletSpendStateStore(), readBalance: async () => "1000000000000", authenticateRecovery: async () => true, now: () => NOW + 6_000 });
    const service = createBuyerNegotiationService<ChannelMessageSignatureV1>({
      buyerClaim: BUYER, buyerParty: { identityBundle: buyerIdentity, vetRecordRef: { anchor: { kind: "storage-program", locator: "unused" }, contentHash: "0".repeat(64) } },
      client: buyer.client, transport: buyer.transport, inbox: buyer.inbox, sessions: buyer.sessions,
      catalog: () => [{ verifiedListing, sellerVetRecordRef: { anchor: { kind: "storage-program", locator: "unused" }, contentHash: "0".repeat(64) }, sellerClaim: SELLER }],
      ceiling: createBuyerCeilingGuard({ amount: "9.8", currency: "DEM" }),
      vet: createBuyerVetExchange({ store: chain, self: buyerSigner, seller: sellerCounterparty, nowMs: () => NOW, pollMs: 50, timeoutMs: 10_000 }),
      commit: (record, vl) => commitNegotiatedAgreement({ record, verifiedListing: vl, orchestrator: BUYER, provider: finality, verifySignature: createCommitmentSignatureVerifier(authority.resolve), nowMs: () => NOW + 4_000,
        commitmentSigner: { algorithm: "ed25519", signer: BUYER, sign: (bytes: Uint8Array) => ed25519Sign(bytes, buyerKeys.privateKey) } }),
      settle: (record, commitment) => settleWithPayDem({ rail, authority: spend, agreement: record.agreement!.finalized!, commitment, maximumNetworkFeeOs: "1000000000", nowMs: () => NOW + 6_000 }),
      nowMs: () => NOW,
    });
    const token = randomBytes(32).toString("base64url");
    const mcp = await startBuyerMcpServer({ service, bearerToken: token });
    cleanups.push(() => mcp.close());
    let id = 1;
    const call = async <T,>(name: string, args: Record<string, unknown>): Promise<T> => {
      const r = await fetch(mcp.endpoint, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: id++, method: "tools/call", params: { name, arguments: args } }) });
      const reply = await r.json() as { result?: { structuredContent?: unknown; isError?: boolean; content?: Array<{ text: string }> } };
      if (reply.result?.isError) throw new Error(reply.result.content?.[0]?.text ?? "tool error");
      return reply.result!.structuredContent as T;
    };

    // The buyer's vet of the seller lands before the announcement; the seller must vet the buyer before the buyer can open.
    // Interleave: open_negotiation blocks on the seller's vet, so run the seller daemon concurrently.
    const opening = call<{ jobId: string }>("open_negotiation", { listingId: "live-rfq-quote" });
    let ticks = 0;
    while (ticks < 50) {
      const t = await daemon.tick();
      ticks += 1;
      if (t.opened > 0) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    const { jobId } = await opening;
    const vetAddresses = [...chain.anchors.keys()].filter((k) => k.includes(jobId));
    expect(vetAddresses).toHaveLength(2); // seller's vet of buyer + buyer's vet of seller

    await call("make_offer", { jobId, amount: "9" });
    expect((await daemon.tick()).errors).toEqual([]);
    await call("counter_offer", { jobId, amount: "9.5" });
    expect((await daemon.tick()).errors).toEqual([]);
    await call("get_negotiation_state", { jobId });
    expect((await daemon.tick()).errors).toEqual([]);
    const final = await call<{ phase: string; lastError?: string }>("get_negotiation_state", { jobId });
    expect(final.lastError).toBeUndefined();
    expect(final.phase).toBe("settled");
    const receipts = await call<{ commitment: { logicalAddress: string }; settlement: { amountOs: string } }>("get_receipts", { jobId });
    expect(receipts.commitment.logicalAddress).toBe(`dacs3:commit:${jobId}`);
    expect(receipts.settlement.amountOs).toBe("9500000000");
    // On-chain footprint: listing, two vet records; the commitment lives in the finality provider. No prices anywhere but the listing band.
    for (const [name, entry] of chain.anchors) {
      if (name.includes("listing")) continue;
      expect(canonicalize(entry.value)).not.toMatch(/"9\.5"|"10\.5"|"9"/);
    }
    expect(contentHash(verifiedListing.listing as unknown as Record<string, unknown>)).toBe(published.pin.contentHash);
  });
});

describe("anchorReaderByRef", () => {
  test("reads native locators directly and resolves logical names through the owner", async () => {
    const reads: string[] = [];
    const chain = { readAnchor: async (address: string) => { reads.push(address); return { native: true }; } };
    const store = {
      readOwnedAnchor: async (logical: string, owner: string) =>
        logical === "dacs1:x:listing:v1" && owner === "ab".repeat(32) ? { nativeAddress: `stor-${"1".repeat(40)}`, value: { logical: true } }
        : logical === "dacs1:x:missing:v1" ? null : ("indeterminate" as const),
    };
    const read = anchorReaderByRef(chain, store, "ab".repeat(32));
    expect(await read(`stor-${"2".repeat(40)}`)).toEqual({ native: true });
    expect(reads).toEqual([`stor-${"2".repeat(40)}`]);
    expect(await read("dacs1:x:listing:v1")).toEqual({ logical: true });
    expect(await read("dacs1:x:missing:v1")).toBeNull();
    await expect(read("dacs1:x:unknown:v1")).rejects.toThrow(/authoritatively/);
  });
});

describe("createDemosFinalityProvider", () => {
  test("binds the commitment write to its portable receipt through the metadata triple", async () => {
    const writes: Array<{ name: string; value: Record<string, unknown>; options: unknown }> = [];
    const stored = new Map<string, Record<string, unknown>>();
    const writer = "did:demos:agent:" + "ab".repeat(32);
    const adapter = {
      async anchorWriteOnce(name: string, value: object, options?: unknown) {
        writes.push({ name, value: value as Record<string, unknown>, options });
        const address = `stor-${"3".repeat(40)}`;
        stored.set(address, structuredClone(value) as Record<string, unknown>);
        return { address, txRef: "tx-1" };
      },
      async readAnchor(address: string) { return stored.get(address) ?? null; },
      async resolveAnchorByName() { return { status: "absent" as const }; },
      async resolveDemosAnchorReceipt(input: { logicalAddress: string; nativeAddress: string; contentHash: string; writer: string }) {
        return { receiptVersion: "1", logicalAddress: input.logicalAddress, nativeAddress: input.nativeAddress, contentHash: input.contentHash, writer: input.writer, transactionRef: { kind: "demos", value: "tx-1" } } as never;
      },
      async verifyDemosAnchorReceipt() { return true; },
    };
    const provider = createDemosFinalityProvider({ adapter, writer, writerAddressHex: "ab".repeat(32) });
    const jobId = "01M4DYPS4TA257642PRDW0Q6VQ";
    const record = { jobId, signature: { signer: writer, value: "sig" }, body: { agreed: true } };
    const anchored = await provider.submit(`dacs3:commit:${jobId}`, record as never);
    expect(anchored.nativeAddress).toBe(`stor-${"3".repeat(40)}`);
    expect(writes).toHaveLength(1);
    const metadata = (writes[0]!.options as { metadata: Record<string, string> }).metadata;
    expect(metadata).toEqual({
      logicalAddress: `dacs3:commit:${jobId}`,
      contentHash: contentHash(record as unknown as Record<string, unknown>),
      envelopeHash: sha256Hex(canonicalize(record as unknown as Record<string, unknown>)),
    });
    // A signed record's contentHash is not the hash of its stored bytes; the metadata is what binds them.
    expect(metadata.contentHash).not.toBe(metadata.envelopeHash);
  });
});
