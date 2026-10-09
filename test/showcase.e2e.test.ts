/**
 * The showcase, offline: a scripted "ChatGPT agent" drives the buyer only
 * through MCP tool calls over HTTP; an independent seller daemon runs its rule
 * policy; both sides talk over the interim transport with real files. After
 * acceptance the buyer co-signs, commits the agreement hash (in-memory
 * finality provider standing in for Demos) and pays over a fake DEM rail
 * behind the real wallet spend authority. Finally we assert that nothing
 * "on chain" contains an offer or counter amount.
 */

import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { canonicalize, contentHash } from "@kynesyslabs/dacs/canonical";
import { ed25519Sign, ed25519Verify, rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { createDurableRfqLifecycleClient } from "@kynesyslabs/dacs/negotiate";
import type { VerifiedListingInput } from "@kynesyslabs/dacs/negotiate";
import type { AttestationRef, IdentityBundle, Listing } from "@kynesyslabs/dacs/artifacts";
import { createInMemoryWalletSpendStateStore, createWalletSpendAuthorityV1 } from "@kynesyslabs/dacs/rails";
import type { PayDemRail } from "@kynesyslabs/dacs/rails";
import type { SettleResult } from "@kynesyslabs/dacs";
import {
  CANONICAL_PROFILE_ID,
  commitNegotiatedAgreement,
  createBuyerCeilingGuard,
  createBuyerNegotiationService,
  createChannelSignatureAdapter,
  createCommitmentSignatureVerifier,
  createInMemoryFinalityProvider,
  createRfqHttpTransport,
  createRfqInboxStore,
  createSellerDaemon,
  createSellerRulePolicy,
  createSessionIndex,
  demosAddressFromClaim,
  openRoleStores,
  settleWithPayDem,
  startBuyerMcpServer,
  startRfqTransportServer,
  startShowcaseServer,
  staticMemberAuthority,
  keyObjectSigner,
} from "../src/index.js";
import type { ChannelMessageSignatureV1 } from "../src/index.js";

const NOW = 1_780_000_000_000;
const buyerKeys = generateKeyPairSync("ed25519");
const sellerKeys = generateKeyPairSync("ed25519");
// Canonical Demos agent claims carry the raw Ed25519 key, so the pay-dem payee resolves.
const BUYER = `did:demos:agent:${Buffer.from(rawPublicKey(buyerKeys.publicKey)).toString("hex")}`;
const SELLER = `did:demos:agent:${Buffer.from(rawPublicKey(sellerKeys.publicKey)).toString("hex")}`;
const peers = new Map<string, Uint8Array>([[BUYER, rawPublicKey(buyerKeys.publicKey)], [SELLER, rawPublicKey(sellerKeys.publicKey)]]);
const publicKeys = new Map<string, KeyObject>([[BUYER, buyerKeys.publicKey], [SELLER, sellerKeys.publicKey]]);
const authority = staticMemberAuthority(peers);

function identity(claim: string): IdentityBundle {
  return { bundleVersion: "1", presentedBy: claim, presentedAt: NOW - 1_000, claims: [{ ref: claim }],
    presentation: { kind: "per-claim", signatures: [{ ref: claim, signature: "identity-proof" }] } };
}
function vetRef(locator: string): AttestationRef {
  return { anchor: { kind: "storage-program", locator }, contentHash: "a".repeat(64) };
}
const buyerParty = { identityBundle: identity(BUYER), vetRecordRef: vetRef("stor:buyer-vet") };
const sellerParty = { identityBundle: identity(SELLER), vetRecordRef: vetRef("stor:seller-vet") };

function listing(): Listing {
  return {
    dacsVersion: "1", listingVersion: 1, listingId: "showcase-private-quote", requiredCapabilities: ["SR-2", "SR-4"],
    seller: { identity: identity(SELLER), displayName: "Showcase seller", publicEndpoint: "https://seller.example/dacs" },
    offering: { title: "Private market data quote", description: "One attested JSON payload, price negotiated privately", category: "data.finance", tags: ["rfq"],
      deliverable: { kind: "attested-payload", payloadFormat: "application/json", verificationMethod: { kind: "self-signed" } } },
    buyerRequirement: { requirementVersion: "1", required: [] },
    pipeline: [{ kind: "negotiate-rfq", parameters: { maxTurns: 6, timeoutSec: 60 } }, { kind: "commit-agreement" }, { kind: "deliver-attested-payload" }],
    pricing: { kind: "negotiable", bandCenter: { amount: "10", currency: "DEM" }, minPct: 20, maxPct: 20 },
    terms: { deadlineSecAfterCommit: 600 },
    validity: { notBefore: NOW - 10_000, notAfter: NOW + 1_000_000 },
    signature: { algorithm: "ed25519", signer: SELLER, value: Buffer.alloc(64, 7).toString("base64url") },
  } as Listing;
}
function verified(): VerifiedListingInput {
  const value = listing();
  return { disposition: "verified", listing: value, pin: { listingId: value.listingId, version: value.listingVersion, contentHash: contentHash(value as unknown as Record<string, unknown>) } };
}
function agreementSigner(party: string, privateKey: KeyObject) {
  return { party, algorithm: "ed25519" as const, sign: (bytes: Uint8Array) => ed25519Sign(bytes, privateKey) };
}
function verifyAgreement(input: { party: string; value: string; signedBytes: Uint8Array }) {
  const key = publicKeys.get(input.party);
  return key !== undefined && ed25519Verify(input.signedBytes, Buffer.from(input.value, "base64url"), key) ? ("valid" as const) : ("invalid" as const);
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => { for (const fn of cleanups.splice(0).reverse()) await fn(); });

async function role(roleName: "buyer" | "seller", base: string, peerEndpoint: () => string) {
  const claim = roleName === "buyer" ? BUYER : SELLER;
  const keys = roleName === "buyer" ? buyerKeys : sellerKeys;
  const stores = await openRoleStores<ChannelMessageSignatureV1>({ role: roleName, root: join(base, roleName), integrityKeyPath: join(base, "keys", `${roleName}.key`), createIntegrityKey: true });
  const inbox = createRfqInboxStore({ path: stores.transportDbPath });
  const sessions = createSessionIndex({ path: join(base, roleName, "sessions.db") });
  const server = await startRfqTransportServer({ self: keyObjectSigner(claim, keys.privateKey), peers, inbox });
  const counterpart = roleName === "buyer" ? SELLER : BUYER;
  const transport = createRfqHttpTransport<ChannelMessageSignatureV1>({
    self: keyObjectSigner(claim, keys.privateKey), peers, endpoints: new Map([[counterpart, "lazy"]]),
    fetch: (input, init) => fetch(input === "lazy" ? peerEndpoint() : input, init), requestTimeoutMs: 2_000,
  });
  const signature = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(claim, keys.privateKey), authority });
  const client = createDurableRfqLifecycleClient<ChannelMessageSignatureV1>({
    role: roleName, store: stores.lifecycle, transport, reserveChannelId: (input) => stores.reservation.reserve(input),
    signChannelMessage: signature.signChannelMessage, verifyChannelMessage: signature.verifyChannelMessage,
    agreementSigner: agreementSigner(claim, keys.privateKey), verifyAgreementContribution: verifyAgreement, nowMs: () => NOW,
  });
  cleanups.push(async () => { await server.close(); inbox.close(); sessions.close(); stores.close(); });
  return { claim, keys, stores, inbox, sessions, server, transport, client };
}

describe("showcase: ChatGPT-style buyer via MCP against an independent seller", () => {
  test("negotiates privately, commits a hash, pays, and leaks no offer content on chain", async () => {
    const base = mkdtempSync(join(tmpdir(), "dacs-rfq-showcase-"));
    cleanups.push(() => rmSync(base, { recursive: true, force: true }));
    let sellerEndpoint = "";
    let buyerEndpoint = "";
    const seller = await role("seller", base, () => buyerEndpoint);
    const buyer = await role("buyer", base, () => sellerEndpoint);
    sellerEndpoint = seller.server.endpoint;
    buyerEndpoint = buyer.server.endpoint;

    // --- seller: rule policy, floor 9.5 DEM, listing published in its catalog
    const daemon = createSellerDaemon({
      sellerClaim: SELLER, sellerParty, listings: () => [verified()], client: seller.client, inbox: seller.inbox, sessions: seller.sessions,
      policy: createSellerRulePolicy({ floor: { amount: "9.5", currency: "DEM" } }), nowMs: () => NOW,
    });

    // --- buyer: ceiling 9.8 DEM, in-memory finality provider, fake DEM rail behind the real spend authority
    const finality = createInMemoryFinalityProvider({ writer: BUYER, nowMs: () => NOW + 5_000 });
    const verifySignature = createCommitmentSignatureVerifier(authority.resolve);
    const railCalls: Array<{ recipient: string; amount: string }> = [];
    const rail: PayDemRail = {
      address: demosAddressFromClaim(BUYER)!,
      async settle(params) {
        await params.assertCurrentBeforeBroadcast?.();
        railCalls.push({ recipient: params.recipient, amount: params.amount });
        return { ok: true, txHash: randomBytes(32).toString("hex"), chainId: "demos:testnet", payer: demosAddressFromClaim(BUYER)!, payee: params.recipient, finality: { model: "bft-final" } } as SettleResult;
      },
    };
    const spend = createWalletSpendAuthorityV1({
      policyVersion: "1", policyId: "showcase-buyer", wallet: demosAddressFromClaim(BUYER)!, chainId: "demos:testnet",
      maximumConcurrentEffects: 1, maximumRetainedReservations: 100,
      assets: [{ asset: "DEM", maximumPerOrderDebit: "20000000000", maximumNetworkFeeDebit: "1000000000", minimumReserve: "0",
        rollingWindowMs: 3_600_000, maximumRollingEffects: 10, maximumRollingDebit: "100000000000", maximumCumulativeDebit: "1000000000000", maximumCounterpartyDebit: "100000000000" }],
    }, {
      store: createInMemoryWalletSpendStateStore(),
      readBalance: async () => "1000000000000",
      authenticateRecovery: async () => true,
      now: () => NOW + 6_000,
    });
    const service = createBuyerNegotiationService<ChannelMessageSignatureV1>({
      buyerClaim: BUYER, buyerParty, client: buyer.client, transport: buyer.transport, inbox: buyer.inbox, sessions: buyer.sessions,
      catalog: () => [{ verifiedListing: verified(), sellerVetRecordRef: sellerParty.vetRecordRef, sellerClaim: SELLER }],
      ceiling: createBuyerCeilingGuard({ amount: "9.8", currency: "DEM" }),
      commit: (record, verifiedListing) => commitNegotiatedAgreement({
        record, verifiedListing, orchestrator: BUYER, provider: finality, verifySignature, nowMs: () => NOW + 4_000,
        commitmentSigner: { algorithm: "ed25519", signer: BUYER, sign: (bytes: Uint8Array) => ed25519Sign(bytes, buyerKeys.privateKey) },
      }),
      settle: (record, commitment) => settleWithPayDem({ rail, authority: spend, agreement: record.agreement!.finalized!, commitment, maximumNetworkFeeOs: "1000000000", nowMs: () => NOW + 6_000 }),
      nowMs: () => NOW,
    });
    const token = randomBytes(32).toString("base64url");
    const mcp = await startBuyerMcpServer({ service, bearerToken: token });
    cleanups.push(() => mcp.close());

    // --- the "model": only ever speaks MCP
    let nextId = 1;
    const rpc = async (method: string, params?: unknown) => {
      const response = await fetch(mcp.endpoint, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }) });
      expect(response.status).toBe(200);
      return response.json() as Promise<{ result?: { structuredContent?: unknown; isError?: boolean; content?: Array<{ text: string }>; tools?: unknown[] }; error?: unknown }>;
    };
    const call = async <T,>(name: string, args: Record<string, unknown>): Promise<T> => {
      const reply = await rpc("tools/call", { name, arguments: args });
      expect(reply.error, JSON.stringify(reply)).toBeUndefined();
      if (reply.result?.isError) throw new Error(reply.result.content?.[0]?.text ?? "tool error");
      return reply.result!.structuredContent as T;
    };

    expect((await fetch(mcp.endpoint, { method: "POST", body: "{}" })).status).toBe(401); // no token
    const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
    expect(init.result).toMatchObject({ protocolVersion: "2025-06-18" });
    const tools = await rpc("tools/list");
    expect((tools.result!.tools as Array<{ name: string }>).map((t) => t.name)).toEqual([
      "find_listing", "open_negotiation", "get_negotiation_state", "make_offer", "counter_offer", "accept", "reject", "get_receipts",
    ]);

    const listings = await call<Array<{ listingId: string; pricing: { bandCenter: string } }>>("find_listing", { query: "market data" });
    expect(listings).toHaveLength(1);
    const opened = await call<{ jobId: string; phase: string; priceBand: { minimum: string; maximum: string }; yourTurn: boolean }>("open_negotiation", { listingId: listings[0]!.listingId });
    expect(opened.priceBand).toEqual({ minimum: "8", maximum: "12", currency: "DEM" });
    expect(opened.yourTurn).toBe(true);
    const jobId = opened.jobId;

    // Free text and out-of-ceiling amounts are refused before anything is signed.
    await expect(call("make_offer", { jobId, amount: "about nine" })).rejects.toThrow(/amount is invalid/);
    await expect(call("make_offer", { jobId, amount: "11" })).rejects.toThrow(/ceiling/);
    // Inside the ceiling but outside the band: the SDK refuses it as a normal tool error.
    await expect(call("make_offer", { jobId, amount: "7" })).rejects.toThrow(/offer-rejected/);

    const afterOffer = await call<{ standingProposal: { amount: string; proposer: string }; yourTurn: boolean }>("make_offer", { jobId, amount: "9" });
    expect(afterOffer.standingProposal).toMatchObject({ amount: "9", proposer: BUYER });
    expect(afterOffer.yourTurn).toBe(false);

    // Seller process: opens the announced session and counters at the midpoint toward its ask.
    const sellerTick1 = await daemon.tick();
    expect(sellerTick1.errors).toEqual([]);
    expect(sellerTick1).toMatchObject({ opened: 1, responded: 1 });

    const countered = await call<{ standingProposal: { amount: string; proposer: string }; yourTurn: boolean; turnsLeft: number }>("get_negotiation_state", { jobId });
    expect(countered.standingProposal).toMatchObject({ amount: "10.5", proposer: SELLER });
    expect(countered.yourTurn).toBe(true);

    // The seller's ask exceeds the ceiling, so accept is refused in code...
    await expect(call("accept", { jobId })).rejects.toThrow(/ceiling/);
    // ...and the model counters instead.
    await call("counter_offer", { jobId, amount: "9.5" });
    const sellerTick2 = await daemon.tick();
    expect(sellerTick2.errors).toEqual([]);
    const accepted = await call<{ status: string; phase: string }>("get_negotiation_state", { jobId });
    expect(accepted.status).toBe("accepted");

    // Buyer starts the agreement (automatic on sync), seller contributes, buyer finalizes, commits and pays.
    await call("get_negotiation_state", { jobId });
    expect((await daemon.tick()).errors).toEqual([]);
    const final = await call<{ phase: string; lastError?: string }>("get_negotiation_state", { jobId });
    expect(final.lastError).toBeUndefined();
    expect(final.phase).toBe("settled");

    const receipts = await call<{ agreementHash: string; commitment: { logicalAddress: string; agreementHash: string; nativeAddress: string }; settlement: { status: string; txHash: string; amountOs: string }; transcriptHashes: string[] }>("get_receipts", { jobId });
    expect(receipts.commitment.logicalAddress).toBe(`dacs3:commit:${jobId}`);
    expect(receipts.commitment.agreementHash).toBe(receipts.agreementHash);
    expect(receipts.settlement).toMatchObject({ status: "settled", amountOs: "9500000000" });
    expect(receipts.transcriptHashes).toHaveLength(4); // offer 9, counter 10.5, counter 9.5, accept
    expect(railCalls).toEqual([{ recipient: demosAddressFromClaim(SELLER), amount: "9500000000" }]);

    // Second settlement attempt is idempotent: still exactly one payment.
    await call("get_receipts", { jobId });
    expect(railCalls).toHaveLength(1);

    // The showcase viewer: the same deal as a procurement-event stream in the DACS Directory's /try contract.
    const showcase = await startShowcaseServer({ client: buyer.client, sessions: buyer.sessions, buyerClaim: BUYER, sellerDisplayName: "Seller", lastErrorFor: (id) => service.lastError(id) });
    cleanups.push(() => showcase.close());
    const page = await fetch(showcase.endpoint);
    expect(page.headers.get("content-type")).toContain("text/html");
    const list = await (await fetch(`${showcase.endpoint}demo/procurement`)).json() as Array<{ id: string; status: string }>;
    expect(list).toEqual([{ id: jobId, status: "complete", phase: "complete", openedAt: expect.any(String) }]);
    const job = await (await fetch(`${showcase.endpoint}demo/procurement/${jobId}`)).json() as { status: string; events: Array<{ phase: string; label: string; txRef?: string; anchorRef?: string }> };
    expect(job.status).toBe("complete");
    const labels = job.events.map((e) => e.label);
    expect(labels.some((l) => /Buyer offered 9 DEM/.test(l))).toBe(true);
    expect(labels.some((l) => /Seller countered 10.5 DEM/.test(l))).toBe(true);
    expect(labels.some((l) => /agreed at 9.5 DEM/.test(l))).toBe(true);
    expect(job.events.find((e) => /Commitment anchored/.test(e.label))?.anchorRef).toBe(receipts.commitment.nativeAddress);
    expect(job.events.find((e) => /Payment broadcast/.test(e.label))?.txRef).toBe(receipts.settlement.txHash);
    expect(job.events.every((e) => ["queued","connecting","discovering","selecting","agreeing","settling","complete"].includes(e.phase))).toBe(true);
    expect((await fetch(`${showcase.endpoint}demo/procurement/options`)).status).toBe(200);
    expect((await fetch(`${showcase.endpoint}demo/procurement/01J8ME0SXKQ4T9V2RC5HJ6WX7E`)).status).toBe(404);

    // What a reviewer sees "on chain": the commitment record only. No offer or counter content.
    const onChain = [...finality.anchored.values()].map((a) => canonicalize(a.record as Record<string, unknown>)).join("\n");
    expect(onChain).toContain(receipts.agreementHash);
    for (const amount of ["\"9\"", "\"10.5\"", "\"9.5\"", "amount", "price", "offer", "counter"]) {
      expect(onChain, `on-chain record contains ${amount}`).not.toContain(amount);
    }
    expect(onChain).not.toContain(receipts.transcriptHashes[0]);
  });
});
