/**
 * Full private RFQ flow between a buyer and a seller process over the interim
 * HTTP transport, with role-local filesystem lifecycle stores, SQLite channel
 * reservations and the provisional signature profile. Mirrors the SDK's own
 * two-agent lifecycle test, but every hop crosses a socket and every durable
 * boundary is a real file.
 */

import { generateKeyPairSync } from "node:crypto";
import type { KeyObject, KeyPairKeyObjectResult } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { contentHash } from "@kynesyslabs/dacs/canonical";
import { ed25519Sign, ed25519Verify, rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { createDurableRfqLifecycleClient } from "@kynesyslabs/dacs/negotiate";
import type { DurableRfqLifecycleClient, VerifiedListingInput } from "@kynesyslabs/dacs/negotiate";
import type { AttestationRef, IdentityBundle, Listing } from "@kynesyslabs/dacs/artifacts";
import { CANONICAL_PROFILE_ID, createChannelSignatureAdapter, staticMemberAuthority } from "../src/channelSignature.js";
import { keyObjectSigner } from "../src/signer.js";
import type { ChannelMessageSignatureV1 } from "../src/channelSignature.js";
import { openRoleStores } from "../src/roleStores.js";
import type { RoleStores } from "../src/roleStores.js";
import { createRfqHttpTransport, createRfqInboxStore, drainInbox, startRfqTransportServer } from "../src/transport/index.js";
import type { RfqInboxStore, RfqTransportServer } from "../src/transport/index.js";

const NOW = 1_780_000_000_000;
const JOB_ID = "01J8ME0SXKQ4T9V2RC5HJ6WX7E";
const BUYER = "did:demos:buyer-e2e";
const SELLER = "did:demos:seller-e2e";
const buyerKeys = generateKeyPairSync("ed25519");
const sellerKeys = generateKeyPairSync("ed25519");
const peers = new Map<string, Uint8Array>([
  [BUYER, rawPublicKey(buyerKeys.publicKey)],
  [SELLER, rawPublicKey(sellerKeys.publicKey)],
]);
const publicKeys = new Map<string, KeyObject>([[BUYER, buyerKeys.publicKey], [SELLER, sellerKeys.publicKey]]);
const authority = staticMemberAuthority(peers);

function identity(claim: string): IdentityBundle {
  return {
    bundleVersion: "1", presentedBy: claim, presentedAt: NOW - 1_000, claims: [{ ref: claim }],
    presentation: { kind: "per-claim", signatures: [{ ref: claim, signature: "identity-proof" }] },
  };
}
function vetRef(locator: string): AttestationRef {
  return { anchor: { kind: "storage-program", locator }, contentHash: "a".repeat(64) };
}
const buyerParty = { identityBundle: identity(BUYER), vetRecordRef: vetRef("stor:buyer-e2e-vet") };
const sellerParty = { identityBundle: identity(SELLER), vetRecordRef: vetRef("stor:seller-e2e-vet") };

function listing(): Listing {
  return {
    dacsVersion: "1", listingVersion: 3, listingId: "e2e-rfq-listing", requiredCapabilities: ["SR-2", "SR-4"],
    seller: { identity: identity(SELLER), displayName: "E2E seller", publicEndpoint: "https://seller.example/dacs" },
    offering: {
      title: "Private quote", description: "RFQ over the interim transport", category: "data.finance", tags: ["rfq"],
      deliverable: { kind: "attested-payload", payloadFormat: "application/json", verificationMethod: { kind: "self-signed" } },
    },
    buyerRequirement: { requirementVersion: "1", required: [] },
    pipeline: [
      { kind: "negotiate-rfq", parameters: { maxTurns: 5, timeoutSec: 10 } },
      { kind: "commit-agreement" },
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "negotiable", bandCenter: { amount: "10", currency: "USDC" }, minPct: 20, maxPct: 20 },
    terms: { deadlineSecAfterCommit: 600 },
    validity: { notBefore: NOW - 10_000, notAfter: NOW + 1_000_000 },
    signature: { algorithm: "ed25519", signer: SELLER, value: Buffer.alloc(64, 7).toString("base64url") },
  } as Listing;
}
function verified(): VerifiedListingInput {
  const value = listing();
  return {
    disposition: "verified", listing: value,
    pin: { listingId: value.listingId, version: value.listingVersion, contentHash: contentHash(value as unknown as Record<string, unknown>) },
  };
}
function agreementSigner(party: string, privateKey: KeyObject) {
  return { party, algorithm: "ed25519" as const, sign: (bytes: Uint8Array) => ed25519Sign(bytes, privateKey) };
}
function verifyAgreement(input: { party: string; value: string; signedBytes: Uint8Array }) {
  const key = publicKeys.get(input.party);
  return key !== undefined && ed25519Verify(input.signedBytes, Buffer.from(input.value, "base64url"), key)
    ? ("valid" as const) : ("invalid" as const);
}

interface Side {
  role: "buyer" | "seller";
  claim: string;
  keys: KeyPairKeyObjectResult;
  stores: RoleStores<ChannelMessageSignatureV1>;
  inbox: RfqInboxStore;
  server: RfqTransportServer;
  client: DurableRfqLifecycleClient<ChannelMessageSignatureV1>;
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const fn of cleanups.splice(0).reverse()) await fn();
});

async function startSide(role: "buyer" | "seller", root: string, keyPath: string, peerEndpoint: () => string): Promise<Side> {
  const claim = role === "buyer" ? BUYER : SELLER;
  const keys = role === "buyer" ? buyerKeys : sellerKeys;
  const stores = await openRoleStores<ChannelMessageSignatureV1>({ role, root, integrityKeyPath: keyPath, createIntegrityKey: true });
  const inbox = createRfqInboxStore({ path: stores.transportDbPath });
  const server = await startRfqTransportServer({ self: keyObjectSigner(claim, keys.privateKey), peers, inbox, nowMs: () => Date.now() });
  const counterpart = role === "buyer" ? SELLER : BUYER;
  const transport = createRfqHttpTransport<ChannelMessageSignatureV1>({
    self: keyObjectSigner(claim, keys.privateKey), peers,
    endpoints: new Map([[counterpart, "lazy"]]),
    // Resolve the peer endpoint lazily so either side can start first.
    fetch: (input, init) => fetch(input === "lazy" ? peerEndpoint() : input, init),
    requestTimeoutMs: 2_000,
  });
  const signature = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(claim, keys.privateKey), authority });
  const client = createDurableRfqLifecycleClient<ChannelMessageSignatureV1>({
    role, store: stores.lifecycle, transport,
    reserveChannelId: (input) => stores.reservation.reserve(input),
    signChannelMessage: signature.signChannelMessage,
    verifyChannelMessage: signature.verifyChannelMessage,
    agreementSigner: agreementSigner(claim, keys.privateKey),
    verifyAgreementContribution: verifyAgreement,
    nowMs: () => NOW,
  });
  const side: Side = { role, claim, keys, stores, inbox, server, client };
  cleanups.push(async () => { await server.close(); inbox.close(); stores.close(); });
  return side;
}

function openInput() {
  return { jobId: JOB_ID, verifiedListing: verified(), buyer: buyerParty, seller: sellerParty, channelId: "e2e-private-channel-01" };
}

async function drain(side: Side) {
  const summary = await drainInbox({ inbox: side.inbox, client: side.client });
  expect(summary.stoppedAt, JSON.stringify(summary)).toBeUndefined();
  return summary;
}

describe("private RFQ over the interim transport", () => {
  test("offer → counter → accept → co-signed agreement, with real files and sockets", async () => {
    const base = mkdtempSync(join(tmpdir(), "dacs-rfq-e2e-"));
    cleanups.push(() => rmSync(base, { recursive: true, force: true }));
    let sellerEndpoint = "";
    let buyerEndpoint = "";
    const seller = await startSide("seller", join(base, "seller"), join(base, "keys", "seller.key"), () => buyerEndpoint);
    const buyer = await startSide("buyer", join(base, "buyer"), join(base, "keys", "buyer.key"), () => sellerEndpoint);
    sellerEndpoint = seller.server.endpoint;
    buyerEndpoint = buyer.server.endpoint;

    expect(await buyer.client.open(openInput())).toMatchObject({ status: "ready" });
    expect(await seller.client.open(openInput())).toMatchObject({ status: "ready" });

    const offer = await buyer.client.sendOffer(JOB_ID, { rfqProposalVersion: "1", price: { amount: "9", currency: "USDC" } });
    expect(offer, JSON.stringify(offer)).toMatchObject({ status: "ready" });
    expect((await drain(seller)).processed).toBe(1);

    const countered = await seller.client.respond(JOB_ID, () => ({
      action: "counter", proposal: { rfqProposalVersion: "1", price: { amount: "9.5", currency: "USDC" } },
    }));
    expect(countered, JSON.stringify(countered)).toMatchObject({ status: "ready" });
    expect((await drain(buyer)).processed).toBe(1);

    expect(await buyer.client.sendAccept(JOB_ID)).toMatchObject({ status: "ready" });
    expect((await drain(seller)).processed).toBe(1);

    expect(await buyer.client.startAgreement(JOB_ID)).toMatchObject({ status: "ready" });
    expect((await drain(seller)).processed).toBe(1);
    expect((await drain(buyer)).processed).toBe(1);

    const buyerStatus = await buyer.client.getStatus(JOB_ID);
    const sellerStatus = await seller.client.getStatus(JOB_ID);
    expect(buyerStatus.status).toBe("ok");
    expect(sellerStatus.status).toBe("ok");
    if (buyerStatus.status !== "ok" || sellerStatus.status !== "ok") return;
    expect(buyerStatus.record.session.status).toBe("accepted");
    expect(sellerStatus.record.transcript).toEqual(buyerStatus.record.transcript);
    expect(buyerStatus.record.transcript).toHaveLength(3);
    expect(buyerStatus.record.agreement?.finalized?.signatures).toHaveLength(2);
    expect(sellerStatus.record.agreement?.finalized).toEqual(buyerStatus.record.agreement?.finalized);
    expect(buyerStatus.record.agreement?.finalized?.derivedFromChannel).toMatchObject({
      subnet: "e2e-private-channel-01", lastMessageHash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });

    // Replaying an already-drained packet is a harmless duplicate, not a new turn.
    expect(await drain(seller)).toMatchObject({ processed: 0, rejected: 0 });
    expect(seller.stores.reservation.lookup("e2e-private-channel-01")).not.toBeNull();
  });

  test("a counter outside the Listing band is rejected before it is sent", async () => {
    const base = mkdtempSync(join(tmpdir(), "dacs-rfq-e2e-"));
    cleanups.push(() => rmSync(base, { recursive: true, force: true }));
    let sellerEndpoint = "";
    let buyerEndpoint = "";
    const seller = await startSide("seller", join(base, "seller"), join(base, "keys", "seller.key"), () => buyerEndpoint);
    const buyer = await startSide("buyer", join(base, "buyer"), join(base, "keys", "buyer.key"), () => sellerEndpoint);
    sellerEndpoint = seller.server.endpoint;
    buyerEndpoint = buyer.server.endpoint;
    await buyer.client.open(openInput());
    await seller.client.open(openInput());
    await buyer.client.sendOffer(JOB_ID, { rfqProposalVersion: "1", price: { amount: "9", currency: "USDC" } });
    await drain(seller);
    const outOfBand = await seller.client.respond(JOB_ID, () => ({
      action: "counter", proposal: { rfqProposalVersion: "1", price: { amount: "100", currency: "USDC" } },
    }));
    expect(outOfBand.status).toBe("rejected");
    expect(buyer.inbox.nextUnprocessed(10)).toHaveLength(0);
  });

  test("restart after a lost acknowledgement resends the identical packet once", async () => {
    const base = mkdtempSync(join(tmpdir(), "dacs-rfq-e2e-"));
    cleanups.push(() => rmSync(base, { recursive: true, force: true }));
    let sellerEndpoint = "";
    let buyerEndpoint = "";
    const seller = await startSide("seller", join(base, "seller"), join(base, "keys", "seller.key"), () => buyerEndpoint);
    sellerEndpoint = seller.server.endpoint;

    // First buyer process: its transport loses every response after the server stored the packet.
    const buyerRoot = join(base, "buyer");
    const buyerKey = join(base, "keys", "buyer.key");
    const stores1 = await openRoleStores<ChannelMessageSignatureV1>({ role: "buyer", root: buyerRoot, integrityKeyPath: buyerKey, createIntegrityKey: true });
    const lossy = createRfqHttpTransport<ChannelMessageSignatureV1>({
      self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers,
      endpoints: new Map([[SELLER, sellerEndpoint]]),
      fetch: async (input, init) => { await fetch(input, init); throw new Error("socket hang up"); },
    });
    const sig = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(BUYER, buyerKeys.privateKey), authority });
    const options = {
      role: "buyer" as const, store: stores1.lifecycle,
      reserveChannelId: (input: Parameters<typeof stores1.reservation.reserve>[0]) => stores1.reservation.reserve(input),
      signChannelMessage: sig.signChannelMessage, verifyChannelMessage: sig.verifyChannelMessage,
      agreementSigner: agreementSigner(BUYER, buyerKeys.privateKey), verifyAgreementContribution: verifyAgreement,
      nowMs: () => NOW,
    };
    const crashed = createDurableRfqLifecycleClient<ChannelMessageSignatureV1>({ ...options, transport: lossy });
    await seller.client.open(openInput());
    expect(await crashed.open(openInput())).toMatchObject({ status: "ready" });
    const sent = await crashed.sendOffer(JOB_ID, { rfqProposalVersion: "1", price: { amount: "9", currency: "USDC" } });
    expect(sent.status).toBe("indeterminate");
    expect(seller.inbox.nextUnprocessed(10)).toHaveLength(1); // stored on the seller despite the lost ack
    stores1.close();

    // Restarted buyer process: same directory, same key, healthy transport.
    const stores2 = await openRoleStores<ChannelMessageSignatureV1>({ role: "buyer", root: buyerRoot, integrityKeyPath: buyerKey });
    cleanups.push(() => stores2.close());
    const healthy = createRfqHttpTransport<ChannelMessageSignatureV1>({
      self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers, endpoints: new Map([[SELLER, sellerEndpoint]]),
    });
    const restarted = createDurableRfqLifecycleClient<ChannelMessageSignatureV1>({
      ...options, store: stores2.lifecycle, transport: healthy,
      reserveChannelId: (input) => stores2.reservation.reserve(input),
    });
    expect(await restarted.resumeOutbox(JOB_ID)).toMatchObject({ status: "ready" });
    // Reconcile found the packet present; nothing was duplicated on the seller.
    expect(seller.inbox.nextUnprocessed(10)).toHaveLength(1);
    expect((await drain(seller)).processed).toBe(1);
    const status = await seller.client.getStatus(JOB_ID);
    expect(status.status).toBe("ok");
    if (status.status === "ok") expect(status.record.session.lastSequence).toBe(1);
  });
});
