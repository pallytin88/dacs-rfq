import { keyObjectSigner } from "../src/signer.js";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { rawPublicKey } from "@kynesyslabs/dacs/crypto";
import type { RfqLifecyclePacket } from "@kynesyslabs/dacs/negotiate";
import {
  createEnvelope,
  createRfqHttpTransport,
  createRfqInboxStore,
  packetHashHex,
  startRfqTransportServer,
  verifyEnvelope,
} from "../src/transport/index.js";
import type { RfqTransportServer, RfqInboxStore } from "../src/transport/index.js";

const BUYER = "did:demos:buyer-transport";
const SELLER = "did:demos:seller-transport";
const buyerKeys = generateKeyPairSync("ed25519");
const sellerKeys = generateKeyPairSync("ed25519");
const strangerKeys = generateKeyPairSync("ed25519");
const peers = new Map<string, Uint8Array>([
  [BUYER, rawPublicKey(buyerKeys.publicKey)],
  [SELLER, rawPublicKey(sellerKeys.publicKey)],
]);

const dirs: string[] = [];
const servers: RfqTransportServer[] = [];
const stores: RfqInboxStore[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) await server.close();
  for (const store of stores.splice(0)) store.close();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function packet(id: string, overrides: Partial<Record<string, unknown>> = {}): RfqLifecyclePacket<string> {
  return {
    packetVersion: "1",
    packetId: id,
    jobId: "01J8ME0SXKQ4T9V2RC5HJ6WX7E",
    channelId: "chan-transport",
    sender: BUYER,
    recipient: SELLER,
    kind: "turn",
    message: {
      channelId: "chan-transport",
      sequence: 1,
      sender: BUYER,
      sentAt: 1_780_000_000_000,
      type: "offer",
      body: { rfqBodyVersion: "1", proposal: { rfqProposalVersion: "1", price: { amount: "10", currency: "DEM" } } },
      signature: "sig",
    },
    ...overrides,
  } as unknown as RfqLifecyclePacket<string>;
}

async function sellerSide(opts: { onPacketStored?: (id: string) => void } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "dacs-rfq-transport-"));
  dirs.push(dir);
  const inbox = createRfqInboxStore({ path: join(dir, "seller", "transport.db") });
  stores.push(inbox);
  const server = await startRfqTransportServer({
    self: keyObjectSigner(SELLER, sellerKeys.privateKey),
    peers,
    inbox,
    onPacketStored: opts.onPacketStored,
  });
  servers.push(server);
  return { inbox, server };
}

function buyerTransport(endpoint: string, fetchImpl?: typeof fetch) {
  return createRfqHttpTransport<string>({
    self: keyObjectSigner(BUYER, buyerKeys.privateKey),
    peers,
    endpoints: new Map([[SELLER, endpoint]]),
    fetch: fetchImpl,
    requestTimeoutMs: 2_000,
  });
}

describe("interim HTTP transport", () => {
  test("publish is acknowledged only after the receiver persisted the packet", async () => {
    let storedBeforeAck: string | null = null;
    const { inbox, server } = await sellerSide({
      onPacketStored: (id) => { storedBeforeAck = inbox.lookup(id) === null ? "missing" : id; },
    });
    const transport = buyerTransport(server.endpoint);
    const p = packet("pkt-1");
    await expect(transport.publish(p)).resolves.toEqual({ disposition: "acknowledged" });
    expect(storedBeforeAck).toBe("pkt-1");
    expect(inbox.lookup("pkt-1")?.packetHash).toBe(packetHashHex(p as unknown as Record<string, unknown>));
    expect(inbox.nextUnprocessed(10).map((row) => row.packetId)).toEqual(["pkt-1"]);
  });

  test("re-publishing identical bytes is acknowledged; different bytes under the same id are rejected", async () => {
    const { server } = await sellerSide();
    const transport = buyerTransport(server.endpoint);
    await expect(transport.publish(packet("pkt-2"))).resolves.toEqual({ disposition: "acknowledged" });
    await expect(transport.publish(packet("pkt-2"))).resolves.toEqual({ disposition: "acknowledged" });
    const altered = packet("pkt-2", { channelId: "chan-other" });
    const result = await transport.publish(altered);
    expect(result.disposition).toBe("rejected");
  });

  test("reconcile answers present, absent and conflict from the receiver's durable store", async () => {
    const { server } = await sellerSide();
    const transport = buyerTransport(server.endpoint);
    const p = packet("pkt-3");
    await expect(transport.reconcile(p)).resolves.toEqual({ disposition: "absent" });
    await transport.publish(p);
    await expect(transport.reconcile(p)).resolves.toEqual({ disposition: "acknowledged" });
    const conflict = await transport.reconcile(packet("pkt-3", { channelId: "chan-other" }));
    expect(conflict.disposition).toBe("rejected");
  });

  test("an ambiguous publish followed by reconcile resolves without resending different bytes", async () => {
    const { inbox, server } = await sellerSide();
    // The request reaches the server and is stored, but the response is lost.
    const lossy: typeof fetch = async (input, init) => {
      await fetch(input, init);
      throw new Error("socket hang up");
    };
    const transport = buyerTransport(server.endpoint, lossy);
    const p = packet("pkt-4");
    const ambiguous = await transport.publish(p);
    expect(ambiguous.disposition).toBe("indeterminate");
    expect(inbox.lookup("pkt-4")).not.toBeNull();
    const healthy = buyerTransport(server.endpoint);
    await expect(healthy.reconcile(p)).resolves.toEqual({ disposition: "acknowledged" });
  });

  test("an unreachable receiver is indeterminate, never absent", async () => {
    const transport = buyerTransport("http://127.0.0.1:9/colony-rfq/v0/messages");
    const p = packet("pkt-5");
    expect((await transport.publish(p)).disposition).toBe("indeterminate");
    expect((await transport.reconcile(p)).disposition).toBe("indeterminate");
  });

  test("packets with a wrong sender, wrong recipient or unknown kind are rejected by signed acknowledgement", async () => {
    const { server } = await sellerSide();
    const transport = buyerTransport(server.endpoint);
    expect((await transport.publish(packet("pkt-6", { sender: SELLER }))).disposition).toBe("rejected");
    expect((await transport.publish(packet("pkt-7", { kind: "mystery" }))).disposition).toBe("rejected");
    const wrongRecipient = packet("pkt-8", { recipient: "did:demos:nobody" });
    expect((await transport.publish(wrongRecipient)).disposition).toBe("rejected");
  });

  test("tampered, replayed, expired and stranger-signed envelopes are refused before storage", async () => {
    const { inbox, server } = await sellerSide();
    const p = packet("pkt-9") as unknown as Record<string, unknown>;
    const payload = { packet: p, packetHash: packetHashHex(p) };
    const post = (body: unknown) => fetch(server.endpoint, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });

    const good = await createEnvelope({ type: "rfq-packet", audience: SELLER, payload, nowMs: Date.now() },
      keyObjectSigner(BUYER, buyerKeys.privateKey));
    expect((await post({ ...good, payload: { ...payload, packet: { ...p, channelId: "x" } } })).status).toBe(401);
    expect(inbox.lookup("pkt-9")).toBeNull();

    const stranger = await createEnvelope({ type: "rfq-packet", audience: SELLER, payload, nowMs: Date.now() },
      keyObjectSigner(BUYER, strangerKeys.privateKey));
    expect((await post(stranger)).status).toBe(401);

    const expired = await createEnvelope({ type: "rfq-packet", audience: SELLER, payload, nowMs: Date.now() - 600_000 },
      keyObjectSigner(BUYER, buyerKeys.privateKey));
    expect((await post(expired)).status).toBe(401);

    expect((await post(good)).status).toBe(200);
    expect((await post(good)).status).toBe(401); // replayed nonce
    expect(inbox.lookup("pkt-9")).not.toBeNull();
  });

  test("acknowledgements are bound to the request and signed by the recipient", async () => {
    const { server } = await sellerSide();
    const p = packet("pkt-10") as unknown as Record<string, unknown>;
    const payload = { packet: p, packetHash: packetHashHex(p) };
    const envelope = await createEnvelope({ type: "rfq-packet", audience: SELLER, payload, nowMs: Date.now() },
      keyObjectSigner(BUYER, buyerKeys.privateKey));
    const response = await fetch(server.endpoint, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(envelope),
    });
    const ack = await response.json();
    const verified = verifyEnvelope(ack, { expectedAudience: BUYER, peers, nowMs: Date.now(), expectedType: "rfq-ack" });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.envelope.sender).toBe(SELLER);
      expect(verified.envelope.payload).toMatchObject({ inReplyTo: envelope.envelopeId, disposition: "stored", packetId: "pkt-10" });
    }
  });

  test("plain HTTP refuses to bind off loopback", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dacs-rfq-transport-"));
    dirs.push(dir);
    const inbox = createRfqInboxStore({ path: join(dir, "transport.db") });
    stores.push(inbox);
    await expect(startRfqTransportServer({
      self: keyObjectSigner(SELLER, sellerKeys.privateKey), peers, inbox, hostname: "0.0.0.0",
    })).rejects.toThrow(/loopback/);
  });
});
