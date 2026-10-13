import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { rawPublicKey } from "@kynesyslabs/dacs/crypto";
import type { RfqLifecyclePacket } from "@kynesyslabs/dacs/negotiate";
import { keyObjectSigner } from "../src/signer.js";
import { createRfqInboxStore } from "../src/transport/inboxStore.js";
import { createL2psInboxFeeder, createL2psTransport, L2PS_CARRIER_VERSION } from "../src/transport/l2ps.js";
import type { L2psCarrierClient, L2psHistoryEntry } from "../src/transport/l2ps.js";

const BUYER = "did:demos:agent:" + "c0".repeat(32);
const SELLER = "did:demos:agent:" + "70".repeat(32);
const BUYER_ADDR = "0x" + "c0".repeat(32);
const SELLER_ADDR = "0x" + "70".repeat(32);
const buyerKeys = generateKeyPairSync("ed25519");
const sellerKeys = generateKeyPairSync("ed25519");
const peers = new Map<string, Uint8Array>([[BUYER, rawPublicKey(buyerKeys.publicKey)], [SELLER, rawPublicKey(sellerKeys.publicKey)]]);
const addresses = new Map([[BUYER, BUYER_ADDR], [SELLER, SELLER_ADDR]]);

/** In-memory subnet: every send becomes a history row visible to sender and recipient; status advances on `tick`. */
function fakeSubnet(initialStatus = "pending") {
  const rows: Array<L2psHistoryEntry & { carrier: unknown }> = [];
  let n = 0;
  const clientFor = (address: string, opts: { failSends?: boolean; throwHistory?: boolean } = {}): L2psCarrierClient => ({
    address: () => address,
    async send({ to, carrier }) {
      if (opts.failSends) throw new Error("node unreachable");
      n += 1;
      const hash = `inner-${n}`;
      rows.unshift({ hash, from: address, to, status: initialStatus, timestamp: Date.now() + n, content: { data: ["native", { nativeOperation: "send", args: [to, 1], rfq: carrier }] }, carrier });
      return { innerHash: hash };
    },
    async history({ limit = 100 } = {}) {
      if (opts.throwHistory) throw new Error("history unavailable");
      return rows.filter((r) => r.from === address || r.to === address).slice(0, limit).map(({ carrier: _c, ...r }) => structuredClone(r));
    },
  });
  return { rows, clientFor, setStatus: (hash: string, status: string) => { const r = rows.find((x) => x.hash === hash); if (r) r.status = status; } };
}

function packet(id: string, overrides: Partial<Record<string, unknown>> = {}): RfqLifecyclePacket<string> {
  return { packetVersion: "1", packetId: id, jobId: "01M4DZJS6XXKHB721MSRVVT1RQ", channelId: "chan-1", sender: BUYER, recipient: SELLER, kind: "turn",
    message: { canonicalChannelMessageVersion: "1", channelId: "chan-1", sequence: 1, sender: BUYER, sentAt: 1, type: "offer", body: { rfqBodyVersion: "1", proposal: { rfqProposalVersion: "1", price: { amount: "9", currency: "DEM" } } }, signature: "sig" }, ...overrides } as never;
}

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

describe("L2PS carrier transport", () => {
  test("acknowledges only at the configured status, feeds the recipient's inbox once, and reconciles exactly", async () => {
    const subnet = fakeSubnet("pending");
    const buyerClient = subnet.clientFor(BUYER_ADDR);
    const buyer = createL2psTransport<string>({ self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers, addresses, client: buyerClient, ackStatus: "confirmed", ackTimeoutMs: 400, pollIntervalMs: 20 });
    const p = packet("pkt-1");
    // Below threshold at deadline: indeterminate, never acknowledged.
    const pending = buyer.publish(p);
    await new Promise((r) => setTimeout(r, 60));
    expect(subnet.rows[0]?.status).toBe("pending");
    expect(await pending).toMatchObject({ disposition: "indeterminate" });
    expect(await buyer.reconcile(p)).toMatchObject({ disposition: "indeterminate" });
    // Node batches then confirms: reconcile turns acknowledged without resending.
    subnet.setStatus(subnet.rows[0]!.hash, "batched");
    expect(await buyer.reconcile(p)).toMatchObject({ disposition: "indeterminate" });
    subnet.setStatus(subnet.rows[0]!.hash, "confirmed");
    expect(await buyer.reconcile(p)).toEqual({ disposition: "acknowledged" });
    expect(subnet.rows).toHaveLength(1);
    // Different bytes under the same packetId are not the acknowledged packet.
    expect(await buyer.reconcile(packet("pkt-1", { channelId: "chan-2" }))).toEqual({ disposition: "absent" });
    expect(await buyer.reconcile(packet("pkt-never"))).toEqual({ disposition: "absent" });

    // Seller side: the feeder admits the carrier into a real inbox exactly once.
    const dir = mkdtempSync(join(tmpdir(), "l2ps-inbox-")); dirs.push(dir);
    const inbox = createRfqInboxStore({ path: join(dir, "inbox.db") });
    const feeder = createL2psInboxFeeder({ self: keyObjectSigner(SELLER, sellerKeys.privateKey), peers, client: subnet.clientFor(SELLER_ADDR), inbox });
    expect(await feeder.poll()).toEqual({ stored: 1, duplicates: 0, rejected: 0 });
    expect(await feeder.poll()).toEqual({ stored: 0, duplicates: 0, rejected: 0 });
    const rows = inbox.nextUnprocessed(10);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.packetId).toBe("pkt-1");
    expect(rows[0]!.sender).toBe(BUYER);
    // A fresh feeder (restart) sees the same chain row as a duplicate, not a second packet.
    const again = createL2psInboxFeeder({ self: keyObjectSigner(SELLER, sellerKeys.privateKey), peers, client: subnet.clientFor(SELLER_ADDR), inbox });
    expect(await again.poll()).toEqual({ stored: 0, duplicates: 1, rejected: 0 });
    inbox.close();
  });

  test("acknowledges immediately when the node reports the status, rejects a failed execution, and never acknowledges on a send error", async () => {
    const subnet = fakeSubnet("confirmed");
    const buyer = createL2psTransport<string>({ self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers, addresses, client: subnet.clientFor(BUYER_ADDR), pollIntervalMs: 10, ackTimeoutMs: 300 });
    expect(await buyer.publish(packet("pkt-ok"))).toEqual({ disposition: "acknowledged" });
    const failing = fakeSubnet("failed");
    const buyer2 = createL2psTransport<string>({ self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers, addresses, client: failing.clientFor(BUYER_ADDR), pollIntervalMs: 10, ackTimeoutMs: 300 });
    expect(await buyer2.publish(packet("pkt-failed"))).toMatchObject({ disposition: "rejected" });
    expect(await buyer2.reconcile(packet("pkt-failed"))).toEqual({ disposition: "absent" });
    const down = createL2psTransport<string>({ self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers, addresses, client: subnet.clientFor(BUYER_ADDR, { failSends: true }), pollIntervalMs: 10, ackTimeoutMs: 300 });
    expect(await down.publish(packet("pkt-down"))).toMatchObject({ disposition: "indeterminate" });
    const blind = createL2psTransport<string>({ self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers, addresses, client: subnet.clientFor(BUYER_ADDR, { throwHistory: true }), pollIntervalMs: 10, ackTimeoutMs: 300 });
    expect(await blind.reconcile(packet("pkt-ok"))).toMatchObject({ disposition: "indeterminate" });
    expect(await buyer.publish(packet("pkt-x", { recipient: "did:demos:agent:" + "99".repeat(32) }))).toMatchObject({ disposition: "rejected" });
  });

  test("the feeder refuses carriers that fail envelope authentication or packet shape and skips failed rows", async () => {
    const subnet = fakeSubnet("confirmed");
    const stranger = generateKeyPairSync("ed25519");
    const forged = createL2psTransport<string>({ self: keyObjectSigner(BUYER, stranger.privateKey), peers, addresses, client: subnet.clientFor(BUYER_ADDR), pollIntervalMs: 10, ackTimeoutMs: 200 });
    await forged.publish(packet("pkt-forged"));
    const honest = createL2psTransport<string>({ self: keyObjectSigner(BUYER, buyerKeys.privateKey), peers, addresses, client: subnet.clientFor(BUYER_ADDR), pollIntervalMs: 10, ackTimeoutMs: 200 });
    await honest.publish(packet("pkt-wrong-recipient-field", { recipient: SELLER, sender: SELLER }));
    await honest.publish(packet("pkt-good"));
    subnet.rows.unshift({ hash: "junk", from: BUYER_ADDR, to: SELLER_ADDR, status: "confirmed", timestamp: Date.now(), content: { data: ["native", { nativeOperation: "send", args: [SELLER_ADDR, 1] }] } } as never);
    subnet.rows.unshift({ ...structuredClone(subnet.rows.find((r) => r.hash === "inner-3")!), hash: "inner-3-failed", status: "failed" });
    const dir = mkdtempSync(join(tmpdir(), "l2ps-inbox-")); dirs.push(dir);
    const inbox = createRfqInboxStore({ path: join(dir, "inbox.db") });
    const feeder = createL2psInboxFeeder({ self: keyObjectSigner(SELLER, sellerKeys.privateKey), peers, client: subnet.clientFor(SELLER_ADDR), inbox });
    expect(await feeder.poll()).toEqual({ stored: 1, duplicates: 0, rejected: 2 });
    expect(inbox.nextUnprocessed(10).map((r) => r.packetId)).toEqual(["pkt-good"]);
    inbox.close();
    expect(L2PS_CARRIER_VERSION).toBe("colony-rfq-l2ps:v0");
  });
});
