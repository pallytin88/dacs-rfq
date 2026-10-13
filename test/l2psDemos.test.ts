import { describe, expect, test } from "vitest";
import { L2PS } from "@kynesyslabs/demosdk/l2ps";
import { createDemosL2psClient } from "../src/transport/l2psDemos.js";

const KEY = "11".repeat(32);
const IV = "22".repeat(16);
const UID = "rfq_test_000001";
const hexToBinary = (hex: string) => Buffer.from(hex, "hex").toString("binary");

/** The ciphertext the node stores for one carrier: the whole outer `l2psEncryptedTx` it received. */
async function sealed(uid: string, inner: Record<string, unknown>, keyHex = KEY) {
  const l2ps = await L2PS.create(hexToBinary(keyHex), hexToBinary(IV));
  l2ps.setConfig({ uid, config: { created_at_block: 0, known_rpcs: [] } } as never);
  const encrypted = await l2ps.encryptTx(inner as never) as unknown as { content: { type: string; data: [string, Record<string, unknown>] } };
  return { hash: "ee".repeat(32), status: "confirmed", signature: null, blockNumber: 7, content: encrypted.content };
}
/** The same ciphertext as a bare payload (`data[1]`), which some rows may carry. */
const bare = (outer: { content: { data: [string, Record<string, unknown>] } }) => outer.content.data[1];

function fakeDemos(rows: unknown[]) {
  const sent: string[] = [];
  return {
    sent,
    getAddress: () => "0x" + "c0".repeat(32),
    async getAddressNonce() { return 4; },
    tx: { async prepare() { return { content: {} as Record<string, unknown> }; } },
    async sign(tx: { content: Record<string, unknown> }) { return { ...tx, hash: "ab".repeat(32) }; },
    async confirm() { return { response: { data: { valid: true } } }; },
    async broadcast() { sent.push("broadcast"); return { result: 200 }; },
    async getL2PSHistory() { return { transactions: rows }; },
  };
}

describe("createDemosL2psClient history", () => {
  test("decrypts each row locally from the stored ciphertext and ignores whatever the node says the content is", async () => {
    const carrier = { carrier: "colony-rfq-l2ps:v0", envelope: { packetId: "p-1" } };
    const inner = { hash: "aa".repeat(32), content: { type: "native", data: ["native", { nativeOperation: "send", args: ["70".repeat(32), 1], rfq: carrier }] } };
    const payload = await sealed(UID, inner);
    const rows = [
      // Honest row: ciphertext present, and a node-side `content` that disagrees (must be ignored).
      { hash: inner.hash, from: "0xc0", to: "0x70", status: "confirmed", timestamp: "5", encrypted_payload: payload, content: { data: ["native", { rfq: { carrier: "colony-rfq-l2ps:v0", envelope: { packetId: "FORGED" } } }] } },
      // Bare payload shape: accepted too.
      { hash: inner.hash, from: "0xc0", to: "0x70", status: "confirmed", timestamp: "5", encrypted_payload: bare(payload) },
      // Node offers plaintext only: nothing to verify, so nothing is read.
      { hash: "bb".repeat(32), from: "0xc0", to: "0x70", status: "confirmed", timestamp: "4", encrypted_payload: null, content: { data: ["native", { rfq: carrier }] } },
      // Ciphertext whose decrypted hash is not the row's hash: dropped.
      { hash: "cc".repeat(32), from: "0xc0", to: "0x70", status: "confirmed", timestamp: "3", encrypted_payload: payload },
      // Ciphertext under another key: dropped.
      { hash: inner.hash, from: "0xc0", to: "0x70", status: "confirmed", timestamp: "2", encrypted_payload: await sealed(UID, inner, "33".repeat(32)) },
      // Ciphertext for another subnet: dropped.
      { hash: inner.hash, from: "0xc0", to: "0x70", status: "confirmed", timestamp: "1", encrypted_payload: await sealed("rfq_other", inner) },
    ];
    const events: Record<string, unknown>[] = [];
    const client = await createDemosL2psClient({ demos: fakeDemos(rows) as never, subnet: { uid: UID, keyHex: KEY, ivHex: IV }, rpc: "http://127.0.0.1:1", log: (e) => events.push({ ...e }) });
    const history = await client.history();
    expect(history.map((h) => h.content)).toEqual([inner.content, inner.content, null, null, null, null]);
    expect((history[0]!.content as { data: unknown[] }).data[1]).toMatchObject({ rfq: { envelope: { packetId: "p-1" } } });
    expect(events.filter((e) => e["event"] === "l2ps-history-row-unreadable")).toHaveLength(2);
  });

  test("every send goes through the lock it was given, so a funder sharing the account cannot race it on the nonce", async () => {
    const order: string[] = [];
    let depth = 0;
    const lock = async <T,>(task: () => Promise<T>): Promise<T> => { depth += 1; order.push(`enter${depth}`); try { return await task(); } finally { order.push("leave"); depth -= 1; } };
    const demos = fakeDemos([]);
    const client = await createDemosL2psClient({ demos: demos as never, subnet: { uid: UID, keyHex: KEY, ivHex: IV }, rpc: "http://127.0.0.1:1", lock });
    await client.send({ to: "0x" + "70".repeat(32), carrier: { carrier: "colony-rfq-l2ps:v0", envelope: {} } as never });
    expect(order).toEqual(["enter1", "leave"]);
    expect(demos.sent).toEqual(["broadcast"]);
  });
});
