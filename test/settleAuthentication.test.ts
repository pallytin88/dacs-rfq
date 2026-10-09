import { describe, expect, test } from "vitest";
import { createPayDemSettlementAuthenticator, rememberSettlementEvidence } from "../src/settle.js";

const PAYER = "c0".repeat(32);
const PAYEE = "70".repeat(32);
const TX = "ab".repeat(32);

function confirmedTx(overrides: Record<string, unknown> = {}, content: Record<string, unknown> = {}) {
  return { response: { status: "confirmed", hash: TX, content: { from: `0x${PAYER}`, to: `0x${PAYEE}`, amount: 0, data: ["native", { nativeOperation: "send", args: [PAYEE, "9500000000"] }], ...content }, ...overrides } };
}

describe("createPayDemSettlementAuthenticator", () => {
  test("authenticates a settled observation only against a confirmed matching transfer on chain", async () => {
    rememberSettlementEvidence("ev-1", { txHash: TX, amountOs: "9500000000", payee: `0x${PAYEE}` });
    const calls: string[] = [];
    const reader = { async getTxByHash(hash: string) { calls.push(hash); return confirmedTx(); } };
    const authenticate = createPayDemSettlementAuthenticator({ reader, payerAddressHex: PAYER });
    expect(await authenticate({}, { disposition: "settled", evidenceHash: "ev-1" })).toBe(true);
    expect(calls).toEqual([TX]);
  });

  test("refuses pending, mismatched, unknown and absence observations", async () => {
    rememberSettlementEvidence("ev-2", { txHash: TX, amountOs: "9500000000", payee: `0x${PAYEE}` });
    const make = (tx: () => Promise<unknown>, payer = PAYER) => createPayDemSettlementAuthenticator({ reader: { getTxByHash: tx }, payerAddressHex: payer });
    expect(await make(async () => confirmedTx({ status: "pending" }))({}, { disposition: "settled", evidenceHash: "ev-2" })).toBe(false);
    expect(await make(async () => confirmedTx({}, { to: `0x${"11".repeat(32)}` }))({}, { disposition: "settled", evidenceHash: "ev-2" })).toBe(false);
    expect(await make(async () => confirmedTx({}, { data: ["native", { nativeOperation: "send", args: [PAYEE, "9400000000"] }] }))({}, { disposition: "settled", evidenceHash: "ev-2" })).toBe(false);
    expect(await make(async () => confirmedTx(), "ff".repeat(32))({}, { disposition: "settled", evidenceHash: "ev-2" })).toBe(false);
    expect(await make(async () => confirmedTx())({}, { disposition: "settled", evidenceHash: "never-remembered" })).toBe(false);
    expect(await make(async () => confirmedTx())({}, { disposition: "terminal-absent", evidenceHash: "ev-2" })).toBe(false);
    expect(await make(async () => { throw new Error("rpc down"); })({}, { disposition: "settled", evidenceHash: "ev-2" })).toBe(false);
  });
});
