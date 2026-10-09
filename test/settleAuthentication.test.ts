import { describe, expect, test } from "vitest";
import { createPayDemSettlementAuthenticator, rememberSettlementEvidence } from "../src/settle.js";

const PAYER = "c0".repeat(32);
const PAYEE = "70".repeat(32);
const TX = "ab".repeat(32);

function confirmedTx(overrides: Record<string, unknown> = {}, content: Record<string, unknown> = {}) {
  return { response: { status: "confirmed", hash: TX, blockNumber: 480877, content: { from: `0x${PAYER}`, to: `0x${PAYEE}`, amount: "9500000000", data: ["native", { nativeOperation: "send", args: [PAYEE, "9500000000"] }], ...content }, ...overrides } };
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

  test("the amount must match in `amount` and, when present, in the native-send args; both must name the payee", async () => {
    rememberSettlementEvidence("ev-3", { txHash: TX, amountOs: "9500000000", payee: `0x${PAYEE}` });
    const make = (tx: () => Promise<unknown>) => createPayDemSettlementAuthenticator({ reader: { getTxByHash: tx }, payerAddressHex: PAYER });
    const settled = { disposition: "settled" as const, evidenceHash: "ev-3" };
    // `amount` right, args wrong (other amount / other payee): refused.
    expect(await make(async () => confirmedTx({}, { data: ["native", { nativeOperation: "send", args: [PAYEE, "9400000000"] }] }))({}, settled)).toBe(false);
    expect(await make(async () => confirmedTx({}, { data: ["native", { nativeOperation: "send", args: ["11".repeat(32), "9500000000"] }] }))({}, settled)).toBe(false);
    // args right, `amount` wrong: refused (an OR between the two used to pass this).
    expect(await make(async () => confirmedTx({}, { amount: "1" }))({}, settled)).toBe(false);
    expect(await make(async () => confirmedTx({}, { amount: 0 }))({}, settled)).toBe(false);
    // no args at all, `amount` right: accepted.
    expect(await make(async () => confirmedTx({}, { data: ["native", { nativeOperation: "send" }] }))({}, settled)).toBe(true);
  });

  test("terminal absence is authenticated only by this wallet's failed transfer for this payee and amount", async () => {
    rememberSettlementEvidence("ev-4", { txHash: TX, amountOs: "9500000000", payee: `0x${PAYEE}` });
    const make = (tx: () => Promise<unknown>) => createPayDemSettlementAuthenticator({ reader: { getTxByHash: tx }, payerAddressHex: PAYER });
    const absent = { disposition: "terminal-absent" as const, evidenceHash: "ev-4" };
    expect(await make(async () => confirmedTx({ status: "failed" }))({}, absent)).toBe(true);
    expect(await make(async () => confirmedTx({ status: "failed" }, { to: `0x${"11".repeat(32)}`, data: ["native", { nativeOperation: "send", args: ["11".repeat(32), "9500000000"] }] }))({}, absent)).toBe(false);
    expect(await make(async () => confirmedTx({ status: "failed" }, { amount: "9400000000", data: ["native", { nativeOperation: "send", args: [PAYEE, "9400000000"] }] }))({}, absent)).toBe(false);
    expect(await make(async () => confirmedTx({ status: "failed", blockNumber: undefined }))({}, absent)).toBe(false);
  });
});
