import { describe, expect, test } from "vitest";
import { createSerialLock } from "../src/walletLock.js";
import { isTerminallyFailedTransfer, reconcileFailedPayDemTransfer, rememberSettlementEvidence } from "../src/settle.js";

describe("createSerialLock", () => {
  test("runs wallet writes strictly one after another, including after a failure", async () => {
    const lock = createSerialLock();
    const order: string[] = [];
    const slow = lock(async () => { order.push("a-start"); await new Promise((r) => setTimeout(r, 20)); order.push("a-end"); return "a"; });
    const failing = lock(async () => { order.push("b"); throw new Error("boom"); });
    const last = lock(async () => { order.push("c"); return "c"; });
    expect(await slow).toBe("a");
    await expect(failing).rejects.toThrow("boom");
    expect(await last).toBe("c");
    expect(order).toEqual(["a-start", "a-end", "b", "c"]);
  });
});

describe("failed pay-dem transfer recovery", () => {
  const TX = "cd".repeat(32);
  const PAYER = "c0".repeat(32);
  const PAYEE = `0x${"70".repeat(32)}`;
  const reservation = {
    reservationId: "pay-dem:01M4DZJS6XXKHB721MSRVVT1RQ", payee: PAYEE,
    debits: [{ asset: "DEM", purpose: "service", expectedAmount: "9500000000", maximumAmount: "9500000000" }],
  } as never;
  const content = (over: Record<string, unknown> = {}) => ({ from: `0x${PAYER}`, to: PAYEE, amount: "9500000000", data: ["native", { nativeOperation: "send", args: ["70".repeat(32), "9500000000"] }], ...over });
  const failedTx = { response: { status: "failed", hash: TX, blockNumber: 480877, attrs: { code: "TX_NONCE_INVALID_LOW" }, content: content() } };
  const expected = { payerAddressHex: PAYER, payee: PAYEE, amountOs: "9500000000" };
  const reader = (tx: unknown) => ({ async getTxByHash() { return tx; } });

  test("only an included-but-failed transaction, for exactly this transfer, counts as terminal absence", async () => {
    expect(await isTerminallyFailedTransfer(reader(failedTx), TX, expected)).toBe(true);
    expect(await isTerminallyFailedTransfer(reader({ response: { status: "confirmed", hash: TX, blockNumber: 1, content: content() } }), TX, expected)).toBe(false);
    expect(await isTerminallyFailedTransfer(reader({ response: { status: "failed", hash: TX, content: content() } }), TX, expected)).toBe(false);
    expect(await isTerminallyFailedTransfer({ async getTxByHash() { throw new Error("rpc"); } }, TX, expected)).toBe(false);
    // Some other failed transfer of this wallet (other payee, other amount, other payer) proves nothing about this reservation.
    expect(await isTerminallyFailedTransfer(reader({ response: { ...failedTx.response, content: content({ to: `0x${"11".repeat(32)}` }) } }), TX, expected)).toBe(false);
    expect(await isTerminallyFailedTransfer(reader({ response: { ...failedTx.response, content: content({ amount: "1" }) } }), TX, expected)).toBe(false);
    expect(await isTerminallyFailedTransfer(reader({ response: { ...failedTx.response, content: content({ from: `0x${"ff".repeat(32)}` }) } }), TX, expected)).toBe(false);
  });

  test("reconciles the held reservation as terminal absence only for this wallet's failed transfer, and never a settled one", async () => {
    const calls: unknown[] = [];
    const authority = { async reconcile(r: unknown, o: unknown) { calls.push([r, o]); return "released" as const; } };
    // An operator hash for some other failed transfer is refused before any evidence is written.
    const otherFailed = { response: { ...failedTx.response, content: content({ to: `0x${"11".repeat(32)}` }) } };
    expect(await reconcileFailedPayDemTransfer({ authority, reservation, reader: reader(otherFailed), payerAddressHex: PAYER, txHash: TX })).toBe("unrecoverable");
    expect(calls).toHaveLength(0);
    const result = await reconcileFailedPayDemTransfer({ authority, reservation, reader: reader(failedTx), payerAddressHex: PAYER, txHash: TX });
    expect(result).toBe("released");
    expect(calls).toHaveLength(1);
    expect((calls[0] as [unknown, { disposition: string }])[1].disposition).toBe("terminal-absent");
    // A confirmed transfer for the reservation is reported as settled, never released.
    const TX2 = "ef".repeat(32);
    rememberSettlementEvidence("ev-x", { txHash: TX2, amountOs: "9500000000", payee: PAYEE, reservationId: "pay-dem:other" });
    const other = { ...(reservation as object), reservationId: "pay-dem:other" } as never;
    expect(await reconcileFailedPayDemTransfer({ authority, reservation: other, reader: reader({ response: { status: "confirmed", hash: TX2, blockNumber: 2, content: content() } }), payerAddressHex: PAYER })).toBe("settled");
    // An operator hash that differs from the remembered transfer is refused.
    expect(await reconcileFailedPayDemTransfer({ authority, reservation: other, reader: reader(failedTx), payerAddressHex: PAYER, txHash: "ab".repeat(32) })).toBe("unrecoverable");
    // A hash this buyer remembered for another reservation never stands for this one, even as a matching failed transfer.
    const third = { ...(reservation as object), reservationId: "pay-dem:third" } as never;
    expect(await reconcileFailedPayDemTransfer({ authority, reservation: third, reader: reader(failedTx), payerAddressHex: PAYER, txHash: TX })).toBe("unrecoverable");
    expect(calls).toHaveLength(1);
    // A refusal by the authority is reported, not retried.
    const refusing = { async reconcile() { throw new Error("wallet spend recovery cannot supersede a live worker"); } };
    expect(await reconcileFailedPayDemTransfer({ authority: refusing, reservation, reader: reader(failedTx), payerAddressHex: PAYER, txHash: TX })).toBe("unrecoverable");
  });
});
