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
  const reservation = {
    reservationId: "pay-dem:01M4DZJS6XXKHB721MSRVVT1RQ", payee: `0x${"70".repeat(32)}`,
    debits: [{ asset: "DEM", purpose: "service", expectedAmount: "9500000000", maximumAmount: "9500000000" }],
  } as never;
  const failedTx = { response: { status: "failed", hash: TX, blockNumber: 480877, attrs: { code: "TX_NONCE_INVALID_LOW" } } };

  test("only an included-but-failed transaction counts as terminal absence", async () => {
    expect(await isTerminallyFailedTransfer({ async getTxByHash() { return failedTx; } }, TX)).toBe(true);
    expect(await isTerminallyFailedTransfer({ async getTxByHash() { return { response: { status: "confirmed", hash: TX, blockNumber: 1 } }; } }, TX)).toBe(false);
    expect(await isTerminallyFailedTransfer({ async getTxByHash() { return { response: { status: "failed", hash: TX } }; } }, TX)).toBe(false);
    expect(await isTerminallyFailedTransfer({ async getTxByHash() { throw new Error("rpc"); } }, TX)).toBe(false);
  });

  test("reconciles the held reservation as terminal absence after re-verifying on chain", async () => {
    const calls: unknown[] = [];
    const authority = { async reconcile(r: unknown, o: unknown) { calls.push([r, o]); return "released" as const; } };
    const result = await reconcileFailedPayDemTransfer({ authority, reservation, reader: { async getTxByHash() { return failedTx; } }, txHash: TX });
    expect(result).toBe("released");
    expect(calls).toHaveLength(1);
    expect((calls[0] as [unknown, { disposition: string }])[1].disposition).toBe("terminal-absent");
    // A confirmed transfer is never released, and a refusal by the authority is reported, not retried.
    rememberSettlementEvidence("ev-x", { txHash: TX, amountOs: "9500000000", payee: `0x${"70".repeat(32)}`, reservationId: "pay-dem:other" });
    const confirmed = await reconcileFailedPayDemTransfer({ authority, reservation: { ...(reservation as object), reservationId: "pay-dem:other" } as never, reader: { async getTxByHash() { return { response: { status: "confirmed", hash: TX, blockNumber: 2 } }; } } });
    expect(confirmed).toBe("unrecoverable");
    const refusing = { async reconcile() { throw new Error("wallet spend recovery cannot supersede a live worker"); } };
    expect(await reconcileFailedPayDemTransfer({ authority: refusing, reservation, reader: { async getTxByHash() { return failedTx; } }, txHash: TX })).toBe("unrecoverable");
  });
});
