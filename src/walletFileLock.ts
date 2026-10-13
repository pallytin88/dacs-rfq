/**
 * One wallet, one writer at a time, across processes. The in-process serial
 * lock (`walletLock.ts`) cannot see a second process on the same account (the
 * seller daemon and `bin/approve.mts`, or `bin/fund-local.mts`), and each of
 * them takes `getAddressNonce + 1` before broadcasting, so they race on the
 * nonce. This lock is a directory under the role root, created atomically
 * with `O_EXCL`; the holder records its pid so a lock left by a dead process
 * is reclaimed. Combine with the serial lock for in-process ordering.
 */

import { closeSync, mkdirSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { SerialLock } from "./walletLock.js";

export interface WalletFileLockOptions {
  /** Directory holding the lock files (created 0700). */
  dir: string;
  /** Wallet address (hex, with or without 0x); the lock is per wallet. */
  wallet: string;
  /** How long a lock may be held before it is considered abandoned (default 120 s). */
  staleMs?: number;
  /** How long to wait for the lock before giving up (default 180 s). */
  waitMs?: number;
  nowMs?: () => number;
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
}

/** A `SerialLock` whose critical section also holds the cross-process file lock. */
export function createWalletFileLock(options: WalletFileLockOptions): SerialLock {
  const nowMs = options.nowMs ?? Date.now;
  const staleMs = options.staleMs ?? 120_000;
  const waitMs = options.waitMs ?? 180_000;
  const wallet = options.wallet.replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(wallet)) throw new Error("wallet must be 64 hex characters");
  mkdirSync(options.dir, { recursive: true, mode: 0o700 });
  const path = join(options.dir, `wallet-${wallet.slice(0, 16)}.lock`);
  let tail: Promise<unknown> = Promise.resolve();

  const tryAcquire = (): boolean => {
    try {
      const fd = openSync(path, "wx", 0o600);
      writeFileSync(fd, JSON.stringify({ pid: process.pid, at: nowMs() }));
      closeSync(fd);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    // Held by someone: reclaim only when the holder is dead or the lock is stale.
    try {
      const held = JSON.parse(readFileSync(path, "utf8")) as { pid?: number; at?: number };
      const age = nowMs() - (typeof held.at === "number" ? held.at : statSync(path).mtimeMs);
      if ((typeof held.pid === "number" && held.pid !== process.pid && !alive(held.pid)) || age > staleMs) rmSync(path, { force: true });
    } catch {
      rmSync(path, { force: true });
    }
    return false;
  };

  const acquire = async (): Promise<void> => {
    const deadline = nowMs() + waitMs;
    while (!tryAcquire()) {
      if (nowMs() >= deadline) throw new Error(`wallet ${wallet.slice(0, 12)}… is locked by another process (${path})`);
      await new Promise((r) => setTimeout(r, 200 + Math.floor(Math.random() * 200)));
    }
  };
  const release = (): void => { rmSync(path, { force: true }); };

  return <T>(task: () => Promise<T>): Promise<T> => {
    const run = tail.then(async () => { await acquire(); try { return await task(); } finally { release(); } }, async () => { await acquire(); try { return await task(); } finally { release(); } });
    tail = run.catch(() => undefined);
    return run;
  };
}
