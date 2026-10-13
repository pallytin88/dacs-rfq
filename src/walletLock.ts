/**
 * One wallet, one writer at a time. Every Demos transaction from a wallet
 * carries the account nonce, so two concurrent writers (an anchor write and a
 * pay-dem transfer, for example) race on the nonce and the loser is included
 * as `failed` (TX_NONCE_INVALID_LOW). Serialise all wallet writes behind this
 * lock; readers never need it.
 */
export type SerialLock = <T>(task: () => Promise<T>) => Promise<T>;

export function createSerialLock(): SerialLock {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(task: () => Promise<T>): Promise<T> => {
    const run = tail.then(task, task);
    tail = run.catch(() => undefined);
    return run;
  };
}
