/**
 * Native transfer on the self-hosted chain (tester funding). On an
 * osDenomination-forked node a native send's `amount` is whole DEM and the
 * node scales it to OS. Confirmed, broadcast, then waited for inclusion.
 */

export interface LocalChainClient {
  getAddress(): string;
  getAddressNonce(address: string): Promise<number>;
  tx: { prepare(): Promise<Record<string, any>> };
  sign(tx: Record<string, any>): Promise<Record<string, any>>;
  confirm(tx: Record<string, any>): Promise<any>;
  broadcast(validity: any): Promise<any>;
  getTxByHash(hash: string): Promise<any>;
}

export async function fundOnLocalChain(options: { demos: LocalChainClient; to: string; amountDem: number; waitMs?: number }): Promise<{ txHash: string; status: string }> {
  const to = options.to.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(to)) throw new Error("recipient must be a 0x-prefixed 64-hex address");
  if (!Number.isSafeInteger(options.amountDem) || options.amountDem <= 0) throw new Error("amount must be a positive whole number of DEM");
  const demos = options.demos;
  const tx = await demos.tx.prepare();
  tx.content.type = "native";
  tx.content.to = to;
  tx.content.amount = options.amountDem;
  tx.content.nonce = (await demos.getAddressNonce(demos.getAddress())) + 1;
  tx.content.timestamp = Date.now();
  tx.content.data = ["native", { nativeOperation: "send", args: [to, options.amountDem] }];
  const signed = await demos.sign(tx);
  const validity = await demos.confirm(signed);
  if (validity?.response?.data?.valid !== true) throw new Error(`node rejected the transfer: ${validity?.response?.data?.message ?? JSON.stringify(validity?.response ?? null).slice(0, 200)}`);
  await demos.broadcast(validity);
  const deadline = Date.now() + (options.waitMs ?? 120_000);
  let status = "pending";
  while (Date.now() < deadline && status !== "confirmed" && status !== "failed") {
    await new Promise((r) => setTimeout(r, 3_000));
    const seen = await demos.getTxByHash(signed.hash).catch(() => null);
    status = String((seen?.response ?? seen)?.status ?? "pending");
  }
  return { txHash: String(signed.hash), status };
}
