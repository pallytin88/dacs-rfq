/**
 * demosdk-backed `L2psCarrierClient`: encrypts a native send with the subnet
 * key (AES-256-GCM, fresh nonce per transaction) and submits it as an
 * `l2psEncryptedTx` to the host node, then reads the member's own history
 * back with the signed `getL2PSAccountTransactions` call. Mirrors the node's
 * reference `scripts/send-l2-batch.ts`.
 */

import { L2PS } from "@kynesyslabs/demosdk/l2ps";
import type { L2psCarrierClient, L2psHistoryEntry } from "./l2ps.js";
import { createSerialLock, type SerialLock } from "../walletLock.js";

const hex = (value: unknown): string | null => (typeof value === "string" ? value.replace(/^0x/, "").toLowerCase() : null);

export interface L2psSubnetConfig {
  uid: string;
  /** 64 hex characters (32-byte AES key) as the node's `private_key.txt` holds it. */
  keyHex: string;
  /** 32 hex characters (16-byte IV) as the node's `iv.txt` holds it. */
  ivHex: string;
}

/** The subset of a connected demosdk `Demos` instance used here. */
export interface DemosSubnetClient {
  getAddress(): string;
  getAddressNonce(address: string): Promise<number>;
  tx: { prepare(): Promise<Record<string, any>> };
  sign(tx: Record<string, any>): Promise<Record<string, any>>;
  confirm(tx: Record<string, any>): Promise<any>;
  broadcast(validity: any): Promise<any>;
  getL2PSHistory(uid: string, options?: Record<string, unknown>): Promise<{ transactions: any[] }>;
}

const hexToBinary = (hex: string): string => Buffer.from(hex.trim(), "hex").toString("binary");

export async function createDemosL2psClient(options: {
  demos: DemosSubnetClient;
  subnet: L2psSubnetConfig;
  rpc: string;
  /**
   * Token amount each carrier transfers, in the node's native-send unit (whole
   * DEM on osDenomination-forked nodes, where 1 shows as 1000000000 OS in
   * history). The executor requires a positive integer.
   */
  amountOs?: number;
  /**
   * Sign the pre-subnet-binding history auth message instead of the
   * subnet-bound one. Only for a node older than the binding change (0.9.8),
   * which also rejects demosdk 4.x transaction signatures; default off.
   */
  legacyHistoryAuth?: boolean;
  log?: (event: Readonly<Record<string, unknown>>) => void;
  /**
   * Serialises every broadcast from this demos instance. Pass the same lock to
   * every client and funder that shares the instance: each broadcast takes the
   * account nonce, so two writers without a common lock race on it.
   */
  lock?: SerialLock;
}): Promise<L2psCarrierClient> {
  if (!/^[0-9a-f]{64}$/i.test(options.subnet.keyHex.trim()) || !/^[0-9a-f]{32}$/i.test(options.subnet.ivHex.trim())) {
    throw new Error("subnet key must be 64 hex characters and the IV 32");
  }
  const log = options.log ?? (() => {});
  const amount = options.amountOs ?? 1;
  const l2ps = await L2PS.create(hexToBinary(options.subnet.keyHex), hexToBinary(options.subnet.ivHex));
  l2ps.setConfig({ uid: options.subnet.uid, config: { created_at_block: 0, known_rpcs: [options.rpc] } });
  const lock = options.lock ?? createSerialLock();
  const address = () => options.demos.getAddress();
  /**
   * The row's transaction content, decrypted here with the subnet key from
   * the ciphertext the node stored. The node's own `content` field is never
   * used: the history read proves the reader's address to the node, not the
   * node to the reader, so only what this key opens is trusted.
   */
  const decryptRow = async (row: any): Promise<Record<string, unknown> | null> => {
    const stored = row?.encrypted_payload;
    if (stored === null || stored === undefined || typeof stored !== "object") return null;
    // The node stores the whole outer `l2psEncryptedTx`; accept a bare
    // payload (`encrypted_data`, `tag`, `original_hash`, ...) as well.
    const outer = typeof stored.encrypted_data === "string"
      ? { content: { type: "l2psEncryptedTx", data: ["l2psEncryptedTx", stored] } }
      : stored;
    try {
      const inner = await l2ps.decryptTx(outer as never) as unknown as { hash?: unknown; content?: Record<string, unknown> } | null;
      if (inner === null || typeof inner !== "object" || inner.content === undefined) return null;
      if (hex(inner.hash) !== hex(row?.hash)) return null;
      return inner.content;
    } catch (cause) {
      log({ event: "l2ps-history-row-unreadable", hash: String(row?.hash ?? "").slice(0, 16), reason: cause instanceof Error ? cause.message : String(cause) });
      return null;
    }
  };

  return {
    address,
    send: (input) => lock(async () => {
      const to = input.to.startsWith("0x") ? input.to : `0x${input.to}`;
      const nonce = (await options.demos.getAddressNonce(address())) + 1;
      const inner = await options.demos.tx.prepare();
      inner.content.type = "native";
      inner.content.to = to;
      inner.content.amount = amount;
      inner.content.nonce = nonce;
      inner.content.timestamp = Date.now();
      inner.content.data = ["native", { nativeOperation: "send", args: [to, amount], l2ps_uid: options.subnet.uid, rfq: input.carrier }];
      const signedInner = await options.demos.sign(inner);
      const encrypted = await l2ps.encryptTx(signedInner as never);
      const payload = (encrypted as unknown as { content: { data: [string, unknown] } }).content.data[1];
      const outer = await options.demos.tx.prepare();
      outer.content.type = "l2psEncryptedTx";
      outer.content.to = to;
      outer.content.amount = 0;
      outer.content.nonce = nonce;
      outer.content.timestamp = Date.now();
      outer.content.data = ["l2psEncryptedTx", payload];
      const signedOuter = await options.demos.sign(outer);
      const validity = await options.demos.confirm(signedOuter);
      const data = validity?.response?.data;
      if (data?.valid !== true) throw new Error(`host node rejected the carrier transaction: ${data?.message ?? JSON.stringify(validity?.response ?? null).slice(0, 200)}`);
      const broadcast = await options.demos.broadcast(validity);
      log({ event: "l2ps-broadcast", innerHash: signedInner.hash, outerHash: signedOuter.hash, result: broadcast?.result ?? broadcast?.response?.result });
      return { innerHash: signedInner.hash as string };
    }),
    async history(opts) {
      const page = await options.demos.getL2PSHistory(options.subnet.uid, {
        limit: opts?.limit ?? 100, ...(opts?.since === undefined ? {} : { since: opts.since }),
        ...(options.legacyHistoryAuth === true ? { legacyAuth: true } : {}),
      });
      return Promise.all(page.transactions.map(async (row: any): Promise<L2psHistoryEntry> => ({
        hash: String(row.hash), from: String(row.from ?? row.from_address ?? ""), to: String(row.to ?? row.to_address ?? ""),
        status: String(row.status), timestamp: Number(row.timestamp), content: await decryptRow(row),
      })));
    },
  };
}
