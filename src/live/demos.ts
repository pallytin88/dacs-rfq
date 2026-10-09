/**
 * Live Demos actor for one role: a connected `DemosAdapter` from the SDK
 * (mnemonic secret, filesystem write journal), the canonical agent claim, a
 * signer that routes through the adapter, and balance reads in OS.
 *
 * Testnet only. The mnemonic is read from a 0600 env file outside the repo
 * and never logged.
 */

import { mkdirSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { createFsDemosWriteJournal, DemosAdapter } from "@kynesyslabs/dacs/substrate";
import { demosAgentClaimRef } from "@kynesyslabs/dacs/identity";
import type { Ed25519Signer } from "../signer.js";

export interface DemosActorOptions {
  rpc: string;
  /** BIP-39 mnemonic (or hex master seed) for a dedicated testnet wallet. */
  secret: string;
  /** Absolute, role-local directory for the write journal. */
  journalDir: string;
  /** Per-write fee ceiling in OS. */
  maximumFeeOs?: bigint;
}

export interface DemosActor {
  adapter: DemosAdapter;
  /** 64-hex Demos address == raw Ed25519 public key. */
  addressHex: string;
  /** `did:demos:agent:<addressHex>` */
  claim: string;
  publicKey: Uint8Array;
  signer: Ed25519Signer;
  balanceOs: () => Promise<bigint>;
}

export async function openDemosActor(options: DemosActorOptions): Promise<DemosActor> {
  if (!isAbsolute(options.journalDir)) throw new Error("journalDir must be absolute");
  mkdirSync(options.journalDir, { recursive: true, mode: 0o700 });
  const writeJournal = await createFsDemosWriteJournal({ dir: join(options.journalDir, "demos-write-journal") });
  const adapter = new DemosAdapter({
    rpc: options.rpc,
    secret: options.secret,
    writeJournal,
    ...(options.maximumFeeOs === undefined ? {} : { maximumFeeOs: options.maximumFeeOs }),
  });
  await adapter.connect();
  const addressHex = adapter.getAddress().replace(/^0x/i, "").toLowerCase();
  const publicKey = await adapter.getPublicKey();
  if (Buffer.from(publicKey).toString("hex") !== addressHex) {
    throw new Error("Demos address does not match the wallet's Ed25519 public key");
  }
  const claim = demosAgentClaimRef(publicKey);
  return {
    adapter,
    addressHex,
    claim,
    publicKey,
    signer: { claim, sign: (bytes) => adapter.sign(Uint8Array.from(bytes)) },
    async balanceOs() {
      const info = await adapter.raw.getAddressInfo(adapter.getAddress());
      const balance = (info as { balance?: unknown } | null)?.balance;
      if (typeof balance === "bigint") return balance;
      if (typeof balance === "number" || typeof balance === "string") return BigInt(balance);
      throw new Error("balance unavailable");
    },
  };
}

/** Parse a `KEY=value` env file (quotes stripped). Never logs values. */
export function readEnvFile(path: string): Record<string, string> {
  if ((statSync(path).mode & 0o077) !== 0) throw new Error(`${path} must be mode 0600`);
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line.length === 0 || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    if (i <= 0) continue;
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(/^"|"$/g, "");
  }
  return out;
}
