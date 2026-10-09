/**
 * One signing abstraction for everything this package signs with a role's
 * Demos key: channel turns, transport envelopes, agreement contributions,
 * identity presentations, vet records and commitment records.
 *
 * In tests the signer wraps a Node KeyObject; live, it wraps the connected
 * `DemosAdapter.sign`, so the private key never leaves the adapter.
 */

import type { KeyObject } from "node:crypto";
import { ed25519Sign } from "@kynesyslabs/dacs/crypto";

export interface Ed25519Signer {
  /** Canonical claim the signatures are attributed to. */
  claim: string;
  sign: (bytes: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export function keyObjectSigner(claim: string, privateKey: KeyObject): Ed25519Signer {
  return { claim, sign: (bytes) => ed25519Sign(bytes, privateKey) };
}

export async function signBytes(signer: Ed25519Signer, bytes: Uint8Array): Promise<Uint8Array> {
  const signature = await signer.sign(bytes);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error("signer returned an invalid Ed25519 signature");
  }
  return signature;
}
