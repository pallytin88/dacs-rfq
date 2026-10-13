/**
 * DACS-1 identity bundles for a Demos agent: a single primary claim with a
 * per-claim presentation signed under `dacs-bundle-presentation:v1:`, exactly
 * as the SDK's funded two-agent run builds and verifies them.
 */

import { sha256Hex } from "@kynesyslabs/dacs/canonical";
import type { IdentityBundle } from "@kynesyslabs/dacs/artifacts";
import { ed25519Verify, publicKeyFromRaw, signedBytes } from "@kynesyslabs/dacs/crypto";
import { identityBundleHash } from "@kynesyslabs/dacs/identity";
import { signBytes } from "../signer.js";
import type { Ed25519Signer } from "../signer.js";

export const BUNDLE_PRESENTATION_DOMAIN = "dacs-bundle-presentation:v1:" as const;

export async function buildIdentityBundle(signer: Ed25519Signer, nowMs: number, sessionBound = true): Promise<IdentityBundle> {
  const bundle: IdentityBundle = {
    bundleVersion: "1",
    presentedBy: signer.claim,
    presentedAt: nowMs,
    ...(sessionBound ? { sessionNonce: sha256Hex(`${signer.claim}:${nowMs}`) } : {}),
    claims: [{ ref: signer.claim }],
    presentation: { kind: "per-claim", signatures: [{ ref: signer.claim, signature: "pending" }] },
  };
  const bytes = signedBytes(BUNDLE_PRESENTATION_DOMAIN, identityBundleHash(bundle));
  const signature = await signBytes(signer, bytes);
  (bundle.presentation as { signatures: Array<{ ref: string; signature: string }> }).signatures[0]!.signature =
    Buffer.from(signature).toString("base64url");
  return bundle;
}

/** Verify a single-claim per-claim presentation against the claim's raw key. */
export function verifyIdentityBundle(bundle: Readonly<IdentityBundle>, publicKey: Uint8Array): boolean {
  if (bundle.bundleVersion !== "1" || bundle.presentation.kind !== "per-claim") return false;
  if (bundle.claims.length !== 1 || bundle.claims[0]!.ref !== bundle.presentedBy) return false;
  const sigs = bundle.presentation.signatures;
  if (sigs.length !== 1 || sigs[0]!.ref !== bundle.presentedBy) return false;
  try {
    const bytes = signedBytes(BUNDLE_PRESENTATION_DOMAIN, identityBundleHash(bundle));
    return ed25519Verify(bytes, Uint8Array.from(Buffer.from(sigs[0]!.signature, "base64url")), publicKeyFromRaw(publicKey));
  } catch {
    return false;
  }
}
