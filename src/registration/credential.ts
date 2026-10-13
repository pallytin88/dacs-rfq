/**
 * Sealed delivery of a tester's subnet credential: X25519 (ephemeral →
 * recipient) → HKDF-SHA256 → AES-256-GCM. The operator never sees the
 * recipient's private key; the recipient never sees ours; the subnet key
 * crosses the wire only inside this envelope.
 */

import { createCipheriv, createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";

export const CREDENTIAL_VERSION = "colony-rfq-credential:v0" as const;

export interface SealedCredential {
  credentialVersion: typeof CREDENTIAL_VERSION;
  /** Ephemeral X25519 public key, 32 bytes hex. */
  ephemeralPublicKey: string;
  /** 12-byte GCM nonce, base64url. */
  nonce: string;
  ciphertext: string;
  tag: string;
}

const HEX64 = /^[0-9a-f]{64}$/;

export function generateX25519KeyPair(): { privateKey: KeyObject; publicKeyHex: string } {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return { privateKey, publicKeyHex: rawX25519PublicKey(publicKey) };
}

export function rawX25519PublicKey(key: KeyObject): string {
  const jwk = key.export({ format: "jwk" }) as { x?: string };
  if (typeof jwk.x !== "string") throw new Error("not an X25519 public key");
  return Buffer.from(jwk.x, "base64url").toString("hex");
}

export function x25519PublicKeyFromHex(hex: string): KeyObject {
  if (!HEX64.test(hex)) throw new Error("X25519 public key must be 64 lowercase hex characters");
  return createPublicKey({ key: { kty: "OKP", crv: "X25519", x: Buffer.from(hex, "hex").toString("base64url") }, format: "jwk" });
}

function deriveKey(shared: Buffer, ephemeralHex: string, recipientHex: string): Buffer {
  return Buffer.from(hkdfSync("sha256", shared, Buffer.from(ephemeralHex + recipientHex, "hex"), CREDENTIAL_VERSION, 32));
}

export function sealCredential(recipientPublicKeyHex: string, payload: Readonly<Record<string, unknown>>): SealedCredential {
  const recipient = x25519PublicKeyFromHex(recipientPublicKeyHex);
  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralHex = rawX25519PublicKey(ephemeral.publicKey);
  const key = deriveKey(diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient }), ephemeralHex, recipientPublicKeyHex);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(ephemeralHex, "hex"));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return { credentialVersion: CREDENTIAL_VERSION, ephemeralPublicKey: ephemeralHex, nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") };
}

export function openCredential(sealed: Readonly<SealedCredential>, recipientPrivateKey: KeyObject): Record<string, unknown> {
  if (sealed.credentialVersion !== CREDENTIAL_VERSION) throw new Error("unknown credential version");
  const recipientHex = rawX25519PublicKey(createPublicKey(recipientPrivateKey));
  const ephemeral = x25519PublicKeyFromHex(sealed.ephemeralPublicKey);
  const key = deriveKey(diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeral }), sealed.ephemeralPublicKey, recipientHex);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(sealed.nonce, "base64url"));
  decipher.setAAD(Buffer.from(sealed.ephemeralPublicKey, "hex"));
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64url"));
  const plain = Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext, "base64url")), decipher.final()]).toString("utf8");
  const parsed: unknown = JSON.parse(plain);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("credential payload is not an object");
  return parsed as Record<string, unknown>;
}
