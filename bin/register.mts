#!/usr/bin/env -S node --import tsx
/**
 * Tester side: register this buyer with an operator's node and receive a
 * private subnet credential, sealed to a key generated here.
 *
 *   REGISTER_URL=https://host/colony-rfq/v0/register tsx bin/register.mts
 *
 * Writes <root>/subnet/credential.json (0600); `TRANSPORT=l2ps tsx bin/buyer.mts run`
 * then picks it up without any L2PS_* settings.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildRegistrationRequest, generateX25519KeyPair, openCredential, openDemosActor, rawX25519PublicKey } from "../src/index.js";
import type { SealedCredential } from "../src/index.js";
import { loadConfig, log } from "./common.mts";

const env = loadConfig();
const url = env["REGISTER_URL"] ?? process.env["REGISTER_URL"];
if (!url) throw new Error("REGISTER_URL missing");
const root = join(env["DACS_RFQ_ROOT"]!, "buyer");
const dir = join(root, "subnet");
mkdirSync(dir, { recursive: true, mode: 0o700 });
const keyPath = join(dir, "x25519.pem");
let privateKey;
if (existsSync(keyPath)) privateKey = createPrivateKey(readFileSync(keyPath, "utf8"));
else {
  const pair = generateX25519KeyPair();
  privateKey = pair.privateKey;
  writeFileSync(keyPath, privateKey.export({ format: "pem", type: "pkcs8" }) as string, { mode: 0o600 });
}
const encryptionPublicKey = rawX25519PublicKey(createPublicKey(privateKey));
const actor = await openDemosActor({ rpc: env["DEMOS_RPC"]!, secret: env["BUYER_WALLET"]!, journalDir: join(root, "journal") });
const request = await buildRegistrationRequest(actor.signer, encryptionPublicKey, Date.now());
const submitted = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request) });
log({ event: "registration-submitted", http: submitted.status, body: await submitted.json() });
const statusUrl = `${url.replace(/\/$/, "")}/${encodeURIComponent(actor.claim)}`;
const once = process.argv.includes("--once");
for (;;) {
  const view = await (await fetch(statusUrl)).json() as { status: string; uid?: string; host?: string; credential?: SealedCredential; note?: string };
  if (view.status === "approved" && view.credential) {
    const opened = openCredential(view.credential, privateKey) as { uid: string; keyHex: string; ivHex: string; host: string; fundingTx?: string };
    // The operator's current public host wins over the one sealed at approval time
    // (an operator may move hostnames; the sealed key material does not change).
    writeFileSync(join(dir, "credential.json"), JSON.stringify({ uid: opened.uid, keyHex: opened.keyHex, ivHex: opened.ivHex, host: view.host ?? opened.host, fundingTx: opened.fundingTx, receivedAt: Date.now() }), { mode: 0o600 });
    log({ event: "registration-approved", uid: opened.uid, host: opened.host, fundingTx: opened.fundingTx, credential: join(dir, "credential.json") });
    process.stdout.write(`Registered. Run: TRANSPORT=l2ps tsx bin/buyer.mts run\n`);
    process.exit(0);
  }
  if (view.status === "rejected") { log({ event: "registration-rejected", note: view.note }); process.exit(1); }
  log({ event: "registration-pending" });
  if (once) process.exit(2);
  await new Promise((r) => setTimeout(r, 10_000));
}
