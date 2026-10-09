import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { demosAgentClaimRef } from "@kynesyslabs/dacs/identity";
import { keyObjectSigner } from "../src/signer.js";
import { buildRegistrationRequest, verifyRegistrationRequest } from "../src/registration/request.js";
import { generateX25519KeyPair, openCredential, sealCredential } from "../src/registration/credential.js";
import { createRegistrationStore } from "../src/registration/store.js";
import { createFsSubnetProvisioner, createRegistrationService } from "../src/registration/service.js";
import { createRfqInboxStore, startRfqTransportServer } from "../src/transport/index.js";

const testerKeys = generateKeyPairSync("ed25519");
const testerRaw = rawPublicKey(testerKeys.publicKey);
const TESTER = demosAgentClaimRef(testerRaw);
const tester = keyObjectSigner(TESTER, testerKeys.privateKey);
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = () => { const d = mkdtempSync(join(tmpdir(), "rfq-reg-")); dirs.push(d); return d; };

describe("sealed credential", () => {
  test("round-trips to the holder of the private key and to nobody else", () => {
    const tester = generateX25519KeyPair();
    const sealed = sealCredential(tester.publicKeyHex, { uid: "u", keyHex: "ab".repeat(32), ivHex: "cd".repeat(16) });
    expect(openCredential(sealed, tester.privateKey)).toEqual({ uid: "u", keyHex: "ab".repeat(32), ivHex: "cd".repeat(16) });
    const other = generateX25519KeyPair();
    expect(() => openCredential(sealed, other.privateKey)).toThrow();
    const tampered = Buffer.from(sealed.ciphertext, "base64url");
    tampered[0] = tampered[0]! ^ 0x01;
    expect(() => openCredential({ ...sealed, ciphertext: tampered.toString("base64url") }, tester.privateKey)).toThrow();
  });
});

describe("registration request", () => {
  test("verifies only a fresh request signed by the claim it names", async () => {
    const enc = generateX25519KeyPair();
    const request = await buildRegistrationRequest(tester, enc.publicKeyHex, 1_000_000);
    expect(verifyRegistrationRequest(request, 1_000_500)).toMatchObject({ ok: true });
    expect(verifyRegistrationRequest({ ...request, encryptionPublicKey: "ff".repeat(32) }, 1_000_500)).toMatchObject({ ok: false, reason: /does not verify/ });
    expect(verifyRegistrationRequest(request, 1_000_000 + 400_000)).toMatchObject({ ok: false, reason: /window/ });
    const stranger = keyObjectSigner(TESTER, generateKeyPairSync("ed25519").privateKey);
    expect(verifyRegistrationRequest(await buildRegistrationRequest(stranger, enc.publicKeyHex, 1_000_000), 1_000_500)).toMatchObject({ ok: false, reason: /does not verify/ });
    expect(verifyRegistrationRequest(await buildRegistrationRequest(keyObjectSigner("did:demos:not-agent", testerKeys.privateKey), enc.publicKeyHex, 1_000_000), 1_000_500)).toMatchObject({ ok: false, reason: /canonical/ });
  });
});

describe("registration service over the transport server", () => {
  test("pending → approve provisions a subnet, funds, seals; the tester opens it; duplicates and conflicts are reported", async () => {
    const root = tmp();
    const nodeRoot = join(root, "node");
    const funded: string[] = [];
    const store = createRegistrationStore({ path: join(root, "registrations.db") });
    const service = createRegistrationService({
      store, host: "https://node.example/rpc", nowMs: () => 5_000_000,
      provisioner: createFsSubnetProvisioner({ nodeRoot, rpc: "https://node.example/rpc" }),
      funder: { fund: async (addressHex) => { funded.push(addressHex); return { txHash: "tx-fund-1" }; } },
    });
    const inbox = createRfqInboxStore({ path: join(root, "inbox.db") });
    const server = await startRfqTransportServer({ self: keyObjectSigner("did:demos:agent:" + "70".repeat(32), generateKeyPairSync("ed25519").privateKey), peers: new Map(), inbox, registration: service });
    const base = server.endpoint.replace(/\/colony-rfq\/v0\/messages$/, "") + "/colony-rfq/v0/register";
    const enc = generateX25519KeyPair();
    const request = await buildRegistrationRequest(tester, enc.publicKeyHex, 5_000_000);
    const post = async (body: unknown) => { const r = await fetch(base, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() as Record<string, unknown> }; };
    expect(await post(request)).toMatchObject({ status: 202, body: { status: "pending" } });
    expect(await post(request)).toMatchObject({ status: 200, body: { status: "pending" } });
    const flipped = (request.signature.value[0] === "A" ? "B" : "A") + request.signature.value.slice(1);
    expect(await post({ ...request, signature: { ...request.signature, value: flipped } })).toMatchObject({ status: 400 });
    const otherKey = await buildRegistrationRequest(tester, generateX25519KeyPair().publicKeyHex, 5_000_000);
    expect(await post(otherKey)).toMatchObject({ status: 409 });
    const status = async () => { const r = await fetch(`${base}/${encodeURIComponent(TESTER)}`); return { status: r.status, body: await r.json() as Record<string, unknown> }; };
    expect(await status()).toMatchObject({ status: 200, body: { status: "pending" } });
    expect((await fetch(`${base}/${encodeURIComponent("did:demos:agent:" + "00".repeat(32))}`)).status).toBe(404);
    expect(service.admittedClaims()).toEqual([]);

    const approved = await service.approve(TESTER);
    expect(approved.status).toBe("approved");
    expect(funded).toEqual([Buffer.from(testerRaw).toString("hex")]);
    expect(approved.fundingTx).toBe("tx-fund-1");
    expect(existsSync(join(nodeRoot, "data", "l2ps", approved.uid!, "config.json"))).toBe(true);
    const config = JSON.parse(readFileSync(join(nodeRoot, "data", "l2ps", approved.uid!, "config.json"), "utf8")) as { uid: string; keys: { private_key_path: string } };
    expect(config.uid).toBe(approved.uid);
    const keyOnDisk = readFileSync(join(nodeRoot, config.keys.private_key_path), "utf8").trim();
    const view = await status();
    expect(view.body["status"]).toBe("approved");
    const opened = openCredential(view.body["credential"] as never, enc.privateKey) as { uid: string; keyHex: string; host: string; fundingTx: string };
    expect(opened).toMatchObject({ uid: approved.uid, keyHex: keyOnDisk, host: "https://node.example/rpc", fundingTx: "tx-fund-1" });
    expect(service.admittedClaims()).toEqual([TESTER]);
    // The sealed credential is useless to anyone without the tester's X25519 key.
    expect(() => openCredential(view.body["credential"] as never, generateX25519KeyPair().privateKey)).toThrow();
    await expect(service.approve(TESTER)).rejects.toThrow(/not pending/);
    // Auto-approve policy: a listed claim is provisioned on submit; an unlisted one waits.
    const auto = createRegistrationService({ store: createRegistrationStore({ path: join(root, "auto.db") }), host: "https://node.example/rpc", nowMs: () => 5_000_000, provisioner: createFsSubnetProvisioner({ nodeRoot: join(root, "node2"), rpc: "https://node.example/rpc" }), autoApprove: [TESTER] });
    expect(await auto.submit(await buildRegistrationRequest(tester, enc.publicKeyHex, 5_000_000))).toMatchObject({ status: 202, body: { status: "approved" } });
    const other = generateKeyPairSync("ed25519");
    const otherSigner = keyObjectSigner(demosAgentClaimRef(rawPublicKey(other.publicKey)), other.privateKey);
    expect(await auto.submit(await buildRegistrationRequest(otherSigner, enc.publicKeyHex, 5_000_000))).toMatchObject({ status: 202, body: { status: "pending" } });
    await server.close();
    inbox.close();
    store.close();
  });
});
