/**
 * Shared bootstrap for the live buyer and seller processes.
 *
 * Config comes from one 0600 env file (default ~/.dacs-rfq/wallets.env) plus
 * optional overrides. Nothing secret is ever printed.
 *
 *   DEMOS_RPC                 Demos node RPC (testnet)
 *   BUYER_WALLET / SELLER_WALLET      mnemonics (dedicated testnet wallets)
 *   BUYER_DID / SELLER_DID            did:demos:agent:<hex>
 *   DACS_RFQ_ROOT             data root (default ~/.dacs-rfq/data)
 *   PEER_DIDS                 extra member claims to admit (comma-separated), e.g. tester buyers
 *   L2PS_NODE_ROOT            (seller) node checkout root; enables tester registration + provisioning
 *   L2PS_PUBLIC_RPC           (seller) node RPC as testers reach it; REGISTRATION_FUND_DEM per approval
 *   REGISTRATION_AUTO_APPROVE (seller) `all` or a comma list of claims approved without an operator step
 *   SELLER_TRANSPORT_URL      the seller's transport endpoint as seen by the buyer
 *   BUYER_TRANSPORT_URL       the buyer's transport endpoint as seen by the seller
 *   LISTING_REF               logical address of the seller's published RFQ listing
 *   MCP_TOKEN                 bearer token for the buyer MCP server (>= 32 chars)
 *   BUYER_CEILING_DEM         buyer ceiling, decimal DEM (default 9.8)
 *   SELLER_FLOOR_DEM          seller floor, decimal DEM (default 9.5)
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { canonicalDemosAgentPublicKey } from "@kynesyslabs/dacs/identity";
import { createDurableRfqLifecycleClient } from "@kynesyslabs/dacs/negotiate";
import { ed25519Verify, publicKeyFromRaw } from "@kynesyslabs/dacs/crypto";
import type { DurableRfqLifecycleTransport } from "@kynesyslabs/dacs/negotiate";
import type { RfqSessionAnnouncement } from "../src/transport/open.js";
import type { RegistrationService } from "../src/registration/service.js";
import {
  CANONICAL_PROFILE_ID, createChannelSignatureAdapter, createDemosL2psClient, createFsSubnetProvisioner, createL2psInboxFeeder, createL2psTransport, createRegistrationService, createRegistrationStore, createRfqHttpTransport, createRfqInboxStore, createSessionIndex, fundOnLocalChain,
  demosAnchorStore, openDemosActor, openRoleStores, readEnvFile, staticMemberAuthority, startRfqTransportServer,
} from "../src/index.js";
import { createSerialLock } from "../src/walletLock.js";
import type { ChannelMessageSignatureV1, Counterparty, DemosActor } from "../src/index.js";

export const log = (event: Record<string, unknown>) => {
  process.stderr.write(`${new Date().toISOString()} ${JSON.stringify(event)}\n`);
};

export function loadConfig(): Record<string, string> {
  const file = process.env["DACS_RFQ_ENV"] ?? join(homedir(), ".dacs-rfq", "wallets.env");
  const env = { ...readEnvFile(file), ...Object.fromEntries(Object.entries(process.env).filter(([, v]) => v !== undefined) as [string, string][]) };
  for (const key of ["DEMOS_RPC", "BUYER_DID", "SELLER_DID"]) if (!env[key]) throw new Error(`${key} missing`);
  env["DACS_RFQ_ROOT"] ??= join(homedir(), ".dacs-rfq", "data");
  return env;
}

export function counterpartyFromClaim(claim: string): Counterparty {
  const key = canonicalDemosAgentPublicKey(claim);
  if (key === null) throw new Error(`${claim} is not a canonical Demos agent claim`);
  return { claim, addressHex: Buffer.from(key).toString("hex"), publicKey: key };
}

type RoleTransport = DurableRfqLifecycleTransport<ChannelMessageSignatureV1> & { announce(announcement: Readonly<RfqSessionAnnouncement>): Promise<{ disposition: string; reason?: string }> };

export async function bootstrapRole(role: "buyer" | "seller", env: Record<string, string>, port: number) {
  const secret = env[role === "buyer" ? "BUYER_WALLET" : "SELLER_WALLET"];
  if (!secret) throw new Error(`${role.toUpperCase()}_WALLET missing`);
  const root = join(env["DACS_RFQ_ROOT"]!, role);
  const actor: DemosActor = await openDemosActor({ rpc: env["DEMOS_RPC"]!, secret, journalDir: join(root, "journal") });
  const expectedDid = env[role === "buyer" ? "BUYER_DID" : "SELLER_DID"]!;
  if (actor.claim !== expectedDid) throw new Error(`${role} wallet resolves to ${actor.claim}, config says ${expectedDid}`);
  const counterpartClaim = env[role === "buyer" ? "SELLER_DID" : "BUYER_DID"]!;
  const counterpart = counterpartyFromClaim(counterpartClaim);
  // PEER_DIDS: additional member claims (comma-separated) this role will talk
  // to, for example tester buyers admitted by the seller. Demos agent claims
  // carry their own Ed25519 key, so no key file is needed per peer.
  const extraPeers = (env["PEER_DIDS"] ?? "").split(",").map((c) => c.trim()).filter((c) => c.length > 0 && c !== actor.claim && c !== counterpart.claim).map(counterpartyFromClaim);
  const peers = new Map<string, Uint8Array>([[actor.claim, actor.publicKey], [counterpart.claim, counterpart.publicKey], ...extraPeers.map((p) => [p.claim, p.publicKey] as const)]);
  const authority = staticMemberAuthority(peers);
  const stores = await openRoleStores<ChannelMessageSignatureV1>({ role, root, integrityKeyPath: join(env["DACS_RFQ_ROOT"]!, "keys", `${role}.key`), createIntegrityKey: true });
  const inbox = createRfqInboxStore({ path: stores.transportDbPath });
  const sessions = createSessionIndex({ path: join(root, "sessions.db") });
  // TRANSPORT=http (default): the interim direct transport. TRANSPORT=l2ps:
  // packets ride encrypted L2PS subnet transactions on the host node at
  // L2PS_RPC; L2PS_UID names the subnet and L2PS_KEY_FILE / L2PS_IV_FILE
  // point at its key material (never the key itself in the env file).
  const transportKind = env["TRANSPORT"] ?? "http";
  let transport: RoleTransport;
  let feederTimer: NodeJS.Timeout | undefined;
  let subnetClient: Awaited<ReturnType<typeof createDemosL2psClient>> | undefined;
  let registration: RegistrationService | undefined;
  let subnetUid: string | undefined;
  let subnetRpc: string | undefined;
  let attachSubnet: ((claim: string, uid: string) => Promise<void>) | undefined;
  let syncAdmittedRef: (() => string[]) | undefined;
  const addresses = new Map([[actor.claim, `0x${actor.addressHex}`], [counterpart.claim, `0x${counterpart.addressHex}`], ...extraPeers.map((p) => [p.claim, `0x${p.addressHex}`] as const)]);
  if (transportKind === "l2ps") {
    // A tester that registered with the operator has <root>/subnet/credential.json
    // (written by bin/register.mts); explicit L2PS_* settings take precedence.
    const credentialPath = join(root, "subnet", "credential.json");
    const issued = !env["L2PS_UID"] && existsSync(credentialPath)
      ? JSON.parse(readFileSync(credentialPath, "utf8")) as { uid: string; keyHex: string; ivHex: string; host: string } : undefined;
    const l2psRpc = env["L2PS_RPC"] ?? issued?.host;
    if (!l2psRpc) throw new Error("L2PS_RPC missing for TRANSPORT=l2ps");
    const subnet = issued !== undefined && !env["L2PS_UID"]
      ? { uid: issued.uid, keyHex: issued.keyHex, ivHex: issued.ivHex }
      : (() => {
          for (const key of ["L2PS_UID", "L2PS_KEY_FILE", "L2PS_IV_FILE"]) if (!env[key]) throw new Error(`${key} missing for TRANSPORT=l2ps (or register first)`);
          return { uid: env["L2PS_UID"]!, keyHex: readFileSync(env["L2PS_KEY_FILE"]!, "utf8").trim(), ivHex: readFileSync(env["L2PS_IV_FILE"]!, "utf8").trim() };
        })();
    const subnetActor = await openDemosActor({ rpc: l2psRpc, secret, journalDir: join(root, "l2ps-journal") });
    // One nonce, one writer: every carrier client and the tester funder share this lock.
    const subnetLock = createSerialLock();
    const l2psClient = await createDemosL2psClient({ demos: subnetActor.adapter.raw as never, subnet, rpc: l2psRpc, log, lock: subnetLock });
    if (role === "seller" && env["L2PS_NODE_ROOT"]) {
      // Operator-side registration: testers register, the operator approves,
      // approval provisions a subnet on our node and funds the tester here.
      const fundDem = Number(env["REGISTRATION_FUND_DEM"] ?? 100);
      registration = createRegistrationService({
        store: createRegistrationStore({ path: join(root, "registrations.db") }),
        provisioner: createFsSubnetProvisioner({ nodeRoot: env["L2PS_NODE_ROOT"]!, rpc: env["L2PS_PUBLIC_RPC"] ?? l2psRpc }),
        funder: { fund: async (addressHex, onSigned) => { const out = await fundOnLocalChain({ demos: subnetActor.adapter.raw as never, to: `0x${addressHex}`, amountDem: fundDem, onSigned, lock: subnetLock }); if (out.status !== "confirmed") throw new Error(`funding ${out.txHash} ended ${out.status}`); return { txHash: out.txHash }; }, amountDem: fundDem },
        host: env["L2PS_PUBLIC_RPC"] ?? l2psRpc, log,
        // REGISTRATION_AUTO_APPROVE=all | did:demos:agent:…,did:demos:agent:…
        // With `all`, REGISTRATION_AUTO_APPROVE_MAX (default 20) caps how many
        // claims get provisioned and funded without an operator's approval.
        ...(env["REGISTRATION_AUTO_APPROVE"] === undefined ? {} : { autoApprove: env["REGISTRATION_AUTO_APPROVE"] === "all" ? "all" as const : env["REGISTRATION_AUTO_APPROVE"].split(",").map((x) => x.trim()).filter(Boolean) }),
        autoApproveMax: Number(env["REGISTRATION_AUTO_APPROVE_MAX"] ?? 20),
      });
    }
    subnetClient = l2psClient;
    subnetUid = subnet.uid;
    subnetRpc = l2psRpc;
    const ackStatus = (env["L2PS_ACK_STATUS"] ?? "confirmed") as "pending" | "batched" | "confirmed";
    // Subnet per peer: the configured subnet serves the configured counterpart
    // (and PEER_DIDS); every approved registration gets its own, loaded from
    // the node's key directory. The feeder set grows with them.
    const clientsByUid = new Map<string, typeof l2psClient>([[subnet.uid, l2psClient]]);
    const uidByClaim = new Map<string, string>([[counterpart.claim, subnet.uid], ...extraPeers.map((p) => [p.claim, subnet.uid] as const)]);
    const feeders = new Map<string, ReturnType<typeof createL2psInboxFeeder>>([[subnet.uid, createL2psInboxFeeder({ self: actor.signer, peers, client: l2psClient, inbox, log })]]);
    attachSubnet = async (claim, uid) => {
      if (!clientsByUid.has(uid)) {
        const dir = join(env["L2PS_NODE_ROOT"]!, "data", "l2ps", uid);
        const peerSubnet = { uid, keyHex: readFileSync(join(dir, "private_key.txt"), "utf8").trim(), ivHex: readFileSync(join(dir, "iv.txt"), "utf8").trim() };
        const client = await createDemosL2psClient({ demos: subnetActor.adapter.raw as never, subnet: peerSubnet, rpc: l2psRpc, log, lock: subnetLock });
        clientsByUid.set(uid, client);
        feeders.set(uid, createL2psInboxFeeder({ self: actor.signer, peers, client, inbox, log }));
        log({ event: "subnet-attached", uid, claim });
      }
      uidByClaim.set(claim, uid);
    };
    transport = createL2psTransport<ChannelMessageSignatureV1>({
      self: actor.signer, peers, addresses, ackStatus, log,
      clientFor: (recipient) => { const uid = uidByClaim.get(recipient); return uid === undefined ? undefined : clientsByUid.get(uid); },
    });
    const pollMs = Number(env["L2PS_POLL_MS"] ?? 2_000);
    let polling = false;
    feederTimer = setInterval(() => {
      if (polling) return;
      polling = true;
      (async () => {
        // Newly approved testers get their subnet attached here, before any
        // announcement could arrive on it.
        if (registration !== undefined) syncAdmittedRef?.();
        for (const [uid, feeder] of feeders) await feeder.poll().catch((cause: unknown) => log({ event: "l2ps-feeder-error", uid, reason: cause instanceof Error ? cause.message : String(cause) }));
      })().finally(() => { polling = false; });
    }, pollMs);
    log({ event: "l2ps-transport", rpc: l2psRpc, uid: subnet.uid, ackStatus, registration: registration !== undefined, subnetBalanceDem: (await subnetActor.balanceOs() / 1_000_000_000n).toString() });
  } else {
    const peerUrl = env[role === "buyer" ? "SELLER_TRANSPORT_URL" : "BUYER_TRANSPORT_URL"];
    if (!peerUrl) throw new Error(`${role === "buyer" ? "SELLER" : "BUYER"}_TRANSPORT_URL missing`);
    transport = createRfqHttpTransport<ChannelMessageSignatureV1>({ self: actor.signer, peers, endpoints: new Map([[counterpart.claim, peerUrl]]), log });
  }
  const wellKnownDir = join(root, "well-known");
  const server = await startRfqTransportServer({
    self: actor.signer, peers, inbox, port, log,
    ...(registration === undefined ? {} : { registration }),
    staticDocuments: () => {
      const docs: Record<string, string> = {};
      for (const [path, file] of [["/.well-known/agent.json", join(wellKnownDir, "agent.json")], ["/.well-known/dacs/listings.json", join(wellKnownDir, "dacs", "listings.json")]] as const) {
        if (existsSync(file)) docs[path] = readFileSync(file, "utf8");
      }
      return docs;
    },
  });
  const signature = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: actor.signer, authority, log });
  const client = createDurableRfqLifecycleClient<ChannelMessageSignatureV1>({
    role, store: stores.lifecycle, transport, reserveChannelId: (input) => stores.reservation.reserve(input),
    signChannelMessage: signature.signChannelMessage, verifyChannelMessage: signature.verifyChannelMessage,
    agreementSigner: { party: actor.claim, algorithm: "ed25519", sign: (bytes: Uint8Array) => actor.signer.sign(bytes) },
    verifyAgreementContribution: (input) => {
      const key = peers.get(input.party);
      return key !== undefined && ed25519Verify(input.signedBytes, Buffer.from(input.value, "base64url"), publicKeyFromRaw(key)) ? "valid" : "invalid";
    },
    nowMs: () => Date.now(),
  });
  const chain = demosAnchorStore(actor.adapter, log);
  log({ event: "role-ready", role, claim: actor.claim, transport: transportKind === "l2ps" ? `l2ps:${subnetUid}` : server.endpoint, balanceDem: (await actor.balanceOs() / 1_000_000_000n).toString(), profile: CANONICAL_PROFILE_ID });
  /** Fold approved registrations into the live peer and address tables (idempotent). */
  const syncAdmitted = (): string[] => {
    if (registration === undefined) return [];
    const approved = registration.list("approved");
    for (const row of approved) {
      if (peers.has(row.claim)) continue;
      const party = counterpartyFromClaim(row.claim);
      peers.set(party.claim, party.publicKey);
      addresses.set(party.claim, `0x${party.addressHex}`);
      log({ event: "peer-admitted", claim: row.claim, uid: row.uid });
      if (attachSubnet !== undefined && row.uid !== undefined) void attachSubnet(row.claim, row.uid).catch((cause: unknown) => log({ event: "subnet-attach-error", uid: row.uid, reason: cause instanceof Error ? cause.message : String(cause) }));
    }
    return approved.map((r) => r.claim);
  };
  syncAdmittedRef = syncAdmitted;
  syncAdmitted();
  const close = async () => { if (feederTimer !== undefined) clearInterval(feederTimer); await server.close(); };
  return { actor, counterpart, extraPeers, peers, authority, stores, inbox, sessions, server, transport, client, chain, root, transportKind, subnetClient, subnetUid, subnetRpc, registration, syncAdmitted, close };
}
