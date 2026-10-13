#!/usr/bin/env -S node --import tsx
/**
 * Live buyer process (testnet): transport server + MCP server for the model.
 *
 *   tsx bin/buyer.mts run
 *
 * Requires LISTING_REF (from the seller's publish-listing) and MCP_TOKEN.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createPayDemRail, createWalletSpendAuthorityV1 } from "@kynesyslabs/dacs/rails";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs/canonical";
import {
  anchorReaderByRef,
  buildIdentityBundle, commitNegotiatedAgreement, createBuyerCeilingGuard, createBuyerNegotiationService, createBuyerVetExchange,
  createCommitmentSignatureVerifier, createDemosFinalityProvider, createDirectoryCatalog, createSqliteWalletSpendStateStore,
  configureSettlementEvidenceStore, createPayDemSettlementAuthenticator, createSerialLock, DACS_DIRECTORY_URL, discoverVerifiedListing, settleWithPayDem, startBuyerMcpServer, startShowcaseServer,
} from "../src/index.js";
import { bootstrapRole, loadConfig, log } from "./common.mts";

const env = loadConfig();
const listingRef = env["LISTING_REF"];
const token = env["MCP_TOKEN"];
if (!token || token.length < 32) throw new Error("MCP_TOKEN missing or shorter than 32 characters");
const role = await bootstrapRole("buyer", env, Number(env["BUYER_TRANSPORT_PORT"] ?? 47102));

const identityPath = join(role.root, "identity-bundle.json");
const identity = existsSync(identityPath)
  ? JSON.parse(readFileSync(identityPath, "utf8"))
  : await (async () => { const b = await buildIdentityBundle(role.actor.signer, Date.now(), false); writeFileSync(identityPath, JSON.stringify(b), { mode: 0o600 }); return b; })();

// Catalog: the DACS Directory (the community front end) for discovery, the
// chain for truth. LISTING_REF, when set, pins one listing instead.
const placeholderVet = { anchor: { kind: "storage-program" as const, locator: "pending" }, contentHash: "0".repeat(64) };
const catalog = listingRef === undefined
  ? createDirectoryCatalog({
      directoryUrl: env["DIRECTORY_URL"] ?? DACS_DIRECTORY_URL,
      sellers: [role.counterpart.claim],
      readAnchor: anchorReaderByRef(role.actor.adapter, role.chain, role.counterpart.addressHex),
      sellerVetRecordRef: () => placeholderVet,
      log,
    })
  : async () => [{
      verifiedListing: await discoverVerifiedListing({
        readAnchor: anchorReaderByRef(role.actor.adapter, role.chain, role.counterpart.addressHex), listingRef,
        sellerClaim: role.counterpart.claim, sellerPublicKey: role.counterpart.publicKey, nowMs: () => Date.now(),
      }),
      sellerVetRecordRef: placeholderVet,
      sellerClaim: role.counterpart.claim,
    }];
const initial = await catalog();
log({ event: "catalog-ready", source: listingRef === undefined ? (env["DIRECTORY_URL"] ?? DACS_DIRECTORY_URL) : listingRef, listings: initial.map((e) => `${e.verifiedListing.listing.listingId}@${e.verifiedListing.listing.listingVersion}`) });

const finality = createDemosFinalityProvider({ adapter: role.actor.adapter, writer: role.actor.claim, writerAddressHex: role.actor.addressHex });
const verifySignature = createCommitmentSignatureVerifier(role.authority.resolve);
// Testnet nodes charge 1 DEM network fee + 1 DEM RPC fee per transaction
// (observed on every anchor write); the rail refuses to broadcast when the
// node-confirmed debit exceeds amount + this ceiling.
const maxFeeOs = BigInt(env["MAX_NETWORK_FEE_OS"] ?? "2000000000");
const rail = await createPayDemRail({ rpc: env["DEMOS_RPC"]!, secret: env["BUYER_WALLET"]!, network: "demos", maxTotalDebitOs: 100_000_000_000n + maxFeeOs });
const spendPolicy = {
  policyVersion: "1", policyId: "supercolony-rfq-buyer", wallet: role.actor.addressHex, chainId: "demos:testnet",
  maximumConcurrentEffects: 1, maximumRetainedReservations: 1_000,
  assets: [{ asset: "DEM", maximumPerOrderDebit: env["MAX_ORDER_OS"] ?? "20000000000", maximumNetworkFeeDebit: maxFeeOs.toString(), minimumReserve: "5000000000",
    rollingWindowMs: 3_600_000, maximumRollingEffects: 10, maximumRollingDebit: "100000000000", maximumCumulativeDebit: "1000000000000", maximumCounterpartyDebit: "100000000000" }],
} as const;
// The spend authority binds its ledger to the exact policy and refuses a
// ledger written under another one. Key the ledger file by the policy so a
// policy change (for example a fee ceiling) opens a fresh ledger and leaves
// the previous one on disk for audit instead of failing every settlement.
const spendPolicyTag = sha256Hex(`dacs-wallet-spend-policy:v1:${canonicalize(spendPolicy as unknown as Record<string, unknown>)}`).slice(0, 16);
// SPEND_LEDGER_EPOCH is an operator decision: bump it only after every held
// reservation in the current ledger has been checked against the chain and
// found never broadcast. The old ledger stays on disk.
const spendLedgerEpoch = env["SPEND_LEDGER_EPOCH"] ?? "1";
if (!/^[0-9]{1,6}$/.test(spendLedgerEpoch)) throw new Error("SPEND_LEDGER_EPOCH must be a small integer");
const spendLedgerPath = join(role.root, `wallet-spend-${spendPolicyTag}-e${spendLedgerEpoch}.db`);
log({ event: "spend-ledger", path: spendLedgerPath, policyTag: spendPolicyTag, epoch: spendLedgerEpoch, maxNetworkFeeOs: maxFeeOs.toString() });
const spendStore = createSqliteWalletSpendStateStore({ path: spendLedgerPath });
configureSettlementEvidenceStore(join(role.root, "settlement-evidence.json"));
// One writer per wallet: anchors (vet, commitment) and the pay-dem transfer
// all carry the account nonce, so they must not be in flight together.
const walletLock = createSerialLock();
const lockedChain = { ...role.chain, anchorArtifact: (input: Parameters<typeof role.chain.anchorArtifact>[0]) => walletLock(() => role.chain.anchorArtifact(input)) };
const txReader = role.actor.adapter.raw as { getTxByHash(hash: string): Promise<unknown> };
const spend = createWalletSpendAuthorityV1(spendPolicy, {
  store: spendStore,
  readBalance: async () => (await role.actor.balanceOs()).toString(),
  // A settled observation is authenticated by reading the transfer back from
  // the node; absence is never authenticated by this process.
  authenticateRecovery: createPayDemSettlementAuthenticator({ reader: txReader, payerAddressHex: role.actor.addressHex, log }),
  leaseDurationMs: 60_000,
});

const service = createBuyerNegotiationService({
  buyerClaim: role.actor.claim,
  buyerParty: { identityBundle: identity, vetRecordRef: { anchor: { kind: "storage-program", locator: "pending" }, contentHash: "0".repeat(64) } },
  client: role.client, transport: role.transport, inbox: role.inbox, sessions: role.sessions,
  catalog,
  ceiling: createBuyerCeilingGuard({ amount: env["BUYER_CEILING_DEM"] ?? "9.8", currency: "DEM" }),
  vet: createBuyerVetExchange({ store: lockedChain, self: role.actor.signer, seller: role.counterpart, log }),
  commit: (record, vl) => walletLock(() => commitNegotiatedAgreement({
    record, verifiedListing: vl, orchestrator: role.actor.claim, provider: finality, verifySignature,
    commitmentSigner: { algorithm: "ed25519", signer: role.actor.claim, sign: (bytes: Uint8Array) => role.actor.signer.sign(bytes) },
  })),
  settle: (record, commitment) => walletLock(() => settleWithPayDem({ rail, authority: spend, agreement: record.agreement!.finalized!, commitment, maximumNetworkFeeOs: maxFeeOs.toString(), recover: { reader: txReader }, log })),
  log,
});
const mcp = await startBuyerMcpServer({ service, bearerToken: token, port: Number(env["MCP_PORT"] ?? 47110), log });
const showcase = await startShowcaseServer({ client: role.client, sessions: role.sessions, buyerClaim: role.actor.claim, sellerDisplayName: "the seller agent",
  transportLabel: role.transportKind === "l2ps" ? `encrypted L2PS subnet ${role.subnetUid} on the self-hosted node` : "interim direct transport; L2PS transport pending",
  ...(role.subnetClient === undefined ? {} : { subnetExhibit: async () => ({ uid: role.subnetUid!, host: role.subnetRpc!, rows: await role.subnetClient!.history({ limit: 100 }) }) }), lastErrorFor: (jobId) => service.lastError(jobId), port: Number(env["SHOWCASE_PORT"] ?? 47120), log });
log({ event: "buyer-running", mcp: mcp.endpoint, showcase: showcase.endpoint, transport: role.server.endpoint, ceilingDem: env["BUYER_CEILING_DEM"] ?? "9.8" });
process.stdout.write(`MCP_ENDPOINT=${mcp.endpoint}\nSHOWCASE_URL=${showcase.endpoint}\n`);
const stop = async () => { await showcase.close(); await mcp.close(); await role.server.close(); process.exit(0); };
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
setInterval(() => { service.tick().catch((e) => log({ event: "tick-error", reason: String(e) })); }, Number(env["BUYER_TICK_MS"] ?? 3_000));
