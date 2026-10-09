#!/usr/bin/env -S node --import tsx
/**
 * Operator reconciliation of a held pay-dem reservation (read-only on chain,
 * then one authority call). Only an included-but-failed transfer is accepted
 * as terminal absence; anything else leaves the hold in place.
 *
 *   tsx bin/reconcile.mts <jobId> <txHash>
 *
 * Runs against the buyer's current spend ledger (same policy/epoch as
 * `buyer.mts run`), so stop the buyer first.
 */
import { join } from "node:path";
import type { FinalizedAgreementCommitment } from "@kynesyslabs/dacs/negotiate";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs/canonical";
import { createWalletSpendAuthorityV1 } from "@kynesyslabs/dacs/rails";
import {
  buildPayDemReservation, configureSettlementEvidenceStore, createPayDemSettlementAuthenticator, createSqliteWalletSpendStateStore, reconcileFailedPayDemTransfer,
} from "../src/index.js";
import { bootstrapRole, loadConfig, log } from "./common.mts";

const [jobId, txHash] = process.argv.slice(2);
if (!jobId || !txHash) throw new Error("usage: reconcile.mts <jobId> <txHash>");
const env = loadConfig();
const role = await bootstrapRole("buyer", env, Number(env["BUYER_TRANSPORT_PORT"] ?? 47102));
const maxFeeOs = BigInt(env["MAX_NETWORK_FEE_OS"] ?? "2000000000");
const spendPolicy = {
  policyVersion: "1", policyId: "supercolony-rfq-buyer", wallet: role.actor.addressHex, chainId: "demos:testnet",
  maximumConcurrentEffects: 1, maximumRetainedReservations: 1_000,
  assets: [{ asset: "DEM", maximumPerOrderDebit: env["MAX_ORDER_OS"] ?? "20000000000", maximumNetworkFeeDebit: maxFeeOs.toString(), minimumReserve: "5000000000",
    rollingWindowMs: 3_600_000, maximumRollingEffects: 10, maximumRollingDebit: "100000000000", maximumCumulativeDebit: "1000000000000", maximumCounterpartyDebit: "100000000000" }],
} as const;
const tag = sha256Hex(`dacs-wallet-spend-policy:v1:${canonicalize(spendPolicy as unknown as Record<string, unknown>)}`).slice(0, 16);
const epoch = env["SPEND_LEDGER_EPOCH"] ?? "1";
const ledger = join(role.root, `wallet-spend-${tag}-e${epoch}.db`);
configureSettlementEvidenceStore(join(role.root, "settlement-evidence.json"));
const txReader = role.actor.adapter.raw as { getTxByHash(hash: string): Promise<unknown> };
const authority = createWalletSpendAuthorityV1(spendPolicy, {
  store: createSqliteWalletSpendStateStore({ path: ledger }),
  readBalance: async () => (await role.actor.balanceOs()).toString(),
  authenticateRecovery: createPayDemSettlementAuthenticator({ reader: txReader, payerAddressHex: role.actor.addressHex, log }),
  leaseDurationMs: 60_000,
});
const entry = role.sessions.get(jobId);
if (entry === null || entry.commitment === undefined) throw new Error(`job ${jobId} has no commitment in this buyer`);
const status = await role.client.getStatus(jobId);
if (status.status !== "ok" || status.record.agreement?.finalized === undefined) throw new Error(`job ${jobId} has no finalized agreement`);
const reservation = buildPayDemReservation({
  agreement: status.record.agreement.finalized, commitment: entry.commitment as unknown as FinalizedAgreementCommitment,
  wallet: role.actor.addressHex, chainId: "demos:testnet", maximumNetworkFeeOs: maxFeeOs.toString(),
});
log({ event: "reconcile-start", jobId, txHash, ledger, reservationId: reservation.reservationId });
const result = await reconcileFailedPayDemTransfer({ authority, reservation, reader: txReader, txHash, log });
log({ event: "reconcile-result", jobId, result });
await role.server.close();
process.exit(result === "released" || result === "existing" ? 0 : 1);
