/**
 * Step 6 settlement leg: pay the committed RFQ price over the native DEM rail,
 * behind the SDK's wallet-wide spend authority.
 *
 * The seller never reads a plaintext agreement from chain (dacs-sdk#331); the
 * buyer pays the exact `terms.price` of the co-signed agreement it holds
 * locally, and the finality commitment at `dacs3:commit:{jobId}` is the only
 * on-chain reference. The payment amount itself is public on the rail.
 */

import { canonicalize, sha256Hex } from "@kynesyslabs/dacs/canonical";
import type { AgreementArtifact } from "@kynesyslabs/dacs/artifacts";
import { canonicalDemosAgentPublicKey } from "@kynesyslabs/dacs/identity";
import { executeWalletSpendEffectV1 } from "@kynesyslabs/dacs/rails";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { SettleResult } from "@kynesyslabs/dacs";
import type {
  PayDemRail,
  WalletSpendAuthorityV1,
  WalletSpendReservationV1,
  WalletSpendSettlementObservationV1,
} from "@kynesyslabs/dacs/rails";
import type { FinalizedAgreementCommitment } from "@kynesyslabs/dacs/negotiate";

export const PAY_DEM_RAIL_ID = "pay-dem:native-transfer:v1" as const;
const DEM_DECIMALS = 9n; // 1 DEM = 10^9 OS

export interface SettleOptions {
  /** When set, an included-but-failed transfer remembered for this job is reconciled as terminal absence and the effect retried once. */
  recover?: { reader: DemosTransactionReader };
  rail: Readonly<PayDemRail>;
  authority: WalletSpendAuthorityV1;
  agreement: Readonly<AgreementArtifact>;
  commitment: Readonly<FinalizedAgreementCommitment>;
  /** Network fee ceiling in OS for the reservation. */
  maximumNetworkFeeOs: string;
  nowMs?: () => number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export type SettleOutcome =
  | { status: "settled"; txHash: string; amountOs: string; payee: string; evidenceHash: string }
  | { status: "held" | "settled-before" | "released" | "conflict" | "denied"; reason: string };

/** Convert a canonical DEM decimal amount to integer OS. */
export function demToOs(amount: string): string {
  const [whole, fraction = ""] = amount.split(".");
  if (!/^(0|[1-9][0-9]*)$/.test(whole) || !/^[0-9]*$/.test(fraction) || BigInt(fraction.length) > DEM_DECIMALS) {
    throw new Error(`amount ${amount} is not a valid DEM amount`);
  }
  const scaled = BigInt(`${whole}${fraction}`) * 10n ** (DEM_DECIMALS - BigInt(fraction.length));
  return scaled.toString();
}

/** Native Demos address (hex of the agent's Ed25519 key) from a canonical Demos agent claim. */
export function demosAddressFromClaim(claim: string): string | null {
  const key = canonicalDemosAgentPublicKey(claim);
  return key === null ? null : Buffer.from(key).toString("hex");
}

function sellerClaim(agreement: Readonly<AgreementArtifact>): string {
  const seller = agreement.parties.find((party) => party.role === "seller");
  if (seller === undefined) throw new Error("agreement has no seller party");
  return seller.primaryClaim;
}

export function buildPayDemReservation(input: {
  agreement: Readonly<AgreementArtifact>;
  commitment: Readonly<FinalizedAgreementCommitment>;
  wallet: string;
  chainId: string;
  maximumNetworkFeeOs: string;
}): WalletSpendReservationV1 {
  const price = input.agreement.terms.price;
  if (price.currency !== "DEM") throw new Error(`pay-dem settlement requires DEM, got ${price.currency}`);
  const amountOs = demToOs(price.amount);
  const payeeAddress = demosAddressFromClaim(sellerClaim(input.agreement));
  if (payeeAddress === null) throw new Error("seller claim does not resolve to a Demos address");
  const settlementBinding = {
    settlementBindingVersion: "1",
    jobId: input.agreement.jobId,
    agreementHash: input.commitment.agreementHash,
    commitmentAddress: input.commitment.nativeAddress,
    rail: PAY_DEM_RAIL_ID,
    payee: payeeAddress,
    amountOs,
  };
  return {
    reservationVersion: "1",
    reservationId: `pay-dem:${input.agreement.jobId}`,
    jobId: input.agreement.jobId,
    phaseIndex: 0,
    phase: "pay-dem",
    agreementHash: input.commitment.agreementHash,
    settlementBindingHash: sha256Hex(canonicalize(settlementBinding)),
    railId: PAY_DEM_RAIL_ID,
    railDefinitionHash: sha256Hex(`dacs-rail:${PAY_DEM_RAIL_ID}`),
    wallet: input.wallet,
    chainId: input.chainId,
    payee: payeeAddress,
    finality: { model: "demos-bft-final" },
    debits: [
      { asset: "DEM", purpose: "service", expectedAmount: amountOs, maximumAmount: amountOs },
      { asset: "DEM", purpose: "network-fee", expectedAmount: "0", maximumAmount: input.maximumNetworkFeeOs },
    ],
  };
}

/**
 * Reserve → pay → record, with the spend authority fence asserted beside the
 * broadcast. Idempotent: a second call for the same job returns the retained
 * outcome instead of paying twice.
 */
export async function settleWithPayDem(options: SettleOptions): Promise<SettleOutcome> {
  const log = options.log ?? (() => {});
  const reservation = buildPayDemReservation({
    agreement: options.agreement,
    commitment: options.commitment,
    wallet: options.authority.policy.wallet,
    chainId: options.authority.policy.chainId,
    maximumNetworkFeeOs: options.maximumNetworkFeeOs,
  });
  const amountOs = reservation.debits[0]!.expectedAmount;
  const result = await executeWalletSpendEffectV1<SettleResult>({
    authority: options.authority,
    reservation,
    async effect(fence) {
      return options.rail.settle({
        recipient: reservation.payee,
        amount: amountOs,
        network: "demos",
        maxTotalDebitOs: (BigInt(amountOs) + BigInt(options.maximumNetworkFeeOs)).toString(),
        assertCurrentBeforeBroadcast: () => fence.assertCurrent(),
      });
    },
    async settlement(settled): Promise<WalletSpendSettlementObservationV1> {
      // The rail settles `ok: false` when the transfer did not reach observed
      // inclusion (timeout or failed). That is not a settlement: throw so the
      // reservation stays effect-pending for read-only reconciliation, and
      // never project an unobserved payment as a debit.
      const detail = settled as SettleResult & { state?: string; message?: string };
      if (settled.ok !== true) {
        log({ event: "settlement-rail-not-included", jobId: options.agreement.jobId, txHash: settled.txHash, state: detail.state, message: detail.message });
        throw new Error(`pay-dem transfer did not reach observed inclusion (${detail.state ?? "unknown"}): ${detail.message ?? settled.txHash}`);
      }
      log({ event: "settlement-rail-included", jobId: options.agreement.jobId, txHash: settled.txHash, blockNumber: settled.blockNumber });
      const evidence = { txHash: settled.txHash, amountOs, payee: reservation.payee };
      rememberSettlementEvidence(sha256Hex(canonicalize(evidence)), { txHash: settled.txHash, amountOs, payee: reservation.payee, reservationId: reservation.reservationId });
      // Every reserved debit needs an actual entry. The native rail reports the
      // service transfer exactly; the network fee actually charged is not
      // surfaced by SettleResult, so it is accounted at the reserved ceiling
      // (conservative: never under-counts the wallet's exposure).
      return {
        disposition: "settled",
        evidenceHash: sha256Hex(canonicalize(evidence)),
        debits: [
          { asset: "DEM", purpose: "service", amount: amountOs },
          { asset: "DEM", purpose: "network-fee", amount: options.maximumNetworkFeeOs },
        ],
      };
    },
  }).catch((cause: unknown): Awaited<ReturnType<typeof executeWalletSpendEffectV1<SettleResult>>> => {
    // A throw after the effect may mean the transfer happened; the authority
    // keeps the reservation effect-pending, so report held and never retry blindly.
    const reason = cause instanceof Error ? cause.message : String(cause);
    log({ event: "settlement-error", jobId: options.agreement.jobId, reason });
    return { status: "held", bindingHash: "", stage: "effect-pending" } as const;
  });
  if (result.status === "held" && result.stage === "effect-pending" && options.recover !== undefined) {
    // A transfer this process remembered may have been included as `failed`
    // (for example a nonce race). That hash can never settle, so it is a
    // terminal absence the authority can release after independent
    // re-verification; the effect is then retried once under a fresh generation.
    const recovered = await reconcileFailedPayDemTransfer({ authority: options.authority, reservation, reader: options.recover.reader, log });
    if (recovered === "released") {
      log({ event: "settlement-retry", jobId: options.agreement.jobId });
      return settleWithPayDem({ ...options, recover: undefined });
    }
  }
  if (result.status === "completed") {
    const evidence = { txHash: result.result.txHash, amountOs, payee: reservation.payee };
    const outcome: SettleOutcome = {
      status: "settled", txHash: result.result.txHash, amountOs, payee: reservation.payee,
      evidenceHash: sha256Hex(canonicalize(evidence)),
    };
    log({ event: "settlement", jobId: options.agreement.jobId, ...outcome });
    return outcome;
  }
  const mapped: SettleOutcome = result.status === "settled"
    ? { status: "settled-before", reason: `already settled (evidence ${result.evidenceHash})` }
    : result.status === "held"
      ? { status: "held", reason: `reservation held at stage ${result.stage}` }
      : result.status === "released"
        ? { status: "released", reason: "reservation was released" }
        : result.status === "conflict"
          ? { status: "conflict", reason: "a different reservation owns this job" }
          : { status: "denied", reason: String((result as { reason?: unknown }).reason ?? "denied") };
  log({ event: "settlement", jobId: options.agreement.jobId, ...mapped });
  return mapped;
}


/* ------------------------ settlement authentication ------------------------ */

export interface SettlementEvidenceEntry {
  txHash: string;
  amountOs: string;
  payee: string;
  reservationId?: string;
}

/** Evidence hash → the transfer it stands for, kept so the authority can re-authenticate it on chain. */
const settlementEvidence = new Map<string, SettlementEvidenceEntry>();
let evidencePath: string | undefined;

/** Persist remembered evidence (0600) so authentication and recovery survive a restart. */
export function configureSettlementEvidenceStore(path: string): void {
  evidencePath = path;
  if (existsSync(path)) {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, SettlementEvidenceEntry>;
    for (const [hash, entry] of Object.entries(parsed)) settlementEvidence.set(hash, entry);
  }
}

function persistEvidence(): void {
  if (evidencePath === undefined) return;
  mkdirSync(dirname(evidencePath), { recursive: true, mode: 0o700 });
  writeFileSync(evidencePath, JSON.stringify(Object.fromEntries(settlementEvidence)), { mode: 0o600 });
}

export function rememberSettlementEvidence(evidenceHash: string, entry: SettlementEvidenceEntry): void {
  settlementEvidence.set(evidenceHash, entry);
  persistEvidence();
}

export function settlementEvidenceFor(evidenceHash: string): SettlementEvidenceEntry | undefined {
  return settlementEvidence.get(evidenceHash);
}

function evidenceForReservation(reservationId: string): [string, SettlementEvidenceEntry] | undefined {
  for (const pair of settlementEvidence) if (pair[1].reservationId === reservationId) return pair;
  return undefined;
}

/** Read a transaction back from the node in the shape both authenticators check. */
async function readTransfer(reader: DemosTransactionReader, txHash: string) {
  const observed = await reader.getTxByHash(txHash);
  const tx = (observed as { response?: unknown })?.response ?? observed;
  const record = tx as { status?: unknown; hash?: unknown; blockNumber?: unknown; content?: { from?: unknown; to?: unknown; amount?: unknown; data?: unknown } };
  return { record, content: record.content ?? {} };
}

/**
 * A transfer that the chain included with status `failed` can never settle:
 * its hash is spent and its nonce was consumed. Only that exact observation
 * authenticates a terminal absence; a merely unseen transaction never does.
 */
export async function isTerminallyFailedTransfer(reader: DemosTransactionReader, txHash: string): Promise<boolean> {
  try {
    const { record } = await readTransfer(reader, txHash);
    return record.status === "failed" && hex64(record.hash) === hex64(txHash) && Number.isSafeInteger(record.blockNumber);
  } catch {
    return false;
  }
}

/**
 * Operator/automatic reconciliation of a held pay-dem reservation whose
 * remembered transfer was included as `failed`. Re-verifies on chain, then
 * asks the authority to release the reservation as terminal absence. Returns
 * the authority's answer, or `"unrecoverable"` when nothing can be proven.
 */
export async function reconcileFailedPayDemTransfer(input: {
  authority: Pick<WalletSpendAuthorityV1, "reconcile">;
  reservation: WalletSpendReservationV1;
  reader: DemosTransactionReader;
  txHash?: string;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}): Promise<"settled" | "released" | "existing" | "unrecoverable"> {
  const log = input.log ?? (() => {});
  let pair = evidenceForReservation(input.reservation.reservationId);
  if (pair === undefined && input.txHash !== undefined) {
    const entry: SettlementEvidenceEntry = { txHash: input.txHash, amountOs: input.reservation.debits[0]!.expectedAmount, payee: input.reservation.payee, reservationId: input.reservation.reservationId };
    const hash = sha256Hex(canonicalize({ txHash: input.txHash, amountOs: entry.amountOs, payee: entry.payee }));
    rememberSettlementEvidence(hash, entry);
    pair = [hash, entry];
  }
  if (pair === undefined) return "unrecoverable";
  const [evidenceHash, entry] = pair;
  if (!await isTerminallyFailedTransfer(input.reader, entry.txHash)) {
    log({ event: "settlement-recovery", reservationId: input.reservation.reservationId, txHash: entry.txHash, result: "not-terminally-failed" });
    return "unrecoverable";
  }
  try {
    const result = await input.authority.reconcile(input.reservation, { disposition: "terminal-absent", evidenceHash });
    log({ event: "settlement-recovery", reservationId: input.reservation.reservationId, txHash: entry.txHash, result });
    return result;
  } catch (cause) {
    log({ event: "settlement-recovery", reservationId: input.reservation.reservationId, txHash: entry.txHash, result: "refused", reason: cause instanceof Error ? cause.message : String(cause) });
    return "unrecoverable";
  }
}

export interface DemosTransactionReader {
  getTxByHash(hash: string): Promise<unknown>;
}

const hex64 = (value: unknown): string | null => {
  if (typeof value !== "string") return null;
  const match = /^(?:0x)?([0-9a-fA-F]{64})$/.exec(value.trim());
  return match === null ? null : match[1]!.toLowerCase();
};

const amountOf = (value: unknown): string | null => {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return value;
  return null;
};

/**
 * `authenticateRecovery` for the wallet spend authority on the pay-dem rail:
 * a settled observation is authenticated only by reading the transfer back
 * from the node (confirmed, this payer, the reserved payee, the exact amount).
 * Absence is never authenticated here: a held reservation stays held until an
 * operator reconciles it, because this process cannot prove a transfer did
 * not happen.
 */
export function createPayDemSettlementAuthenticator(options: {
  reader: DemosTransactionReader;
  payerAddressHex: string;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}): (reservation: unknown, observation: Readonly<{ disposition: string; evidenceHash: string }>) => Promise<boolean> {
  const log = options.log ?? (() => {});
  const payer = options.payerAddressHex.toLowerCase();
  return async (_reservation, observation) => {
    const entry = settlementEvidence.get(observation.evidenceHash);
    if (entry === undefined) {
      log({ event: "settlement-authentication", ok: false, reason: "evidence not produced by this buyer" });
      return false;
    }
    if (observation.disposition === "terminal-absent") {
      // Only an included-but-failed transaction proves absence; `not-invoked` is never claimed here.
      const failed = await isTerminallyFailedTransfer(options.reader, entry.txHash);
      log({ event: "settlement-authentication", ok: failed, txHash: entry.txHash, disposition: "terminal-absent" });
      return failed;
    }
    if (observation.disposition !== "settled") return false;
    try {
      const { record, content } = await readTransfer(options.reader, entry.txHash);
      const args = Array.isArray(content.data) && Array.isArray((content.data as unknown[])[1]) ? ((content.data as unknown[])[1] as unknown[]) : [];
      const tupleArgs = Array.isArray(content.data) && (content.data as unknown[])[1] !== null && typeof (content.data as unknown[])[1] === "object"
        ? (((content.data as unknown[])[1] as { args?: unknown[] }).args ?? []) : args;
      const amountMatches = amountOf(content.amount) === entry.amountOs || tupleArgs.some((a) => amountOf(a) === entry.amountOs);
      const ok = record.status === "confirmed" && hex64(record.hash) === hex64(entry.txHash)
        && hex64(content.from) === payer && hex64(content.to) === hex64(entry.payee) && amountMatches;
      log({ event: "settlement-authentication", ok, txHash: entry.txHash, status: record.status });
      return ok;
    } catch (cause) {
      log({ event: "settlement-authentication", ok: false, reason: cause instanceof Error ? cause.message : String(cause) });
      return false;
    }
  };
}
