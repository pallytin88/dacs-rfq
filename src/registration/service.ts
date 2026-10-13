/**
 * Registration service: testers submit a signed request, the operator
 * approves, and approval provisions a private subnet on the host node, funds
 * the tester on the host chain, and seals the credential to the tester's key.
 * Approved claims become admitted peers of the seller.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { canonicalDemosAgentPublicKey } from "@kynesyslabs/dacs/identity";
import { sealCredential } from "./credential.js";
import type { SealedCredential } from "./credential.js";
import { verifyRegistrationRequest } from "./request.js";
import { createSerialLock } from "../walletLock.js";
import type { RegistrationStore, RegistrationRow } from "./store.js";

export interface ProvisionedSubnet { uid: string; keyHex: string; ivHex: string }

export interface SubnetProvisioner {
  /** Create a fresh subnet for this claim on the host node; returns its uid and key material. */
  createSubnet(claim: string): Promise<ProvisionedSubnet>;
  /** Key material of a subnet this provisioner created earlier, or null when it has none. */
  loadSubnet(uid: string): Promise<ProvisionedSubnet | null>;
}

export interface LocalFunder {
  /**
   * Transfer host-chain funds to the tester's wallet; returns the transaction
   * hash. `onSigned` receives that hash before the broadcast so the caller can
   * record it first; the fund must not be broadcast if `onSigned` throws.
   */
  fund(addressHex: string, onSigned: (txHash: string) => void | Promise<void>): Promise<{ txHash: string }>;
  /** Whole DEM sent per approval, for the operator's own accounting/logs. */
  amountDem?: number;
}

export interface RegistrationServiceOptions {
  store: RegistrationStore;
  provisioner: SubnetProvisioner;
  funder?: LocalFunder;
  /** Host node RPC the tester should use for the subnet. */
  host: string;
  /**
   * Operator policy: claims approved without a manual step. `"all"` approves
   * every authenticated request (open test network); otherwise an exact list.
   * Default: nothing, every request waits for `approve`.
   */
  autoApprove?: "all" | readonly string[];
  /**
   * With `autoApprove: "all"`, the number of approved claims after which new
   * requests wait for the operator (each approval provisions a subnet and
   * funds a wallet). Default 20. Listed claims are never capped.
   */
  autoApproveMax?: number;
  /** Total DEM unattended approvals may fund; default `autoApproveMax` × the funder's per-approval amount. */
  autoApproveMaxFundDem?: number;
  nowMs?: () => number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface RegistrationStatusView {
  status: "pending" | "approved" | "rejected" | "unknown";
  uid?: string;
  host?: string;
  credential?: SealedCredential;
  note?: string;
}

export interface RegistrationService {
  submit(body: unknown): Promise<{ status: number; body: Record<string, unknown> }>;
  status(claim: string): Promise<{ status: number; body: RegistrationStatusView }>;
  approve(claim: string): Promise<RegistrationRow>;
  reject(claim: string, note: string): RegistrationRow;
  list(status?: "pending" | "approved" | "rejected"): RegistrationRow[];
  admittedClaims(): string[];
}

export function createRegistrationService(options: RegistrationServiceOptions): RegistrationService {
  const nowMs = options.nowMs ?? Date.now;
  const log = options.log ?? (() => {});
  const approvals = createSerialLock();
  const fundDem = options.funder?.amountDem ?? 0;
  /**
   * `autoApprove: "all"` is bounded two ways: by the number of claims
   * provisioned unattended (`autoApproveMax`, default 20) and by the DEM those
   * approvals may send in total (`autoApproveMaxFundDem`, default cap × the
   * per-approval amount). Rows that already hold a funding hash count, so an
   * approval interrupted after its broadcast still spends its share.
   */
  const unattendedBudgetExhausted = (): Record<string, number> | null => {
    const cap = options.autoApproveMax ?? 20;
    const rows = options.store.list();
    const provisioned = rows.filter((r) => r.status === "approved" || r.fundingTx !== undefined);
    const spentDem = provisioned.filter((r) => r.fundingTx !== undefined).length * fundDem;
    const maxFundDem = options.autoApproveMaxFundDem ?? cap * fundDem;
    if (provisioned.length >= cap) return { approved: provisioned.length, cap };
    if (fundDem > 0 && spentDem + fundDem > maxFundDem) return { spentDem, nextDem: fundDem, maxFundDem };
    return null;
  };
  const service: RegistrationService = {
    async submit(body) {
      const verified = verifyRegistrationRequest(body, nowMs());
      if (!verified.ok) {
        log({ event: "registration-rejected", reason: verified.reason });
        return { status: 400, body: { error: "registration-not-authenticated", reason: verified.reason } };
      }
      const outcome = options.store.submit(verified.request, nowMs());
      log({ event: "registration-submitted", claim: verified.request.claim, outcome });
      if (outcome === "conflict") return { status: 409, body: { error: "claim already registered with another encryption key" } };
      const claim = verified.request.claim;
      const listed = Array.isArray(options.autoApprove) && options.autoApprove.includes(claim);
      const auto = options.autoApprove === "all" || listed;
      if (outcome === "stored" && auto) {
        // The budget check and the approval run under one lock, so two
        // overlapping submits cannot both read a count under the cap.
        await approvals(async () => {
          const budget = unattendedBudgetExhausted();
          if (budget !== null && !listed) { log({ event: "registration-auto-approve-capped", claim, ...budget }); return; }
          try { await service.approve(claim); } catch (cause) { log({ event: "registration-auto-approve-failed", claim, reason: cause instanceof Error ? cause.message : String(cause) }); }
        });
      }
      const row = options.store.get(claim)!;
      return { status: outcome === "stored" ? 202 : 200, body: { status: row.status, claim: row.claim } };
    },
    async status(claim) {
      const row = options.store.get(claim);
      if (row === null) return { status: 404, body: { status: "unknown" } };
      if (row.status !== "approved") return { status: 200, body: { status: row.status, ...(row.note === undefined ? {} : { note: row.note }) } };
      return { status: 200, body: { status: "approved", uid: row.uid!, host: options.host, credential: JSON.parse(row.credentialJson!) as SealedCredential } };
    },
    async approve(claim) {
      const row = options.store.get(claim);
      if (row === null || row.status !== "pending") throw new Error(`registration ${claim} is not pending`);
      const key = canonicalDemosAgentPublicKey(claim);
      if (key === null) throw new Error("stored claim is not a Demos agent claim");
      // Each step is recorded before the next starts, so an approval that was
      // interrupted (crash after the funding broadcast, say) resumes from the
      // row: the subnet already minted is reused and a funded claim is never
      // funded again.
      let subnet: ProvisionedSubnet;
      if (row.uid !== undefined) {
        const existing = await options.provisioner.loadSubnet(row.uid);
        if (existing === null) throw new Error(`registration ${claim} names subnet ${row.uid}, which the provisioner cannot load`);
        subnet = existing;
        log({ event: "registration-resumed", claim, uid: row.uid });
      } else {
        subnet = await options.provisioner.createSubnet(claim);
        options.store.beginProvision(claim, subnet.uid, nowMs());
      }
      let fundingTx: string | undefined = row.fundingTx;
      if (options.funder !== undefined && fundingTx === undefined) {
        const at = nowMs();
        ({ txHash: fundingTx } = await options.funder.fund(Buffer.from(key).toString("hex"), (txHash) => { options.store.beginFunding(claim, txHash, at); }));
      }
      const credential = sealCredential(row.encryptionPublicKey, { uid: subnet.uid, keyHex: subnet.keyHex, ivHex: subnet.ivHex, host: options.host, ...(fundingTx === undefined ? {} : { fundingTx }) });
      options.store.approve(claim, { uid: subnet.uid, credentialJson: JSON.stringify(credential), ...(fundingTx === undefined ? {} : { fundingTx }) }, nowMs());
      log({ event: "registration-approved", claim, uid: subnet.uid, fundingTx });
      return options.store.get(claim)!;
    },
    reject(claim, note) {
      options.store.reject(claim, note, nowMs());
      log({ event: "registration-rejected-by-operator", claim, note });
      return options.store.get(claim)!;
    },
    list: (status) => options.store.list(status),
    admittedClaims: () => options.store.approvedClaims(),
  };
  return service;
}

/**
 * Provisioner for a node we operate: writes `data/l2ps/<uid>/` with fresh key
 * material and a config the node loads on demand (or at the next restart).
 */
export function createFsSubnetProvisioner(options: { nodeRoot: string; rpc: string; uidPrefix?: string }): SubnetProvisioner {
  return {
    async createSubnet(claim) {
      const key = canonicalDemosAgentPublicKey(claim);
      if (key === null) throw new Error("claim is not a Demos agent claim");
      const uid = `${options.uidPrefix ?? "rfq"}_${Buffer.from(key).toString("hex").slice(0, 12)}_${randomBytes(3).toString("hex")}`;
      const dir = join(options.nodeRoot, "data", "l2ps", uid);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const keyHex = randomBytes(32).toString("hex");
      const ivHex = randomBytes(16).toString("hex");
      writeFileSync(join(dir, "private_key.txt"), `${keyHex}\n`, { mode: 0o600 });
      writeFileSync(join(dir, "iv.txt"), `${ivHex}\n`, { mode: 0o600 });
      writeFileSync(join(dir, "config.json"), JSON.stringify({
        uid, enabled: true, config: { created_at_block: 0, known_rpcs: [options.rpc] },
        keys: { private_key_path: `data/l2ps/${uid}/private_key.txt`, iv_path: `data/l2ps/${uid}/iv.txt` },
      }, null, 2), { mode: 0o600 });
      return { uid, keyHex, ivHex };
    },
    async loadSubnet(uid) {
      if (!/^[A-Za-z0-9_]+$/.test(uid)) return null;
      const dir = join(options.nodeRoot, "data", "l2ps", uid);
      if (!existsSync(join(dir, "private_key.txt")) || !existsSync(join(dir, "iv.txt"))) return null;
      return { uid, keyHex: readFileSync(join(dir, "private_key.txt"), "utf8").trim(), ivHex: readFileSync(join(dir, "iv.txt"), "utf8").trim() };
    },
  };
}
