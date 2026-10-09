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
      // `all` is bounded: once the cap of approved claims is reached, further
      // requests wait for the operator instead of being provisioned and funded.
      const cap = options.autoApproveMax ?? 20;
      const capped = options.autoApprove === "all" && !listed && options.store.approvedClaims().length >= cap;
      if (outcome === "stored" && auto && capped) log({ event: "registration-auto-approve-capped", claim, approved: options.store.approvedClaims().length, cap });
      if (outcome === "stored" && auto && !capped) {
        try { await service.approve(claim); } catch (cause) { log({ event: "registration-auto-approve-failed", claim, reason: cause instanceof Error ? cause.message : String(cause) }); }
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
