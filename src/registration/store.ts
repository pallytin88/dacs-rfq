/**
 * Durable registration queue (SQLite, 0600): one row per claim through
 * pending → approved | rejected. The approved row keeps the sealed credential
 * so the tester can fetch it again after a restart on either side.
 */

import BetterSqlite3 from "better-sqlite3";
import type { Database } from "better-sqlite3";
import { closeSync, mkdirSync, openSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import type { RegistrationRequest } from "./request.js";

export type RegistrationStatus = "pending" | "approved" | "rejected";

export interface RegistrationRow {
  claim: string;
  encryptionPublicKey: string;
  requestedAt: number;
  status: RegistrationStatus;
  uid?: string;
  credentialJson?: string;
  fundingTx?: string;
  note?: string;
  updatedAt: number;
}

export interface RegistrationStore {
  submit(request: Readonly<RegistrationRequest>, nowMs: number): "stored" | "duplicate" | "conflict";
  get(claim: string): RegistrationRow | null;
  list(status?: RegistrationStatus): RegistrationRow[];
  approve(claim: string, input: Readonly<{ uid: string; credentialJson: string; fundingTx?: string }>, nowMs: number): void;
  reject(claim: string, note: string, nowMs: number): void;
  approvedClaims(): string[];
  close(): void;
}

export function createRegistrationStore(options: { path: string }): RegistrationStore {
  if (!isAbsolute(options.path)) throw new Error("registration store path must be absolute");
  mkdirSync(dirname(options.path), { recursive: true, mode: 0o700 });
  closeSync(openSync(options.path, "a", 0o600));
  if ((statSync(options.path).mode & 0o077) !== 0) throw new Error(`${options.path} must not be group/world accessible`);
  const db: Database = new BetterSqlite3(options.path, { timeout: 5_000 });
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.exec(`CREATE TABLE IF NOT EXISTS registrations (
    claim TEXT PRIMARY KEY NOT NULL, encryption_key TEXT NOT NULL, requested_at INTEGER NOT NULL,
    status TEXT NOT NULL, uid TEXT, credential_json TEXT, funding_tx TEXT, note TEXT, updated_at INTEGER NOT NULL
  ) WITHOUT ROWID;`);
  const toRow = (r: Record<string, unknown>): RegistrationRow => ({
    claim: r["claim"] as string, encryptionPublicKey: r["encryption_key"] as string, requestedAt: r["requested_at"] as number,
    status: r["status"] as RegistrationStatus, updatedAt: r["updated_at"] as number,
    ...(r["uid"] ? { uid: r["uid"] as string } : {}), ...(r["credential_json"] ? { credentialJson: r["credential_json"] as string } : {}),
    ...(r["funding_tx"] ? { fundingTx: r["funding_tx"] as string } : {}), ...(r["note"] ? { note: r["note"] as string } : {}),
  });
  const getStmt = db.prepare("SELECT * FROM registrations WHERE claim = ?");
  return {
    submit(request, nowMs) {
      const existing = getStmt.get(request.claim) as Record<string, unknown> | undefined;
      if (existing !== undefined) return existing["encryption_key"] === request.encryptionPublicKey ? "duplicate" : "conflict";
      db.prepare("INSERT INTO registrations (claim, encryption_key, requested_at, status, updated_at) VALUES (?, ?, ?, 'pending', ?)")
        .run(request.claim, request.encryptionPublicKey, request.requestedAt, nowMs);
      return "stored";
    },
    get(claim) { const r = getStmt.get(claim) as Record<string, unknown> | undefined; return r === undefined ? null : toRow(r); },
    list(status) {
      const rows = (status === undefined ? db.prepare("SELECT * FROM registrations ORDER BY requested_at").all() : db.prepare("SELECT * FROM registrations WHERE status = ? ORDER BY requested_at").all(status)) as Record<string, unknown>[];
      return rows.map(toRow);
    },
    approve(claim, input, nowMs) {
      const changed = db.prepare("UPDATE registrations SET status = 'approved', uid = ?, credential_json = ?, funding_tx = ?, updated_at = ? WHERE claim = ? AND status = 'pending'")
        .run(input.uid, input.credentialJson, input.fundingTx ?? null, nowMs, claim).changes;
      if (changed !== 1) throw new Error(`registration ${claim} is not pending`);
    },
    reject(claim, note, nowMs) {
      const changed = db.prepare("UPDATE registrations SET status = 'rejected', note = ?, updated_at = ? WHERE claim = ? AND status = 'pending'").run(note, nowMs, claim).changes;
      if (changed !== 1) throw new Error(`registration ${claim} is not pending`);
    },
    approvedClaims() { return (db.prepare("SELECT claim FROM registrations WHERE status = 'approved' ORDER BY requested_at").all() as { claim: string }[]).map((r) => r.claim); },
    close() { db.close(); },
  };
}
