/**
 * Role-local index of negotiations this process knows about, plus the
 * post-negotiation milestones (commitment, settlement) that live outside the
 * SDK lifecycle record. SQLite, one file per role.
 */

import { closeSync, mkdirSync, openSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import type { Database } from "better-sqlite3";
import { canonicalize } from "@kynesyslabs/dacs/canonical";

export interface SessionIndexEntry {
  jobId: string;
  channelId: string;
  listingId: string;
  listingVersion: number;
  counterparty: string;
  /** Exact verified Listing JSON retained for later phases (no secrets). */
  listingJson: string;
  openedAt: number;
  commitment?: Record<string, unknown>;
  settlement?: Record<string, unknown>;
  updatedAt: number;
}

export interface SessionIndex {
  put: (entry: Omit<SessionIndexEntry, "updatedAt">) => void;
  get: (jobId: string) => SessionIndexEntry | null;
  list: () => SessionIndexEntry[];
  setCommitment: (jobId: string, commitment: Record<string, unknown>, nowMs: number) => void;
  setSettlement: (jobId: string, settlement: Record<string, unknown>, nowMs: number) => void;
  close: () => void;
}

const APPLICATION_ID = 0x52465153; // "RFQS"
const SCHEMA_VERSION = 1;

function open(path: string): Database {
  if (!isAbsolute(path)) throw new Error("session index path must be absolute");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  closeSync(openSync(path, "a", 0o600));
  const db = new BetterSqlite3(path, { timeout: 5_000 });
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  const applicationId = db.pragma("application_id", { simple: true }) as number;
  const userVersion = db.pragma("user_version", { simple: true }) as number;
  if (applicationId === 0 && userVersion === 0) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        job_id          TEXT PRIMARY KEY NOT NULL,
        channel_id      TEXT NOT NULL,
        listing_id      TEXT NOT NULL,
        listing_version INTEGER NOT NULL,
        counterparty    TEXT NOT NULL,
        listing_json    TEXT NOT NULL,
        opened_at       INTEGER NOT NULL,
        commitment_json TEXT,
        settlement_json TEXT,
        updated_at      INTEGER NOT NULL
      ) WITHOUT ROWID;
    `);
    db.pragma(`application_id = ${APPLICATION_ID}`);
    db.pragma(`user_version = ${SCHEMA_VERSION}`);
  } else if (applicationId !== APPLICATION_ID || userVersion !== SCHEMA_VERSION) {
    db.close();
    throw new Error("session index belongs to another application or schema version");
  }
  if (statSync(path).mode & 0o077) {
    db.close();
    throw new Error(`session index ${path} must not be group/world accessible`);
  }
  return db;
}

interface Row {
  job_id: string; channel_id: string; listing_id: string; listing_version: number; counterparty: string;
  listing_json: string; opened_at: number; commitment_json: string | null; settlement_json: string | null; updated_at: number;
}

function toEntry(row: Row): SessionIndexEntry {
  return {
    jobId: row.job_id,
    channelId: row.channel_id,
    listingId: row.listing_id,
    listingVersion: row.listing_version,
    counterparty: row.counterparty,
    listingJson: row.listing_json,
    openedAt: row.opened_at,
    ...(row.commitment_json === null ? {} : { commitment: JSON.parse(row.commitment_json) as Record<string, unknown> }),
    ...(row.settlement_json === null ? {} : { settlement: JSON.parse(row.settlement_json) as Record<string, unknown> }),
    updatedAt: row.updated_at,
  };
}

export function createSessionIndex(options: { path: string }): SessionIndex {
  const db = open(options.path);
  const insert = db.prepare(
    `INSERT OR IGNORE INTO sessions (job_id, channel_id, listing_id, listing_version, counterparty, listing_json, opened_at, updated_at)
     VALUES (@jobId, @channelId, @listingId, @listingVersion, @counterparty, @listingJson, @openedAt, @openedAt)`,
  );
  const select = db.prepare<[string], Row>("SELECT * FROM sessions WHERE job_id = ?");
  const selectAll = db.prepare<[], Row>("SELECT * FROM sessions ORDER BY opened_at ASC");
  const setCommitment = db.prepare<[string, number, string]>(
    "UPDATE sessions SET commitment_json = ?, updated_at = ? WHERE job_id = ? AND commitment_json IS NULL",
  );
  const setSettlement = db.prepare<[string, number, string]>(
    "UPDATE sessions SET settlement_json = ?, updated_at = ? WHERE job_id = ? AND settlement_json IS NULL",
  );
  return {
    put(entry) {
      insert.run(entry);
    },
    get(jobId) {
      const row = select.get(jobId);
      return row === undefined ? null : toEntry(row);
    },
    list() {
      return selectAll.all().map(toEntry);
    },
    setCommitment(jobId, commitment, nowMs) {
      setCommitment.run(canonicalize(commitment), nowMs, jobId);
    },
    setSettlement(jobId, settlement, nowMs) {
      setSettlement.run(canonicalize(settlement), nowMs, jobId);
    },
    close() {
      db.close();
    },
  };
}
