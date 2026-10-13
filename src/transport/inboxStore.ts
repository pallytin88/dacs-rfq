/**
 * Receiver-side durable inbox for the interim transport.
 *
 * The receiver MUST persist a packet before it signs an acknowledgement, and a
 * `reconcile` lookup is answered from this same store, so "absent" is the
 * receiver's own authenticated statement about its durable state. Nonces are
 * recorded in the same transaction as the packet so a replayed envelope can
 * never be acknowledged as a fresh delivery.
 */

import { closeSync, mkdirSync, openSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import type { Database } from "better-sqlite3";
import { canonicalize } from "@kynesyslabs/dacs/canonical";

export type InboxAdmission =
  | { outcome: "stored" }
  | { outcome: "duplicate" }
  | { outcome: "conflict"; reason: string }
  | { outcome: "replay" };

export interface InboxPacketRow {
  packetId: string;
  jobId: string;
  channelId: string;
  sender: string;
  packetHash: string;
  packet: Record<string, unknown>;
  receivedAt: number;
}

export interface RfqInboxStore {
  admit: (input: Readonly<{
    packet: Readonly<Record<string, unknown>>;
    packetHash: string;
    envelopeId: string;
    nonce: string;
    nonceExpiresAt: number;
    sender: string;
    nowMs: number;
  }>) => InboxAdmission;
  /** Records a nonce for a non-packet envelope (lookups). Returns false on replay. */
  recordNonce: (nonce: string, sender: string, expiresAt: number, nowMs: number) => boolean;
  lookup: (packetId: string) => { packetHash: string; receivedAt: number } | null;
  nextUnprocessed: (limit: number) => InboxPacketRow[];
  markProcessed: (packetId: string, note: string, nowMs: number) => void;
  pruneNonces: (nowMs: number) => number;
  close: () => void;
}

const SCHEMA_VERSION = 1;
const APPLICATION_ID = 0x52465149; // "RFQI"

function open(path: string, busyTimeoutMs: number): Database {
  if (!isAbsolute(path)) throw new Error("inbox database path must be absolute");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  // Create the file ourselves so SQLite (and its -wal/-shm siblings) inherit 0600.
  closeSync(openSync(path, "a", 0o600));
  const db = new BetterSqlite3(path, { timeout: busyTimeoutMs });
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  const applicationId = db.pragma("application_id", { simple: true }) as number;
  const userVersion = db.pragma("user_version", { simple: true }) as number;
  if (applicationId === 0 && userVersion === 0) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS packets (
        packet_id    TEXT PRIMARY KEY NOT NULL,
        job_id       TEXT NOT NULL,
        channel_id   TEXT NOT NULL,
        sender       TEXT NOT NULL,
        packet_hash  TEXT NOT NULL,
        packet_json  TEXT NOT NULL,
        envelope_id  TEXT NOT NULL,
        received_seq INTEGER NOT NULL,
        received_at  INTEGER NOT NULL,
        processed_at INTEGER,
        processed_note TEXT
      ) WITHOUT ROWID;
      CREATE INDEX IF NOT EXISTS packets_unprocessed ON packets (received_seq) WHERE processed_at IS NULL;
      CREATE TABLE IF NOT EXISTS nonces (
        nonce      TEXT PRIMARY KEY NOT NULL,
        sender     TEXT NOT NULL,
        seen_at    INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      ) WITHOUT ROWID;
      CREATE TABLE IF NOT EXISTS counters (
        name  TEXT PRIMARY KEY NOT NULL,
        value INTEGER NOT NULL
      ) WITHOUT ROWID;
      INSERT OR IGNORE INTO counters (name, value) VALUES ('received_seq', 0);
    `);
    db.pragma(`application_id = ${APPLICATION_ID}`);
    db.pragma(`user_version = ${SCHEMA_VERSION}`);
  } else if (applicationId !== APPLICATION_ID || userVersion !== SCHEMA_VERSION) {
    db.close();
    throw new Error("inbox database belongs to another application or schema version");
  }
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) {
    db.close();
    throw new Error(`inbox database ${path} must not be group/world accessible`);
  }
  return db;
}

export function createRfqInboxStore(options: { path: string; busyTimeoutMs?: number }): RfqInboxStore {
  const db = open(options.path, options.busyTimeoutMs ?? 5_000);
  const selectPacket = db.prepare<[string], { packet_hash: string; received_at: number }>(
    "SELECT packet_hash, received_at FROM packets WHERE packet_id = ?",
  );
  const insertPacket = db.prepare(
    `INSERT INTO packets (packet_id, job_id, channel_id, sender, packet_hash, packet_json, envelope_id, received_seq, received_at)
     VALUES (@packetId, @jobId, @channelId, @sender, @packetHash, @packetJson, @envelopeId, @seq, @receivedAt)`,
  );
  const selectNonce = db.prepare<[string], { nonce: string }>("SELECT nonce FROM nonces WHERE nonce = ?");
  const insertNonce = db.prepare<[string, string, number, number]>(
    "INSERT INTO nonces (nonce, sender, seen_at, expires_at) VALUES (?, ?, ?, ?)",
  );
  const bumpSeq = db.prepare<[], { value: number }>(
    "UPDATE counters SET value = value + 1 WHERE name = 'received_seq' RETURNING value",
  );
  const selectUnprocessed = db.prepare<[number], {
    packet_id: string; job_id: string; channel_id: string; sender: string; packet_hash: string; packet_json: string; received_at: number;
  }>(
    "SELECT packet_id, job_id, channel_id, sender, packet_hash, packet_json, received_at FROM packets WHERE processed_at IS NULL ORDER BY received_seq ASC LIMIT ?",
  );
  const markProcessed = db.prepare<[number, string, string]>(
    "UPDATE packets SET processed_at = ?, processed_note = ? WHERE packet_id = ? AND processed_at IS NULL",
  );
  const pruneNonces = db.prepare<[number]>("DELETE FROM nonces WHERE expires_at < ?");

  const admitTx = db.transaction((input: Parameters<RfqInboxStore["admit"]>[0]): InboxAdmission => {
    if (selectNonce.get(input.nonce) !== undefined) return { outcome: "replay" };
    insertNonce.run(input.nonce, input.sender, input.nowMs, input.nonceExpiresAt);
    const existing = selectPacket.get(String(input.packet["packetId"]));
    if (existing !== undefined) {
      return existing.packet_hash === input.packetHash
        ? { outcome: "duplicate" }
        : { outcome: "conflict", reason: "packetId is already bound to different bytes" };
    }
    const seq = bumpSeq.get()!.value;
    insertPacket.run({
      packetId: String(input.packet["packetId"]),
      jobId: String(input.packet["jobId"]),
      channelId: String(input.packet["channelId"]),
      sender: input.sender,
      packetHash: input.packetHash,
      packetJson: canonicalize(input.packet),
      envelopeId: input.envelopeId,
      seq,
      receivedAt: input.nowMs,
    });
    return { outcome: "stored" };
  });
  const nonceTx = db.transaction((nonce: string, sender: string, expiresAt: number, nowMs: number): boolean => {
    if (selectNonce.get(nonce) !== undefined) return false;
    insertNonce.run(nonce, sender, nowMs, expiresAt);
    return true;
  });

  return {
    admit: (input) => admitTx.immediate(input),
    recordNonce: (nonce, sender, expiresAt, nowMs) => nonceTx.immediate(nonce, sender, expiresAt, nowMs),
    lookup(packetId) {
      const row = selectPacket.get(packetId);
      return row === undefined ? null : { packetHash: row.packet_hash, receivedAt: row.received_at };
    },
    nextUnprocessed(limit) {
      return selectUnprocessed.all(limit).map((row) => ({
        packetId: row.packet_id,
        jobId: row.job_id,
        channelId: row.channel_id,
        sender: row.sender,
        packetHash: row.packet_hash,
        packet: JSON.parse(row.packet_json) as Record<string, unknown>,
        receivedAt: row.received_at,
      }));
    },
    markProcessed(packetId, note, nowMs) {
      markProcessed.run(nowMs, note, packetId);
    },
    pruneNonces(nowMs) {
      return pruneNonces.run(nowMs).changes;
    },
    close() {
      db.close();
    },
  };
}
