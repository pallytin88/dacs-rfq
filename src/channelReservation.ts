/**
 * Durable, idempotent channel-ID reservation (DACS-3 CH-6) backed by SQLite.
 *
 * `openRfqSession()` requires that a channelId be owned by exactly one
 * job/listing/member reservation, and that this survive restarts. A
 * process-local `Set` is explicitly not acceptable. One database per role;
 * never share the file between buyer and seller.
 *
 * Decision semantics (four-value):
 * - `pass`           this exact reservation owns the channelId (first write or
 *                    byte-identical repeat);
 * - `fail`           a different reservation already owns it;
 * - `indeterminate`  the database could not establish uniqueness (locked,
 *                    I/O error, integrity failure); the caller must stop;
 * - `error`          the input itself is malformed.
 */

import { closeSync, mkdirSync, openSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import type { Database } from "better-sqlite3";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs/canonical";
import type { RfqChannelReservationInput } from "@kynesyslabs/dacs/negotiate";

export type ReservationDecision = "pass" | "fail" | "indeterminate" | "error";

export interface SqliteChannelReservationOptions {
  /** Absolute path of the role-local database file. */
  path: string;
  role: "buyer" | "seller";
  busyTimeoutMs?: number;
}

export interface SqliteChannelReservation {
  reserve: (input: Readonly<RfqChannelReservationInput>) => ReservationDecision;
  /** Read-only lookup for diagnostics and tests. */
  lookup: (channelId: string) => { reservationHash: string; reservedAt: number } | null;
  close: () => void;
}

const SCHEMA_VERSION = 1;
const APPLICATION_ID = 0x52465143; // "RFQC"

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function validateInput(input: unknown): input is RfqChannelReservationInput {
  if (!isRecord(input)) return false;
  const keys = Object.keys(input);
  const expected = ["reservationVersion", "jobId", "listingPin", "channelId", "members"];
  if (keys.length !== expected.length || !expected.every((key) => keys.includes(key))) return false;
  if (input["reservationVersion"] !== "1") return false;
  if (!nonEmpty(input["jobId"]) || !nonEmpty(input["channelId"])) return false;
  const pin = input["listingPin"];
  if (
    !isRecord(pin) ||
    !nonEmpty(pin["listingId"]) ||
    typeof pin["version"] !== "number" ||
    !Number.isSafeInteger(pin["version"]) ||
    !nonEmpty(pin["contentHash"])
  ) {
    return false;
  }
  const members = input["members"];
  return (
    Array.isArray(members) &&
    members.length === 2 &&
    members.every(nonEmpty) &&
    members[0] !== members[1]
  );
}

function openDatabase(options: SqliteChannelReservationOptions): Database {
  if (!isAbsolute(options.path)) throw new Error("reservation database path must be absolute");
  mkdirSync(dirname(options.path), { recursive: true, mode: 0o700 });
  // Create the file ourselves so SQLite (and its -wal/-shm siblings) inherit 0600.
  closeSync(openSync(options.path, "a", 0o600));
  const db = new BetterSqlite3(options.path, { timeout: options.busyTimeoutMs ?? 5_000 });
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.pragma("foreign_keys = ON");
  const applicationId = db.pragma("application_id", { simple: true }) as number;
  const userVersion = db.pragma("user_version", { simple: true }) as number;
  if (applicationId === 0 && userVersion === 0) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS channel_reservations (
        channel_id       TEXT PRIMARY KEY NOT NULL,
        role             TEXT NOT NULL,
        reservation_hash TEXT NOT NULL,
        reservation_json TEXT NOT NULL,
        reserved_at      INTEGER NOT NULL
      ) WITHOUT ROWID;
    `);
    db.pragma(`application_id = ${APPLICATION_ID}`);
    db.pragma(`user_version = ${SCHEMA_VERSION}`);
  } else if (applicationId !== APPLICATION_ID || userVersion !== SCHEMA_VERSION) {
    db.close();
    throw new Error("reservation database belongs to another application or schema version");
  }
  const mode = statSync(options.path).mode & 0o777;
  if (mode & 0o077) {
    db.close();
    throw new Error(`reservation database ${options.path} must not be group/world accessible`);
  }
  return db;
}

export function createSqliteChannelReservation(
  options: SqliteChannelReservationOptions,
): SqliteChannelReservation {
  const db = openDatabase(options);
  const select = db.prepare<[string], { role: string; reservation_hash: string; reserved_at: number }>(
    "SELECT role, reservation_hash, reserved_at FROM channel_reservations WHERE channel_id = ?",
  );
  const insert = db.prepare<[string, string, string, string, number]>(
    "INSERT INTO channel_reservations (channel_id, role, reservation_hash, reservation_json, reserved_at) VALUES (?, ?, ?, ?, ?)",
  );
  const reserveTx = db.transaction(
    (channelId: string, hash: string, json: string, now: number): ReservationDecision => {
      const existing = select.get(channelId);
      if (existing === undefined) {
        insert.run(channelId, options.role, hash, json, now);
        return "pass";
      }
      return existing.reservation_hash === hash && existing.role === options.role ? "pass" : "fail";
    },
  );

  return {
    reserve(input) {
      if (!validateInput(input)) return "error";
      let json: string;
      try {
        json = canonicalize(input as unknown as Record<string, unknown>);
      } catch {
        return "error";
      }
      const hash = sha256Hex(json);
      try {
        return reserveTx.immediate(input.channelId, hash, json, Date.now());
      } catch {
        // Busy, I/O, corruption: uniqueness cannot be established. Fail closed.
        return "indeterminate";
      }
    },
    lookup(channelId) {
      const row = select.get(channelId);
      return row === undefined
        ? null
        : { reservationHash: row.reservation_hash, reservedAt: row.reserved_at };
    },
    close() {
      db.close();
    },
  };
}
