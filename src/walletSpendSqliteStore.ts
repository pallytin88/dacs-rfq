/**
 * SQLite `WalletSpendStateStore` for a single-host buyer. The SDK ships an
 * in-memory store (tests) and dacs-node ships Postgres; the showcase buyer is
 * one process on one machine, so a serialized SQLite transaction per scope is
 * sufficient and durable.
 */

import { closeSync, mkdirSync, openSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import type { WalletSpendStateStore, WalletSpendStateV1 } from "@kynesyslabs/dacs/rails";

const APPLICATION_ID = 0x52465157; // "RFQW"

export function createSqliteWalletSpendStateStore(options: { path: string }): WalletSpendStateStore & { close: () => void } {
  if (!isAbsolute(options.path)) throw new Error("wallet spend store path must be absolute");
  mkdirSync(dirname(options.path), { recursive: true, mode: 0o700 });
  closeSync(openSync(options.path, "a", 0o600));
  const db = new BetterSqlite3(options.path, { timeout: 5_000 });
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  const applicationId = db.pragma("application_id", { simple: true }) as number;
  if (applicationId === 0) {
    db.exec(`CREATE TABLE IF NOT EXISTS wallet_spend_state (scope TEXT PRIMARY KEY NOT NULL, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL) WITHOUT ROWID;`);
    db.pragma(`application_id = ${APPLICATION_ID}`);
    db.pragma("user_version = 1");
  } else if (applicationId !== APPLICATION_ID) {
    db.close();
    throw new Error("wallet spend store belongs to another application");
  }
  if (statSync(options.path).mode & 0o077) {
    db.close();
    throw new Error(`wallet spend store ${options.path} must not be group/world accessible`);
  }
  const select = db.prepare<[string], { state_json: string }>("SELECT state_json FROM wallet_spend_state WHERE scope = ?");
  const upsert = db.prepare<[string, string, number]>(
    "INSERT INTO wallet_spend_state (scope, state_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(scope) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at",
  );
  return {
    async read(scope) {
      const row = select.get(scope);
      return row === undefined ? null : (JSON.parse(row.state_json) as WalletSpendStateV1);
    },
    async transact(scope, operation) {
      const run = db.transaction(() => {
        const row = select.get(scope);
        const current = row === undefined ? null : (JSON.parse(row.state_json) as WalletSpendStateV1);
        const next = operation(current, Date.now());
        upsert.run(scope, JSON.stringify(next.state), Date.now());
        return next.value;
      });
      return run.immediate();
    },
    close() {
      db.close();
    },
  };
}
