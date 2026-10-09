/**
 * Role-local durable state for one RFQ participant.
 *
 * Layout (one root per role, never shared between buyer and seller):
 *
 *   <root>/rfq/              authenticated filesystem lifecycle store (SDK), 0700
 *   <root>/reservations.db   SQLite channel-ID reservations (CH-6)
 *   <root>/transport.db      interim transport inbox / nonce log
 *   <keyPath>                32-byte integrity key, 0600, OUTSIDE <root>
 *
 * The integrity key authenticates every lifecycle record; the SDK requires it
 * to live outside the store directory and never be persisted alongside it.
 */

import { randomBytes } from "node:crypto";
import { mkdirSync, openSync, readFileSync, statSync, writeFileSync, closeSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createFsDurableRfqLifecycleStore } from "@kynesyslabs/dacs/negotiate";
import type { DurableRfqLifecycleStore } from "@kynesyslabs/dacs/negotiate";
import { createSqliteChannelReservation } from "./channelReservation.js";
import type { SqliteChannelReservation } from "./channelReservation.js";

export type RfqRole = "buyer" | "seller";

export interface RoleStoreOptions {
  role: RfqRole;
  /** Absolute, role-local root directory. */
  root: string;
  /** Absolute path to the 32-byte integrity key file; must be outside `root`. */
  integrityKeyPath: string;
  /** Create the key file if missing (0600). Default false: fail closed. */
  createIntegrityKey?: boolean;
}

export interface RoleStores<TSignature = unknown> {
  role: RfqRole;
  root: string;
  lifecycle: DurableRfqLifecycleStore<TSignature>;
  reservation: SqliteChannelReservation;
  transportDbPath: string;
  close: () => void;
}

function assertOutside(child: string, parent: string): void {
  const rel = resolve(child);
  const base = resolve(parent);
  if (rel === base || rel.startsWith(`${base}/`)) {
    throw new Error("integrity key must be stored outside the role store root");
  }
}

export function loadOrCreateIntegrityKey(path: string, create: boolean): Uint8Array {
  if (!isAbsolute(path)) throw new Error("integrity key path must be absolute");
  try {
    const stat = statSync(path);
    if ((stat.mode & 0o077) !== 0) throw new Error(`integrity key ${path} must be mode 0600`);
    const bytes = readFileSync(path);
    if (bytes.length !== 32) throw new Error("integrity key must be exactly 32 bytes");
    return new Uint8Array(bytes);
  } catch (cause) {
    if (!(cause instanceof Error) || !("code" in cause) || cause.code !== "ENOENT" || !create) {
      throw cause;
    }
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const key = randomBytes(32);
  // O_EXCL so two processes can never both "create" the same key.
  const fd = openSync(path, "wx", 0o600);
  try {
    writeFileSync(fd, key);
  } finally {
    closeSync(fd);
  }
  return new Uint8Array(key);
}

export async function openRoleStores<TSignature = unknown>(
  options: RoleStoreOptions,
): Promise<RoleStores<TSignature>> {
  if (!isAbsolute(options.root)) throw new Error("role store root must be absolute");
  assertOutside(options.integrityKeyPath, options.root);
  mkdirSync(options.root, { recursive: true, mode: 0o700 });
  const rfqDir = join(options.root, "rfq");
  mkdirSync(rfqDir, { recursive: true, mode: 0o700 });

  const integrityKey = loadOrCreateIntegrityKey(
    options.integrityKeyPath,
    options.createIntegrityKey ?? false,
  );
  const lifecycle = await createFsDurableRfqLifecycleStore<TSignature>({
    dir: rfqDir,
    role: options.role,
    integrityKey,
  });
  const reservation = createSqliteChannelReservation({
    path: join(options.root, "reservations.db"),
    role: options.role,
  });
  return {
    role: options.role,
    root: options.root,
    lifecycle,
    reservation,
    transportDbPath: join(options.root, "transport.db"),
    close() {
      reservation.close();
    },
  };
}
