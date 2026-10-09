import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import type { RfqChannelReservationInput } from "@kynesyslabs/dacs/negotiate";
import { createSqliteChannelReservation } from "../src/channelReservation.js";

const dirs: string[] = [];
function tmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "dacs-rfq-reservation-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function reservation(channelId: string, jobId = "01J8ME0SXKQ4T9V2RC5HJ6WX7E"): RfqChannelReservationInput {
  return {
    reservationVersion: "1",
    jobId,
    listingPin: { listingId: "listing-1", version: 3, contentHash: "a".repeat(64) },
    channelId,
    members: ["did:demos:buyer", "did:demos:seller"],
  };
}

describe("SQLite channel reservation (CH-6)", () => {
  test("first reservation passes, identical repeat passes, different reservation fails", () => {
    const db = createSqliteChannelReservation({ path: join(tmp(), "buyer", "reservations.db"), role: "buyer" });
    expect(db.reserve(reservation("chan-1"))).toBe("pass");
    expect(db.reserve(reservation("chan-1"))).toBe("pass");
    expect(db.reserve(reservation("chan-1", "01J8ME0SXKQ4T9V2RC5HJ6WX7F"))).toBe("fail");
    expect(db.reserve(reservation("chan-2"))).toBe("pass");
    db.close();
  });

  test("a second reservation for the same channel fails after a restart", () => {
    const path = join(tmp(), "seller", "reservations.db");
    const first = createSqliteChannelReservation({ path, role: "seller" });
    expect(first.reserve(reservation("chan-restart"))).toBe("pass");
    first.close();

    const second = createSqliteChannelReservation({ path, role: "seller" });
    expect(second.reserve(reservation("chan-restart", "01J8ME0SXKQ4T9V2RC5HJ6WX7F"))).toBe("fail");
    expect(second.reserve(reservation("chan-restart"))).toBe("pass");
    expect(second.lookup("chan-restart")).not.toBeNull();
    second.close();
  });

  test("malformed input is error, never a reservation", () => {
    const db = createSqliteChannelReservation({ path: join(tmp(), "buyer", "reservations.db"), role: "buyer" });
    expect(db.reserve({ ...reservation("chan-x"), members: ["same", "same"] } as never)).toBe("error");
    expect(db.reserve({ ...reservation("chan-x"), reservationVersion: "2" } as never)).toBe("error");
    expect(db.lookup("chan-x")).toBeNull();
    db.close();
  });

  test("the same channel reserved by the other role fails", () => {
    const dir = tmp();
    const buyer = createSqliteChannelReservation({ path: join(dir, "shared.db"), role: "buyer" });
    expect(buyer.reserve(reservation("chan-role"))).toBe("pass");
    buyer.close();
    const seller = createSqliteChannelReservation({ path: join(dir, "shared.db"), role: "seller" });
    expect(seller.reserve(reservation("chan-role"))).toBe("fail");
    seller.close();
  });

  test("a locked database yields indeterminate, not pass", () => {
    const path = join(tmp(), "buyer", "reservations.db");
    const holder = createSqliteChannelReservation({ path, role: "buyer", busyTimeoutMs: 50 });
    const contender = createSqliteChannelReservation({ path, role: "buyer", busyTimeoutMs: 50 });
    // Hold an exclusive write transaction open via a raw connection.
    const raw = new (require("better-sqlite3") as typeof import("better-sqlite3"))(path, { timeout: 50 });
    raw.exec("BEGIN IMMEDIATE");
    expect(contender.reserve(reservation("chan-locked"))).toBe("indeterminate");
    raw.exec("ROLLBACK");
    raw.close();
    expect(contender.reserve(reservation("chan-locked"))).toBe("pass");
    holder.close();
    contender.close();
  });
});
