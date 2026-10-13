/**
 * Feed durably received packets into the role's lifecycle client, in arrival
 * order, marking each one processed only after the client has durably recorded
 * its own outcome. `indeterminate` or `conflict` stops the drain without
 * marking, so a restart replays the same packet; `rejected` is terminal for
 * that packet and is recorded with its reason.
 */

import type { DurableRfqLifecycleClient } from "@kynesyslabs/dacs/negotiate";
import type { RfqInboxStore } from "./inboxStore.js";
import { isSessionAnnouncement } from "./open.js";
import type { RfqSessionAnnouncement } from "./open.js";

export type AnnouncementHandler = (
  announcement: Readonly<RfqSessionAnnouncement>,
) => Promise<{ status: "ready" | "duplicate" | "rejected" | "indeterminate"; reason?: string }>;

export interface DrainOptions<TSignature> {
  inbox: RfqInboxStore;
  client: DurableRfqLifecycleClient<TSignature>;
  /** Seller side: open the announced session. Omitted on the buyer. */
  onOpen?: AnnouncementHandler;
  nowMs?: () => number;
  limit?: number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface DrainSummary {
  processed: number;
  rejected: number;
  stoppedAt?: { packetId: string; status: string; reason?: string };
}

export async function drainInbox<TSignature>(options: DrainOptions<TSignature>): Promise<DrainSummary> {
  const nowMs = options.nowMs ?? Date.now;
  const log = options.log ?? (() => {});
  const summary: DrainSummary = { processed: 0, rejected: 0 };
  const rows = options.inbox.nextUnprocessed(options.limit ?? 100);
  for (const row of rows) {
    let result: { status: string; reason?: string };
    if (row.packet["kind"] === "open") {
      if (!isSessionAnnouncement(row.packet)) {
        options.inbox.markProcessed(row.packetId, "rejected: malformed announcement", nowMs());
        summary.rejected += 1;
        continue;
      }
      result = options.onOpen === undefined
        ? { status: "rejected", reason: "this role does not accept announcements" }
        : await options.onOpen(row.packet);
    } else {
      result = await options.client.receive(row.packet);
    }
    const reason = "reason" in result ? result.reason : undefined;
    log({ event: "inbox-drain", packetId: row.packetId, status: result.status, ...(reason === undefined ? {} : { reason }) });
    if (result.status === "ready" || result.status === "duplicate") {
      options.inbox.markProcessed(row.packetId, result.status, nowMs());
      summary.processed += 1;
      continue;
    }
    if (result.status === "rejected") {
      options.inbox.markProcessed(row.packetId, `rejected: ${result.reason ?? ""}`, nowMs());
      summary.rejected += 1;
      continue;
    }
    summary.stoppedAt = { packetId: row.packetId, status: result.status, ...(reason === undefined ? {} : { reason }) };
    void reason;
    break;
  }
  return summary;
}
