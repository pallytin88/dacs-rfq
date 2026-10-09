/**
 * Read-only showcase server: the viewer page plus the procurement-event API in
 * the DACS Directory's `/try` contract (`GET /demo/procurement/options`,
 * `GET /demo/procurement`, `GET /demo/procurement/{jobId}`). No bearer token:
 * it exposes nothing the chain does not already show except the buyer's own
 * offer history, so bind it to loopback (default) or put TLS in front.
 */

import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { DurableRfqLifecycleClient } from "@kynesyslabs/dacs/negotiate";
import type { SessionIndex } from "../sessionIndex.js";
import { deriveProcurementJob } from "./procurement.js";
import type { ProcurementJob } from "./procurement.js";
import { showcasePageHtml } from "./showcasePage.js";

export interface ShowcaseServerOptions<TSignature> {
  client: DurableRfqLifecycleClient<TSignature>;
  sessions: SessionIndex;
  buyerClaim: string;
  sellerDisplayName?: string;
  transportLabel?: string;
  /** Private-channel exhibit: this member's subnet history as metadata only (never content). */
  subnetExhibit?: () => Promise<{ uid: string; host: string; rows: readonly { hash: string; from: string; to: string; status: string; timestamp: number }[] }>;
  lastErrorFor?: (jobId: string) => string | undefined;
  hostname?: string;
  port?: number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface ShowcaseServer {
  readonly endpoint: string;
  readonly port: number;
  readonly server: Server;
  jobFor(jobId: string): Promise<ProcurementJob | null>;
  close(): Promise<void>;
}

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": String(bytes.length), "cache-control": "no-store", "access-control-allow-origin": "*" });
  response.end(bytes);
}

export async function startShowcaseServer<TSignature>(options: ShowcaseServerOptions<TSignature>): Promise<ShowcaseServer> {
  const hostname = options.hostname ?? "127.0.0.1";
  if (!["127.0.0.1", "::1", "localhost"].includes(hostname)) throw new Error("the showcase server binds loopback only; put TLS in front for other hosts");
  const log = options.log ?? (() => {});

  async function jobFor(jobId: string): Promise<ProcurementJob | null> {
    const entry = options.sessions.get(jobId);
    if (entry === null) return null;
    const status = await options.client.getStatus(jobId);
    return deriveProcurementJob({
      entry, record: status.status === "ok" ? status.record : null, buyerClaim: options.buyerClaim,
      sellerDisplayName: options.sellerDisplayName, transportLabel: options.transportLabel, lastError: options.lastErrorFor?.(jobId),
    });
  }

  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    (async () => {
      const url = new URL(request.url ?? "/", "http://localhost");
      if (request.method !== "GET") { writeJson(response, 405, { error: "method-not-allowed" }); return; }
      if (url.pathname === "/" || url.pathname === "/try-chat") {
        const html = showcasePageHtml();
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(html);
        return;
      }
      if (url.pathname === "/demo/procurement/options") {
        writeJson(response, 200, { profiles: [{ id: "private-rfq", title: `Private RFQ (DACS-3) over ${options.transportLabel ?? "the interim direct transport"}`, negotiationPhase: "negotiate-rfq", executionControl: { model: "model-driven-via-mcp" }, buyerControl: { model: "operator-custodied-buyer" }, paymentRails: ["pay-dem"] }] });
        return;
      }
      if (url.pathname === "/demo/subnet") {
        if (options.subnetExhibit === undefined) { writeJson(response, 404, { error: "no subnet transport" }); return; }
        const exhibit = await options.subnetExhibit();
        writeJson(response, 200, {
          uid: exhibit.uid, host: exhibit.host,
          note: "Each row is one encrypted L2PS transaction carrying a signed channel packet. The host node stores only ciphertext; content is readable solely by the two members through a signed history read and is never served here.",
          rows: exhibit.rows.map((r) => ({ hash: r.hash, from: r.from, to: r.to, status: r.status, at: new Date(r.timestamp).toISOString() })),
        });
        return;
      }
      if (url.pathname === "/demo/procurement") {
        const jobs = await Promise.all(options.sessions.list().map(async (entry) => {
          const job = await jobFor(entry.jobId);
          return job === null ? null : { id: job.id, status: job.status, phase: job.phase, openedAt: new Date(entry.openedAt).toISOString() };
        }));
        writeJson(response, 200, jobs.filter((j) => j !== null));
        return;
      }
      const match = /^\/demo\/procurement\/([0-9A-HJKMNP-TV-Z]{26})$/.exec(url.pathname);
      if (match !== null) {
        const job = await jobFor(match[1]!);
        if (job === null) { writeJson(response, 404, { error: "unknown job" }); return; }
        writeJson(response, 200, job);
        return;
      }
      writeJson(response, 404, { error: "not-found" });
    })().catch((cause) => {
      log({ event: "showcase-error", reason: cause instanceof Error ? cause.message : String(cause) });
      if (!response.headersSent) writeJson(response, 500, { error: "internal" });
      else response.destroy();
    });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(options.port ?? 0, hostname, () => { server.off("error", reject); resolve(); }); });
  const address = server.address() as AddressInfo;
  const host = address.family === "IPv6" ? `[${address.address}]` : address.address;
  return {
    endpoint: `http://${host}:${address.port}/`,
    port: address.port,
    server,
    jobFor,
    close: () => new Promise<void>((resolve, reject) => { server.closeAllConnections?.(); server.close((e) => (e ? reject(e) : resolve())); }),
  };
}
