/**
 * Minimal MCP (Model Context Protocol) server over Streamable HTTP exposing
 * the buyer negotiation service as tools. JSON-RPC 2.0 over `POST /mcp`,
 * JSON responses (no SSE), bearer-token authenticated, loopback-only without
 * TLS. The model never sees keys, stores or the outbox; it only receives the
 * structured results below.
 *
 * Implemented methods: initialize, notifications/initialized, ping,
 * tools/list, tools/call. Everything else returns -32601.
 */

import { timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { Server as HttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { BuyerServiceError } from "./service.js";
import type { BuyerNegotiationService } from "./service.js";

export const MCP_PROTOCOL_VERSION = "2025-06-18" as const;
export const MCP_PATH = "/mcp" as const;

interface ToolSpec {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  required: readonly string[];
  optional: readonly string[];
  run: (args: Record<string, unknown>) => Promise<unknown>;
}

const JOB_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const AMOUNT = /^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$/;
const SHORT = /^[\x20-\x7E]{1,200}$/;

function str(args: Record<string, unknown>, key: string, pattern: RegExp): string {
  const value = args[key];
  if (typeof value !== "string" || !pattern.test(value)) throw new BuyerServiceError("invalid-argument", `${key} is invalid`);
  return value;
}

function exactArgs(args: unknown, required: readonly string[], optional: readonly string[]): Record<string, unknown> {
  if (args === null || typeof args !== "object" || Array.isArray(args)) throw new BuyerServiceError("invalid-argument", "arguments must be an object");
  const record = args as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!required.includes(key) && !optional.includes(key)) throw new BuyerServiceError("invalid-argument", `unexpected argument ${key}`);
  }
  for (const key of required) if (!(key in record)) throw new BuyerServiceError("invalid-argument", `missing argument ${key}`);
  return record;
}

export function buyerTools(service: BuyerNegotiationService): ToolSpec[] {
  const jobArg = { jobId: { type: "string", description: "Negotiation id returned by open_negotiation (26-character ULID)." } };
  return [
    {
      name: "find_listing",
      description: "Find seller listings that support private RFQ negotiation. Returns id, seller, title, price band and turn limits.",
      inputSchema: { type: "object", properties: { listingId: { type: "string" }, query: { type: "string" } }, additionalProperties: false },
      required: [], optional: ["listingId", "query"],
      run: (a) => service.findListing({
        ...("listingId" in a ? { listingId: str(a, "listingId", SHORT) } : {}),
        ...("query" in a ? { query: str(a, "query", SHORT) } : {}),
      }),
    },
    {
      name: "open_negotiation",
      description: "Open a private negotiation channel with the seller of a listing. Returns the negotiation state including the price band and your ceiling.",
      inputSchema: { type: "object", properties: { listingId: { type: "string" } }, required: ["listingId"], additionalProperties: false },
      required: ["listingId"], optional: [],
      run: (a) => service.openNegotiation({ listingId: str(a, "listingId", SHORT) }),
    },
    {
      name: "get_negotiation_state",
      description: "Current state: whose turn it is, standing proposal, turns and time left, price band, ceiling, and deal phase after acceptance.",
      inputSchema: { type: "object", properties: jobArg, required: ["jobId"], additionalProperties: false },
      required: ["jobId"], optional: [],
      run: (a) => service.getNegotiationState({ jobId: str(a, "jobId", JOB_ID) }),
    },
    {
      name: "make_offer",
      description: "Send the opening offer. amount is a decimal string in the listing currency; it must be inside the price band and at or below your ceiling.",
      inputSchema: { type: "object", properties: { ...jobArg, amount: { type: "string", description: "Decimal price, e.g. \"9.50\"" } }, required: ["jobId", "amount"], additionalProperties: false },
      required: ["jobId", "amount"], optional: [],
      run: (a) => service.makeOffer({ jobId: str(a, "jobId", JOB_ID), amount: str(a, "amount", AMOUNT) }),
    },
    {
      name: "counter_offer",
      description: "Reply to the seller's standing proposal with a counter price. Same constraints as make_offer.",
      inputSchema: { type: "object", properties: { ...jobArg, amount: { type: "string" } }, required: ["jobId", "amount"], additionalProperties: false },
      required: ["jobId", "amount"], optional: [],
      run: (a) => service.counterOffer({ jobId: str(a, "jobId", JOB_ID), amount: str(a, "amount", AMOUNT) }),
    },
    {
      name: "accept",
      description: "Accept the seller's standing proposal. Refused if it exceeds your ceiling. On success the service co-signs, commits the agreement hash on Demos and pays.",
      inputSchema: { type: "object", properties: jobArg, required: ["jobId"], additionalProperties: false },
      required: ["jobId"], optional: [],
      run: (a) => service.accept({ jobId: str(a, "jobId", JOB_ID) }),
    },
    {
      name: "reject",
      description: "End the negotiation without a deal.",
      inputSchema: { type: "object", properties: { ...jobArg, reason: { type: "string" } }, required: ["jobId"], additionalProperties: false },
      required: ["jobId"], optional: ["reason"],
      run: (a) => service.reject({ jobId: str(a, "jobId", JOB_ID), ...("reason" in a ? { reason: str(a, "reason", SHORT) } : {}) }),
    },
    {
      name: "get_receipts",
      description: "Receipts for a deal: agreement hash, channel binding, on-chain commitment receipt and settlement transaction. Never includes offer or counter contents.",
      inputSchema: { type: "object", properties: jobArg, required: ["jobId"], additionalProperties: false },
      required: ["jobId"], optional: [],
      run: (a) => service.getReceipts({ jobId: str(a, "jobId", JOB_ID) }),
    },
  ];
}

export interface McpServerOptions {
  service: BuyerNegotiationService;
  bearerToken: string;
  hostname?: string;
  port?: number;
  tls?: { key: string | Buffer; cert: string | Buffer };
  serverName?: string;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

export interface McpServer {
  readonly endpoint: string;
  readonly port: number;
  readonly server: HttpServer | HttpsServer;
  close: () => Promise<void>;
}

interface JsonRpcRequest { jsonrpc: "2.0"; id?: string | number | null; method: string; params?: unknown }

function rpcError(id: string | number | null, code: number, message: string, data?: unknown) {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": String(bytes.length), "cache-control": "no-store" });
  response.end(bytes);
}

function readBody(request: IncomingMessage, maxBytes: number): Promise<Buffer | "too-large"> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) { resolve("too-large"); request.resume(); return; }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function tokenMatches(header: string | undefined, expected: string): boolean {
  if (header === undefined || !header.startsWith("Bearer ")) return false;
  const presented = Buffer.from(header.slice(7), "utf8");
  const wanted = Buffer.from(expected, "utf8");
  return presented.length === wanted.length && timingSafeEqual(presented, wanted);
}

export async function startBuyerMcpServer(options: McpServerOptions): Promise<McpServer> {
  if (options.bearerToken.length < 32) throw new Error("MCP bearer token must be at least 32 characters");
  const hostname = options.hostname ?? "127.0.0.1";
  if (options.tls === undefined && !["127.0.0.1", "::1", "localhost"].includes(hostname)) {
    throw new Error("plain HTTP is restricted to loopback; supply TLS key and cert for other bindings");
  }
  const log = options.log ?? (() => {});
  const tools = buyerTools(options.service);
  const byName = new Map(tools.map((tool) => [tool.name, tool]));

  async function handleRpc(message: JsonRpcRequest): Promise<unknown | undefined> {
    const id = message.id ?? null;
    switch (message.method) {
      case "initialize":
        return { jsonrpc: "2.0", id, result: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: options.serverName ?? "supercolony-dacs-rfq-buyer", version: "0.1.0" },
          instructions: "Negotiate privately with a DACS seller. Call find_listing, then open_negotiation, then make_offer. Read get_negotiation_state before each move; accept only when the standing proposal is acceptable and within your ceiling.",
        } };
      case "notifications/initialized":
        return undefined;
      case "ping":
        return { jsonrpc: "2.0", id, result: {} };
      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) } };
      case "tools/call": {
        const params = message.params as { name?: unknown; arguments?: unknown } | undefined;
        const tool = typeof params?.name === "string" ? byName.get(params.name) : undefined;
        if (tool === undefined) return rpcError(id, -32602, "unknown tool");
        try {
          const args = exactArgs(params?.arguments ?? {}, tool.required, tool.optional);
          const result = await tool.run(args);
          log({ event: "mcp-tool", tool: tool.name, ok: true });
          return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result, isError: false } };
        } catch (cause) {
          const code = cause instanceof BuyerServiceError ? cause.code : "internal";
          const text = cause instanceof Error ? cause.message : String(cause);
          log({ event: "mcp-tool", tool: tool.name, ok: false, code, reason: text });
          // Tool-level failures are normal tool results for the model, not protocol errors.
          return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify({ error: code, message: text }) }], isError: true } };
        }
      }
      default:
        return rpcError(id, -32601, "method not found");
    }
  }

  const listener = (request: IncomingMessage, response: ServerResponse) => {
    (async () => {
      if (request.url !== MCP_PATH) { writeJson(response, 404, { error: "not-found" }); return; }
      if (!tokenMatches(request.headers.authorization, options.bearerToken)) {
        response.writeHead(401, { "www-authenticate": "Bearer" }); response.end(); return;
      }
      if (request.method === "GET") { writeJson(response, 405, { error: "sse-not-supported" }); return; }
      if (request.method !== "POST") { writeJson(response, 405, { error: "method-not-allowed" }); return; }
      const body = await readBody(request, 65_536);
      if (body === "too-large") { writeJson(response, 413, { error: "body-too-large" }); return; }
      let parsed: unknown;
      try { parsed = JSON.parse(body.toString("utf8")); } catch { writeJson(response, 400, rpcError(null, -32700, "parse error")); return; }
      const messages = Array.isArray(parsed) ? parsed : [parsed];
      const replies: unknown[] = [];
      for (const message of messages) {
        if (message === null || typeof message !== "object" || (message as JsonRpcRequest).jsonrpc !== "2.0" || typeof (message as JsonRpcRequest).method !== "string") {
          replies.push(rpcError(null, -32600, "invalid request"));
          continue;
        }
        const reply = await handleRpc(message as JsonRpcRequest);
        if (reply !== undefined) replies.push(reply);
      }
      if (replies.length === 0) { response.writeHead(202); response.end(); return; }
      writeJson(response, 200, Array.isArray(parsed) ? replies : replies[0]);
    })().catch((cause) => {
      log({ event: "mcp-handler-error", reason: cause instanceof Error ? cause.message : String(cause) });
      if (!response.headersSent) writeJson(response, 500, rpcError(null, -32603, "internal error"));
      else response.destroy();
    });
  };
  const server = options.tls === undefined ? createHttpServer(listener) : createHttpsServer({ key: options.tls.key, cert: options.tls.cert }, listener);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, hostname, () => { server.off("error", reject); resolve(); });
  });
  const address = server.address() as AddressInfo;
  const host = address.family === "IPv6" ? `[${address.address}]` : address.address;
  return {
    endpoint: `${options.tls === undefined ? "http" : "https"}://${host}:${address.port}${MCP_PATH}`,
    port: address.port,
    server,
    close: () => new Promise<void>((resolve, reject) => { server.closeAllConnections?.(); server.close((e) => (e ? reject(e) : resolve())); }),
  };
}
