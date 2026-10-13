#!/usr/bin/env -S node --import tsx
/**
 * Scripted "ChatGPT agent" for the live showcase: speaks only MCP to the
 * buyer. Opens, offers 9, counters 9.5 if the seller asks more, waits for the
 * deal to settle, prints receipts.
 *
 *   MCP_ENDPOINT=http://127.0.0.1:47110/mcp MCP_TOKEN=... tsx bin/drive.mts
 */

const endpoint = process.env["MCP_ENDPOINT"] ?? "http://127.0.0.1:47110/mcp";
const token = process.env["MCP_TOKEN"];
if (!token) throw new Error("MCP_TOKEN missing");
let id = 1;
async function rpc(method: string, params?: unknown) {
  const r = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: id++, method, params }) });
  if (r.status !== 200) throw new Error(`HTTP ${r.status}`);
  return r.json() as Promise<{ result?: { structuredContent?: unknown; isError?: boolean; content?: Array<{ text: string }>; tools?: unknown[] }; error?: unknown }>;
}
async function call<T>(name: string, args: Record<string, unknown>): Promise<T> {
  const reply = await rpc("tools/call", { name, arguments: args });
  if (reply.error) throw new Error(JSON.stringify(reply.error));
  if (reply.result?.isError) throw new Error(reply.result.content?.[0]?.text ?? "tool error");
  process.stderr.write(`[model] ${name}(${JSON.stringify(args)}) -> ${JSON.stringify(reply.result?.structuredContent).slice(0, 300)}\n`);
  return reply.result!.structuredContent as T;
}
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "showcase-driver", version: "0" } });
const listings = await call<Array<{ listingId: string }>>("find_listing", {});
if (listings.length === 0) throw new Error("no listing");
const opened = await call<{ jobId: string; priceBand: unknown }>("open_negotiation", { listingId: listings[0]!.listingId });
const jobId = opened.jobId;
let state = await call<{ status: string; phase: string; yourTurn: boolean; standingProposal: { amount: string; proposer: string } | null; lastError?: string }>("make_offer", { jobId, amount: process.env["OPEN_OFFER_DEM"] ?? "9" });
for (let i = 0; i < 120; i += 1) {
  if (state.phase === "settled" || state.phase === "terminal") break;
  if (state.status === "open" && state.yourTurn && state.standingProposal !== null) {
    const ask = Number(state.standingProposal.amount);
    if (ask <= Number(process.env["ACCEPT_UP_TO_DEM"] ?? "9.8")) state = await call("accept", { jobId });
    else state = await call("counter_offer", { jobId, amount: process.env["COUNTER_DEM"] ?? "9.5" });
    continue;
  }
  await wait(3_000);
  state = await call("get_negotiation_state", { jobId });
}
const receipts = await call("get_receipts", { jobId });
process.stdout.write(JSON.stringify({ jobId, finalPhase: state.phase, lastError: state.lastError, receipts }, null, 2) + "\n");
