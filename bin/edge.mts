#!/usr/bin/env -S node --import tsx
/**
 * Loopback edge for one public hostname: routes the seller's transport and
 * registration (`/colony-rfq/*`, `/.well-known/*`) to the seller server and
 * everything else to the host node RPC. Put a tunnel or TLS proxy in front.
 *
 *   EDGE_PORT=47300 SELLER_PORT=47101 NODE_PORT=53550 tsx bin/edge.mts
 */
import { createServer, request as httpRequest } from "node:http";

const port = Number(process.env["EDGE_PORT"] ?? 47300);
const seller = Number(process.env["SELLER_PORT"] ?? 47101);
const node = Number(process.env["NODE_PORT"] ?? 53550);
const MAX_BODY = 1_048_576;

const server = createServer((req, res) => {
  const path = req.url ?? "/";
  const target = path.startsWith("/colony-rfq/") || path.startsWith("/.well-known/") ? seller : node;
  const chunks: Buffer[] = [];
  let size = 0;
  req.on("data", (chunk: Buffer) => { size += chunk.length; if (size > MAX_BODY) { req.destroy(); return; } chunks.push(chunk); });
  req.on("end", () => {
    const headers: Record<string, string> = { "content-type": req.headers["content-type"] ?? "application/json", "x-forwarded-for": String(req.headers["cf-connecting-ip"] ?? req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? ""), "x-forwarded-proto": "https" };
    const upstream = httpRequest({ host: "127.0.0.1", port: target, method: req.method, path, headers }, (up) => {
      res.writeHead(up.statusCode ?? 502, { "content-type": up.headers["content-type"] ?? "application/json", "cache-control": "no-store" });
      up.pipe(res);
    });
    upstream.on("error", () => { if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "upstream-unavailable" })); });
    upstream.end(Buffer.concat(chunks));
  });
});
server.listen(port, "127.0.0.1", () => process.stdout.write(JSON.stringify({ event: "edge-listening", port, seller, node }) + "\n"));
