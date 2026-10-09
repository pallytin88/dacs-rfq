#!/usr/bin/env -S node --import tsx
/**
 * Operator side of tester registration, against the seller's registration
 * store (seller may keep running; SQLite WAL):
 *
 *   tsx bin/approve.mts list
 *   tsx bin/approve.mts approve <claim>     provisions a subnet on the node, funds the tester, seals the credential
 *   tsx bin/approve.mts reject <claim> [note]
 */
import { join } from "node:path";
import { createFsSubnetProvisioner, createRegistrationService, createRegistrationStore, fundOnLocalChain, openDemosActor } from "../src/index.js";
import { loadConfig, log } from "./common.mts";

const [command, claim, ...rest] = process.argv.slice(2);
const env = loadConfig();
for (const key of ["L2PS_RPC", "L2PS_NODE_ROOT"]) if (!env[key]) throw new Error(`${key} missing`);
const root = join(env["DACS_RFQ_ROOT"]!, "seller");
const store = createRegistrationStore({ path: join(root, "registrations.db") });
const funder = await openDemosActor({ rpc: env["L2PS_RPC"]!, secret: env["SELLER_WALLET"]!, journalDir: join(root, "l2ps-journal") });
const fundDem = Number(env["REGISTRATION_FUND_DEM"] ?? 100);
const service = createRegistrationService({
  store, host: env["L2PS_PUBLIC_RPC"] ?? env["L2PS_RPC"]!, log,
  provisioner: createFsSubnetProvisioner({ nodeRoot: env["L2PS_NODE_ROOT"]!, rpc: env["L2PS_PUBLIC_RPC"] ?? env["L2PS_RPC"]! }),
  funder: { fund: async (addressHex) => { const out = await fundOnLocalChain({ demos: funder.adapter.raw as never, to: `0x${addressHex}`, amountDem: fundDem }); if (out.status !== "confirmed") throw new Error(`funding ${out.txHash} ended ${out.status}`); return { txHash: out.txHash }; } },
});
if (command === "list") {
  for (const row of service.list()) console.log(JSON.stringify({ claim: row.claim, status: row.status, requestedAt: new Date(row.requestedAt).toISOString(), uid: row.uid, fundingTx: row.fundingTx, note: row.note }));
} else if (command === "approve" && claim) {
  const row = await service.approve(claim);
  console.log(JSON.stringify({ approved: row.claim, uid: row.uid, fundingTx: row.fundingTx }));
} else if (command === "reject" && claim) {
  const row = service.reject(claim, rest.join(" ") || "rejected by operator");
  console.log(JSON.stringify({ rejected: row.claim, note: row.note }));
} else {
  throw new Error("usage: approve.mts list | approve <claim> | reject <claim> [note]");
}
store.close();
process.exit(0);
