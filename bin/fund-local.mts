#!/usr/bin/env -S node --import tsx
/**
 * Fund a tester wallet on the self-hosted chain from our buyer wallet:
 *   tsx bin/fund-local.mts <0xaddress> <amountDem>
 * Uses the node at L2PS_RPC. A plain native send, confirmed then broadcast,
 * and waited for inclusion; prints the transaction hash.
 */
import { join } from "node:path";
import { fundOnLocalChain, openDemosActor } from "../src/index.js";
import { loadConfig } from "./common.mts";

const [to, amountDem] = process.argv.slice(2);
if (!to || !/^0x[0-9a-f]{64}$/i.test(to) || !amountDem || !/^[0-9]+$/.test(amountDem)) throw new Error("usage: fund-local.mts <0x64hex> <wholeDem>");
const env = loadConfig();
const rpc = env["L2PS_RPC"];
if (!rpc) throw new Error("L2PS_RPC missing");
const funder = await openDemosActor({ rpc, secret: env["FUNDER_WALLET"] ?? env["BUYER_WALLET"]!, journalDir: join(env["DACS_RFQ_ROOT"]!, "funder", "l2ps-journal") });
const before = await funder.balanceOs();
const out = await fundOnLocalChain({ demos: funder.adapter.raw as never, to, amountDem: Number(amountDem) });
console.log(JSON.stringify({ ...out, to: to.toLowerCase(), amountDem, funderBalanceBeforeDem: (before / 1_000_000_000n).toString(), funderBalanceAfterDem: ((await funder.balanceOs()) / 1_000_000_000n).toString() }));
process.exit(out.status === "confirmed" ? 0 : 1);
