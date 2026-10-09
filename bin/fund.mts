#!/usr/bin/env -S node --import tsx
/**
 * Operator-run helper: move testnet DEM from a funder wallet you control to
 * the two showcase wallets. This moves tokens, so it is for you to run, not
 * the agent.
 *
 *   FUNDER_WALLET="<mnemonic>" AMOUNT_DEM=100 tsx bin/fund.mts
 *
 * Reads BUYER_ADDRESS / SELLER_ADDRESS / DEMOS_RPC from ~/.dacs-rfq/wallets.env.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { createPayDemRail } from "@kynesyslabs/dacs/rails";
import { readEnvFile } from "../src/index.js";

const env = readEnvFile(process.env["DACS_RFQ_ENV"] ?? join(homedir(), ".dacs-rfq", "wallets.env"));
const funder = process.env["FUNDER_WALLET"];
if (!funder) throw new Error("FUNDER_WALLET (mnemonic of a wallet you control) is required");
const amountOs = BigInt(process.env["AMOUNT_DEM"] ?? "100") * 1_000_000_000n;
const feeOs = 1_000_000_000n;
const rail = await createPayDemRail({ rpc: env["DEMOS_RPC"]!, secret: funder, network: "demos", maxTotalDebitOs: amountOs + feeOs });
for (const role of ["BUYER", "SELLER"]) {
  const payee = env[`${role}_ADDRESS`]!;
  const result = await rail.settle({ recipient: payee, amount: amountOs.toString(), network: "demos", maxTotalDebitOs: (amountOs + feeOs).toString() });
  process.stdout.write(`${role} ${payee.slice(0, 12)}… tx=${result.txHash} ok=${result.ok}\n`);
}
