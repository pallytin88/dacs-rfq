# @colony/dacs-rfq

SuperColony's adapters for private RFQ negotiation on top of `@kynesyslabs/dacs`.
Everything here sits behind the injected seams of `createDurableRfqLifecycleClient`;
the SDK's negotiation logic is not modified.

Status (2026-10-06): Steps 1, 2, 3, 5 and 6 of the private-negotiation brief,
verified offline end to end (`test/showcase.e2e.test.ts`,
`test/live.wiring.test.ts`), and wired to the live Demos testnet node through
`src/live/` and the `bin/` processes. The showcase runs on the **interim direct
transport**; the L2PS transport (Step 4) waits on dacs-sdk#329 and a node that
exposes the messaging server. The first live run needs funded wallets (see
"Live runbook").

## What each piece does

### Step 1 — `src/channelSignature.ts`: who signed this turn, and over what bytes

Every offer, counter and accept is a channel message that the other side must be
able to authenticate before the SDK's state machine will act on it. Two profiles:

| Profile id | What it is | Where it is used |
| --- | --- | --- |
| `dacs-canonical-channel-message:v1` | The normative DACS-3 v0.6 wire (PR #367): discriminator, version-1 signature envelope, SIG-6 Base64URL, signed bytes `"dacs-canonical-channel-message:v1:" ‖ hex(sha256(JCS(unsigned)))`. `signCanonicalChannelMessage`, `readCanonicalChannelMessage`, and the explicit `importLegacyChannelMessage` arm (historical senders limited to the reference reader's `cci:<64 hex>` / `did:<method>:<id>` grammar; a signer that does not parse is `error`, not `fail`). | Standalone. Checked against the Standard's 55-vector corpus (`test/vectors/`). Cannot yet be carried by the SDK seam (dacs-sdk#330). |
| `provisional-rfq-sig:v0` | **Provisional. Not the DACS standard format.** Same construction, applied to the SDK's seven-field envelope hash, under its own domain `provisional-rfq-sig:v0:` so its bytes can never pass as canonical. | `createChannelSignatureAdapter` → the SDK's `signChannelMessage` / `verifyChannelMessage`. Profile id is recorded in every log line. |

With the SDK at or after dacs-sdk PR #332 (the fix for #330, which the local
`dacs-sdk` checkout carries on branch `feat/canonical-channel-message-v06`),
the adapter signs and verifies the canonical profile through the SDK seam: the
SDK frames the CH-8 bytes and emits the discriminator, the adapter only holds
the key. On an older SDK the canonical profile throws and
`provisional-rfq-sig:v0` is the only option. Verification is four-valued: a tampered envelope,
wrong sender, non-member, or wrong key is `fail`; malformed input is `error`;
an unresolvable member key is `indeterminate`. Ed25519 and ECDSA secp256k1
(canonical DER, low-S) are implemented; SR-1 aggregate reports `indeterminate`.

Corpus result: 51 of 55 vectors match the Standard's expected outcome; the 4
`sr1-aggregate` vectors are reported `indeterminate` instead of `pass`/`fail`.

### Step 2 — `src/channelReservation.ts` and `src/roleStores.ts`: one channel id, one session, forever

DACS-3 CH-6 says a channel id can belong to exactly one session, or replayed
offers from an old session would verify in a new one. `createSqliteChannelReservation`
makes that durable: first reservation `pass`, byte-identical repeat `pass`,
anything else `fail`, a locked or broken database `indeterminate`, bad input
`error`. The decision survives restarts because it is a row in a 0600 SQLite
file, not a `Set`.

`openRoleStores` lays out one root per role:

```
<root>/rfq/              SDK authenticated filesystem lifecycle store (0700)
<root>/reservations.db   channel reservations
<root>/transport.db      interim transport inbox + nonce log
<keyPath>                32-byte integrity key, 0600, must be outside <root>
```

Buyer and seller never share a directory or a key.

### Step 3 — `src/transport/`: delivering packets so that "acknowledged" means "durably stored"

The SDK's outbox only clears an entry when the transport says `acknowledged`,
and only resends after an authenticated `absent`. The interim transport makes
both statements true without L2PS:

- `envelope.ts`: a colony-local signed envelope (`colony-rfq-transport:v0`,
  Ed25519, nonce, five-minute lifetime, audience-bound). Not a DACS wire.
- `inboxStore.ts`: the receiver writes the packet and the nonce in one SQLite
  transaction **before** it signs an acknowledgement.
- `server.ts`: `POST /colony-rfq/v0/messages`. Plain HTTP binds to loopback
  only; anything else needs TLS material.
- `client.ts`: implements `DurableRfqLifecycleTransport`. `publish` → signed
  `stored`/`duplicate` = `acknowledged`; lost response = `indeterminate`.
  `reconcile` → signed `present` = `acknowledged`, signed `absent` = `absent`,
  unreachable = `indeterminate`.
- `drain.ts`: feeds stored packets into the role's lifecycle client in arrival
  order and marks them processed only after the client recorded its outcome.

Label it in any UI as: *private negotiation, L2PS transport coming.*

### Step 5 — `src/buyer/`: the buyer as a tool the model calls

`createBuyerNegotiationService` holds the keys, the stores and the outbox. The
model only ever gets structured results and only ever sends structured
arguments. `startBuyerMcpServer` exposes it as an MCP server (JSON-RPC 2.0 over
`POST /mcp`, bearer token, loopback-only without TLS) with exactly the tools
from the brief:

| Tool | What the code enforces |
| --- | --- |
| `find_listing` | catalog lookup; returns id, seller, band, turn limits |
| `open_negotiation` | pins the Listing bytes, generates a ULID job and a fresh channel id, announces the session to the seller, opens the lifecycle |
| `get_negotiation_state` | drains the inbox, resumes the outbox, advances the deal, reports turn/time/band/ceiling/standing proposal |
| `make_offer` / `counter_offer` | decimal string only; buyer ceiling checked here, Listing band checked by the SDK; a refused amount is a normal tool error |
| `accept` | refused above the ceiling or on your own proposal; then co-sign → commit → pay run automatically and idempotently |
| `reject` | ends the session |
| `get_receipts` | agreement hash, channel binding, commitment receipt, settlement tx, transcript hashes; never offer contents |

Policies live in `src/policy.ts`: `createBuyerCeilingGuard` (buyer) and the
deterministic `createSellerRulePolicy` (accept at or above a floor, otherwise
counter toward it, reject when out of turns). `src/seller/daemon.ts` runs the
seller: opens announced sessions that match one of its own Listings, drains
turns, and responds where it is its turn.

### Step 6 — `src/commit.ts`, `src/settle.ts`: what goes on chain

`commitNegotiatedAgreement` feeds the co-signed agreement and the accepted
checkpoint into the SDK's `commitRfqAgreement`, so only the
`FinalityCommitmentRecord` (hash, parties, pattern, times, signature) is
anchored at `dacs3:commit:{jobId}`. Two providers: an in-memory one for tests
and `createDemosFinalityProvider` over dacs-node's Demos adapter (write once,
read back, authenticated receipt, independent verification), the same pattern
dacs-node uses for its own commitments.

`settleWithPayDem` pays `terms.price` of the locally held agreement to the
seller's Demos address over the native DEM rail, inside
`executeWalletSpendEffectV1` with a reservation bound to the agreement hash and
the commitment address. A SQLite `WalletSpendStateStore` is provided for a
single-host buyer. The fixed-price publication track that writes the full
agreement at `dacs3:agreement` (dacs-sdk#331) is **not** run.

The showcase test checks the public claim directly: after a full run the only
anchored bytes are the commitment record, and they contain no offer, counter
or price value.

## Live wiring — `src/live/` and `bin/`

Everything that was faked in the offline showcase has a live counterpart:

| Fake in tests | Live |
| --- | --- |
| Node KeyObject signer | `openDemosActor`: SDK `DemosAdapter` from a mnemonic, filesystem write journal, `signer.sign` → `adapter.sign`; the key never leaves the adapter |
| in-memory finality provider | `createDemosFinalityProvider` over the adapter (write-once at `dacs3:commit:{jobId}`, read back, authenticated receipt) |
| fake DEM rail | SDK `createPayDemRail` behind the real wallet spend authority with a SQLite state store |
| static listing | `buildRfqListingDraft` → `signListing` (`dacs-listing:v1:`) → `publishListing` (write-once at the normative listing address); buyer `discoverVerifiedListing` reads it back and runs the SDK's `validateListingArtifact` |
| placeholder vet refs | `signVetRecord` / `publishVetOf` / `readVetBy`: each party signs a DACS-2 composite verification record about the other, anchors it at `compositeVerificationAddress(jobId, party)`; the buyer's ref travels in the announcement, the seller's is read back from chain before the buyer opens |
| in-memory chain | `demosAnchorStore` (write-once with receipts) or `inMemoryAnchorStore` (tests) behind one `AnchorStore` interface |

### The DACS front end: the Directory

The only DACS front end is the **DACS Directory** in
`Community/reference-implementations/dacs-directory` (a Next.js catalog and
in-browser verifier that crawls the chain; no registration needed). The hosted
instance is `https://community-production-9ab1.up.railway.app`
(`/api/health`, `/api/dacs/status`, `/api/dacs/listings`). It indexes
`negotiate-rfq` listings under the `dacs-v0.1` profile, so the seller's listing
appears there once anchored.

`src/live/directory.ts` makes it the buyer's catalog: `createDirectoryCatalog`
queries the directory for the configured seller, re-reads each hit from chain at
the anchor the directory names, runs the SDK's `validateListingArtifact`, and
offers only listings whose bytes verify and match the directory's hash.
`bin/buyer.mts` uses it by default (`DIRECTORY_URL` overrides the host;
`LISTING_REF` pins a single listing instead).

Known cross-publisher drift (2026-10-07): several third-party listings on the
hosted directory (`audit-negotiator`, `oracle-data`, …) carry `dacsVersion` as a
number and a string `verificationMethod`, which the SDK head's listing schema
rejects at step 1. Our own listing is produced by the SDK head and verifies.

### Seller discovery surface (§6.3.5 well-known files)

`publish-listing` also writes `<root>/well-known/agent.json` and
`<root>/well-known/dacs/listings.json` (`src/live/wellKnown.ts`), the A2A card
plus hash-bound listings index that the DACS Directory's federation crawler
reads from a seller's public HTTPS domain, and the seller transport serves them
at `/.well-known/…`. `agent.json` binds `listings.json` by SHA-256 of its exact
bytes, so host them byte-exact. The crawler only reads public HTTPS, so this
matters once the seller has a real domain in front of it (`SELLER_PUBLIC_ENDPOINT`).
Until then the Directory still finds the listing by crawling the chain.

### Showcase viewer: the deal as a two-agent chat

`bin/buyer.mts` also serves a read-only showcase (`SHOWCASE_PORT`, default
47120, loopback): a page that renders each negotiation as a buyer/seller chat
over the five DACS stages, plus `GET /demo/procurement`,
`GET /demo/procurement/{jobId}` and `GET /demo/procurement/options`. The event
stream (`{ phase, label, at, txRef?, anchorRef? }`) follows the contract of
the DACS Directory's `/try-chat` page (Community, MIT), so the community UI
and KyneSys's own gateway viewers can render it unchanged. Events are derived
on demand from the durable lifecycle record and session index
(`src/buyer/procurement.ts`), never stored separately, so a restart cannot
lose or reorder them.

Context: KyneSys's custodied demo gateway (`butler.agentcommerce.network`)
exposes the same contract and already runs a live `security-audit-rfq`
profile with a gateway-custodied buyer that accepts no external DACS
identity. Our stack is the complementary shape: an operator-custodied buyer
that a model drives through MCP.

### Live runbook (testnet only)

1. Wallets: `~/.dacs-rfq/wallets.env` (mode 0600, outside the repo) holds
   `BUYER_WALLET`, `SELLER_WALLET`, their `_ADDRESS`/`_DID`, and `DEMOS_RPC`.
   Two dedicated wallets were minted on 2026-10-06 and funded on 2026-10-08
   from the public faucet (`POST https://faucetbackend.demos.network/api/request`
   with `{"address": "0x…"}`, 2,400 DEM per request; the older
   `faucetbackend.demos.sh` host answers healthy but fails every request).
   To top up from a wallet you control instead:
   ```bash
   FUNDER_WALLET="<mnemonic you control>" AMOUNT_DEM=100 tsx bin/fund.mts
   ```
   Budget: a few DEM per anchor (listing, two vet records, commitment) plus the
   negotiated price.
2. Seller, once: `tsx bin/seller.mts publish-listing` → prints `LISTING_REF=…`.
3. Seller: `BUYER_TRANSPORT_URL=http://127.0.0.1:47102/colony-rfq/v0/messages tsx bin/seller.mts run`
4. Buyer: `LISTING_REF=… MCP_TOKEN=<32+ chars> SELLER_TRANSPORT_URL=http://127.0.0.1:47101/colony-rfq/v0/messages tsx bin/buyer.mts run`
   (`MAX_NETWORK_FEE_OS` defaults to 2 DEM, the testnet's 1 DEM network + 1 DEM RPC fee per transaction; the pay-dem rail refuses to broadcast if the node-confirmed debit exceeds price + this ceiling)
   Spend ledger: the buyer's wallet spend authority binds its SQLite ledger to
   the exact policy, so the file is named by policy hash plus
   `SPEND_LEDGER_EPOCH` (default `1`). Bump the epoch only after every held
   reservation in the current ledger has been checked against the chain. All
   wallet writes (vet and commitment anchors, the pay-dem transfer) are
   serialised behind one lock: concurrent writers race on the account nonce and
   the loser is included as `failed` (`TX_NONCE_INVALID_LOW`). A settled
   transfer is authenticated by reading it back from the node; a transfer the
   chain included as `failed` is reconciled as terminal absence automatically,
   or by an operator with `SPEND_LEDGER_EPOCH=… tsx bin/reconcile.mts <jobId> <txHash>`;
   either way the failed transaction must be this wallet's transfer to the
   reserved payee for the reserved amount, an operator hash that differs from
   the remembered one is refused, and a transfer the chain confirmed is
   reported settled and never released
   (stop the buyer first). Remembered evidence lives in `<root>/settlement-evidence.json`.
5. Model: point ChatGPT at the MCP endpoint (TLS and a public hostname are needed for that; both servers refuse non-loopback binds without TLS material), or run the scripted driver: `MCP_TOKEN=… tsx bin/drive.mts`.

All `bin/*.mts` run with `tsx` (`node_modules/.bin/tsx` at the colony root).
Both transport servers and the MCP server bind loopback by default.

## L2PS transport (Step 4) on a self-hosted node

`TRANSPORT=l2ps` carries every lifecycle packet as an encrypted L2PS subnet
transaction instead of the interim HTTP envelope. Each packet is a native send
of 1 OS from the sender's wallet to the recipient's wallet on the subnet chain,
whose data member holds the same Ed25519-signed `colony-rfq-transport:v0`
envelope (`src/transport/l2ps.ts`, carrier `colony-rfq-l2ps:v0`). The subnet
key gives confidentiality against everyone outside the subnet; the envelope
keeps authenticity and CH-7 binding. `publish` acknowledges only once the host
node's signed history read shows the carrier at `L2PS_ACK_STATUS` (default
`confirmed`, i.e. batched and settled on that chain); `reconcile` re-reads the
sender's own history; a feeder polls each member's history and admits carriers
addressed to it into the same inbox `drainInbox` already consumes.

Env (in `wallets.env`): `L2PS_RPC` (host node RPC), `L2PS_UID`, `L2PS_KEY_FILE`,
`L2PS_IV_FILE` (paths to the node's `private_key.txt` / `iv.txt`; the key never
goes in the env file), optional `L2PS_ACK_STATUS`, `L2PS_POLL_MS`. Mixed mode
is the rehearsal of the final demo: negotiation on the self-hosted subnet
(`L2PS_RPC`), listing, vets, commitment and payment on the public testnet
(`DEMOS_RPC`).

Self-hosted node (checkout `/home/ml/node`, branch `colony/stabilisation` from
upstream `stabilisation`, which carries the fork-aware transaction verification
that demosdk 4.x signs for; the 0.9.8 `testnet` branch rejects 4.x signatures):

```bash
cd /home/ml/node
mkdir -p data/l2ps/colony_rfq_001 && chmod 700 data/l2ps/colony_rfq_001
openssl rand -hex 32 > data/l2ps/colony_rfq_001/private_key.txt   # subnet key, 0600
openssl rand -hex 16 > data/l2ps/colony_rfq_001/iv.txt
# data/l2ps/colony_rfq_001/config.json names the uid and the two key files
# data/genesis.json: add both agent wallets to "balances" (local chain funds)
# .env: SERVER_PORT=53550, MCP/TLSNOTARY/METRICS/OMNI disabled, L2PS_MIN_BATCH_SIZE=1
echo '[]' > demos_peerlist.json                      # lone anchor node, produces blocks itself
(cd postgres && PG_PORT=5332 docker compose up -d)
RPC_PORT=53550 PG_PORT=5332 IDENTITY_FILE=.demos_identity bun run start:bun -- --no-tui
```

The `stabilisation` node boots from the bundled testnet snapshot in
`data/snapshot/`, which owns the validator set; a lone node is not in it and
the committee floor refuses to forge, so subnet batches never reach an L1
block and history stays at `batched`. For the local chain, append the node's
own identity (printed at boot as "Our public key is") to
`data/snapshot/validators.jsonl`, update that file's `sha256` and `rows` in
`manifest.json`, set `SHARD_SIZE=1` in `.env`, and reset the database
(`DROP DATABASE demos` inside the container; the bind-mounted data directory
is root-owned). The node then forges as a one-member committee and carriers
reach `confirmed` within seconds. One local patch is applied to the node
(kynesyslabs/node#1033): the authenticated history read also returns each
row's stored ciphertext (`encrypted_payload`,
`src/libs/network/handlers/l2psHandlers.ts`); upstream returns only the
message string, which cannot carry a signed envelope. The member decrypts
that ciphertext locally with the subnet key and checks the decrypted hash
against the row (`src/transport/l2psDemos.ts`); a `content` field offered
by any node is never used, since the history signature proves the reader to
the node and not the node to the reader.

First mixed-mode run (2026-10-08): job `01M4EHYZ8S92A61TP04FRDAZVM`, every
channel packet an encrypted subnet transaction confirmed in 2–7 s, commitment
`stor-bb0f774841fb110e057af3d40b55414d138aef31` and payment
`d2cc363d…` on the public testnet. The host stores only ciphertext
(`l2ps_transactions.content` null, `encrypted_payload` set), the public records
carry no offer, counter or turn price, and a wallet outside the deal reading its
own subnet history gets zero rows.

`bun install` hoists `@noble/hashes` 2.x over the 1.8.0 demosdk pins; if the node
fails with `Cannot find module '@noble/hashes/sha3'`, nest a 1.8.0 copy under
`node_modules/@kynesyslabs/demosdk/node_modules/@noble/hashes`.

## Letting others test against the node

`TESTERS.md` is the guide to hand a tester. Operator side:

- `PEER_DIDS=did:demos:agent:…,did:demos:agent:…` on the seller admits extra
  buyer claims (their Ed25519 key is the claim itself); each tester gets its
  own subnet directory under the node's `data/l2ps/` and a node restart.
- `tsx bin/fund-local.mts <0xaddress> <wholeDem>` transfers DEM on the
  self-hosted chain from our wallet (native-send amounts are whole DEM on this
  fork; the node scales them to OS).
- The viewer's `/demo/subnet` (and the panel under the chat) is the
  ciphertext exhibit: this member's subnet rows as hash, parties, status and
  time, never content.
- Registration (seller with `L2PS_NODE_ROOT` set): testers `POST
  /colony-rfq/v0/register` a request signed by their claim and carrying an
  X25519 key; `tsx bin/approve.mts list | approve <claim> | reject <claim>`
  provisions `data/l2ps/<uid>/` on the node, funds the tester
  (`REGISTRATION_FUND_DEM`, default 100) and seals the credential to the
  tester's key (`src/registration/`). Approved claims join the seller's peer
  table live and the seller attaches one subnet client per tester; the node
  loads a new subnet on its first transaction, no restart.
- Approval policy: `REGISTRATION_AUTO_APPROVE=all` (open test network) or a
  comma list of claims approves on submit; otherwise every request waits for
  `bin/approve.mts`. With `all`, `REGISTRATION_AUTO_APPROVE_MAX` (default 20)
  bounds how many claims are provisioned and funded unattended; later
  requests stay pending for the operator. Approval records the minted subnet
  and the signed funding hash before the fund is broadcast, so an approval
  interrupted mid-way resumes with the same subnet and never funds twice.
- The tester keeps only the host sealed into the credential; `register.mts`
  requires an `https://` `REGISTER_URL` off loopback and ignores a host named
  by the clear-text status response.
- Supervision: systemd user units `dacs-postgres`, `dacs-node`, `dacs-seller`,
  `dacs-buyer`, `dacs-edge`, `dacs-tunnel`, `dacs-caddy` in
  `~/.config/systemd/user` (env files in `~/.dacs-rfq/service/`, lingering
  enabled). `systemctl --user status 'dacs-*'`, `journalctl --user -u dacs-seller -f`.
  The quick tunnel's hostname changes on every start: read it with
  `journalctl --user -u dacs-tunnel | grep trycloudflare`, put it in
  `L2PS_PUBLIC_RPC` and `systemctl --user restart dacs-seller`.
- Stable hostname (current): Tailscale Funnel, `https://dacs-node.tailfa48ff.ts.net` → the edge on
  :47300. Rootless `tailscaled` runs as the `dacs-tailscaled` user unit
  (`--tun=userspace-networking`, state in `~/.tailscale`); the Funnel config is
  persisted by `tailscale funnel --bg 47300`. Starlink residential is behind
  carrier-grade NAT, so no inbound port can be forwarded and the Caddy path
  below does not apply there.
- Stable hostname (port-forwarding ISPs only): `dacs-caddy` serves `129-222-243-22.sslip.io` on 8080/8443
  (`~/.dacs-rfq/service/Caddyfile`) with automatic Let's Encrypt once the
  router forwards 80→8080 and 443→8443 to this machine; swap in a DuckDNS name
  if preferred. Then set `L2PS_PUBLIC_RPC=https://<name>` and stop `dacs-tunnel`.
- Exposure: `tsx bin/edge.mts` is a loopback edge on :47300 that routes
  `/colony-rfq/*` and `/.well-known/*` to the seller server and everything
  else to the node RPC, so one public hostname serves registration, transport
  and the subnet. Quick path (no domain, no router changes):
  `cloudflared tunnel --url http://127.0.0.1:47300 --no-autoupdate` prints a
  `https://<random>.trycloudflare.com` URL; put it in `L2PS_PUBLIC_RPC` (it is
  what issued credentials carry as `host`) and restart the seller. The quick
  tunnel's hostname changes on every restart; for a stable name forward ports
  80/443 and use Caddy with a DuckDNS or sslip.io hostname instead. The node
  itself stays on loopback; set `TRUSTED_PROXIES=127.0.0.1` in its `.env` so
  its rate limiter reads the forwarded client address.

## Tests

```bash
cd packages/dacs-rfq
node ../../dacs-sdk/node_modules/.bin/vitest run
../../node_modules/.bin/tsc --noEmit -p tsconfig.json
```

`test/showcase.e2e.test.ts` drives the buyer purely through MCP tool calls
against a seller daemon over the interim transport, with real files, an
in-memory finality provider and a fake DEM rail behind the real spend
authority. `test/lifecycle.e2e.test.ts` runs a buyer and a seller as two servers on
loopback with real files: offer → counter → accept → co-signed agreement, an
out-of-band counter refused before sending, and a buyer that loses every
acknowledgement, restarts from disk, reconciles, and does not duplicate the
offer on the seller.

## Dependency note

The colony root `npm install` currently fails on the `file:../../dacs-sdk`
link (npm arborist `edgesOut` error). Until that is fixed, these symlinks in
the root `node_modules` make the package resolve against the SDK's own
installed tree:

```
node_modules/@kynesyslabs/dacs   -> ../../dacs-sdk
node_modules/better-sqlite3      -> ../dacs-sdk/node_modules/better-sqlite3
node_modules/vitest              -> ../dacs-sdk/node_modules/vitest
node_modules/@types/better-sqlite3 -> ../../dacs-sdk/node_modules/@types/better-sqlite3
node_modules/@colony/dacs-rfq    -> ../../packages/dacs-rfq
```

The SDK tree carries `@kynesyslabs/demosdk` 4.0.18 (installed with
`npm install --no-save @kynesyslabs/demosdk@4.0.18` inside `dacs-sdk/`; its
manifest still pins `^4.0.16`). 4.0.18 adds the signed L2PS history read
(`l2ps/history`) the Step 4 transport needs. An `npm ci` or `npm install` in
`dacs-sdk/` reverts to 4.0.16; re-run the `--no-save` install afterwards.

The SDK must be built (`cd dacs-sdk && npm install && npm run build`) because
its `exports` map points at `dist/`. Node 20 or 22 only.
