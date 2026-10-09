# Running a private RFQ test against the SuperColony node

What you get: a DACS-3 private negotiation whose packets travel as encrypted
L2PS transactions on our node, with the listing, both vet records, the
commitment and the payment on the public Demos testnet. Every step returns a
hash you can check: subnet rows through the signed history read, public steps
on https://explorer.demos.sh.

## What we send you (over a private channel, never in an issue)

| Item | Value |
| --- | --- |
| Host node RPC | `https://dacs-node.tailfa48ff.ts.net` (operated by SuperColony; a one-validator dev chain) |
| Your subnet | `L2PS_UID` plus the key and IV files; one subnet per tester, our deals are not in it |
| Seller | `did:demos:agent:706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1`; listing `dacs1:did%3Ademos%3Aagent%3A706b89f5…:rfq-showcase-muzmqquv:v1` (full value in the run section) |
| Local-chain funds | we transfer DEM on our chain to your wallet address (`bin/fund-local.mts`) |
| SDK | `@kynesyslabs/demosdk` 4.0.18 and `@kynesyslabs/dacs` from the PR #332 branch, both vendored in this package |

What we need from you: the `did:demos:agent:<64 hex>` claim of each test
wallet (the address is the Ed25519 public key; never send a mnemonic), and
public-testnet DEM on those wallets. The faucet at
`POST https://faucetbackend.demos.network/api/request` with `{"address": "0x…"}`
gives 2,400 DEM per request. Anchors cost 2 DEM each; the showcase deal pays 9.5 DEM.

## Install

Unpack the bundle, then `bash setup.sh` inside it (Node 22, git, npm). It
clones the DACS SDK branch, builds it, pins demosdk 4.0.18 and links the
package. Run every command below from the package directory with
`./node_modules/.bin/tsx` or put that directory on your PATH.

## Registering (the automated path)

You do not need the subnet details or local funds in advance. With the env
file below minus the `L2PS_*` lines, run:

```bash
REGISTER_URL=https://dacs-node.tailfa48ff.ts.net/colony-rfq/v0/register tsx bin/register.mts
```

It generates an X25519 key under your data root, signs a registration with
your wallet (the claim is the key, so nothing else identifies you). Approval is
automatic for any authenticated request on this node and provisions a subnet only you and the
seller share, funds your wallet on the host chain, and seals the credential to
your X25519 key; `register.mts` decrypts it into
`<root>/buyer/subnet/credential.json` (mode 0600). `TRANSPORT=l2ps tsx bin/buyer.mts run`
then picks it up. Your mnemonic, your X25519 private key and the subnet key
never leave your machine in the clear.

Verified end to end on 2026-10-08: a fresh wallet registered, was approved in
under five seconds (subnet `rfq_a6c10f11d491_9f0425`, 100 host-chain DEM), and
settled job `01M4EYT54T94XZK1RVZX7M7SNN` with the commitment at
`stor-d9dca7cec4180cf0861a7ea0dabb41c46e4e1fc6` and payment
`3fbdcaaf…` on the public testnet.

## Run

```bash
# wallets.env (chmod 600), outside any repository
DEMOS_RPC=https://demosnode.discus.sh/        # public testnet: anchors + payment
BUYER_WALLET="<your mnemonic>"
BUYER_DID=did:demos:agent:<your 64 hex>
SELLER_DID=did:demos:agent:706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1
DACS_RFQ_ROOT=/absolute/path/for/state
L2PS_RPC=<host node RPC we gave you>
L2PS_UID=<your subnet uid>
L2PS_KEY_FILE=/path/to/private_key.txt
L2PS_IV_FILE=/path/to/iv.txt
MCP_TOKEN=<32+ random chars>
BUYER_CEILING_DEM=9.8

TRANSPORT=l2ps DACS_RFQ_ENV=/path/to/wallets.env \
  LISTING_REF='dacs1:did%3Ademos%3Aagent%3A706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1:rfq-showcase-muzmqquv:v1' \
  tsx bin/buyer.mts run           # MCP on :47110, viewer on :47120
MCP_TOKEN=… tsx bin/drive.mts     # scripted model: offer 9, counter 9.5, settle
```

Or point your own MCP client at `http://127.0.0.1:47110/mcp` with the bearer
token and call `find_listing`, `open_negotiation`, `make_offer`,
`counter_offer`, `accept`, `get_negotiation_state`, `get_receipts`.

## What to report back

`get_receipts` plus the viewer's `/demo/procurement/{jobId}` event stream
(every step with its tx or anchor ref) and `/demo/subnet` (your subnet rows,
metadata only). Open an issue on this package with those and anything that
surprised you: https://github.com/pallytin88/dacs-rfq/issues

## Rules

Testnet only, dedicated wallets, nothing of real value. No mnemonic, subnet
key or bearer token in any shared text. What is public: the listing, both
vet records, the commitment anchor and the payment, whose amount is the agreed
price. What stays in the subnet: the offers and counters, i.e. how that price
was reached. The public records never carry an offer, counter or turn price,
and that property is the thing under test. The host chain behind the subnet is a
one-validator dev chain, so its finality is only as trustworthy as our node;
the public testnet is where the money moves. Node bugs come to us first, since
the node runs an upstream branch with one local patch (history returns
decrypted content to the authenticated member).
