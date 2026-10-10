#!/usr/bin/env bash
# One-shot setup for a tester machine (Linux/macOS, Node 22, git, npm):
#   bash setup.sh
# Clones the DACS SDK branch this package builds on, builds it, pins demosdk
# 4.0.18 beside it, and links everything so `tsx bin/*.mts` resolves.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="$HERE/../dacs-sdk"
node -e 'const [m]=process.versions.node.split("."); if (+m<22) { console.error("Node 22+ required, found", process.version); process.exit(1) }'
# The exact DACS SDK commit this package is built and tested against (dacs-sdk
# PR #332 branch). A branch name alone is not a pin: the branch moved on
# 2026-10-10 and a fresh install against its tip broke the buyer.
SDK_COMMIT="${DACS_SDK_COMMIT:-3523cf872ff52438015531ba40b065f268e31ca4}"
SDK_REPO="https://github.com/pallytin88/dacs-sdk.git"
if [ ! -d "$SDK/.git" ]; then
  git clone --no-checkout "$SDK_REPO" "$SDK"
fi
( cd "$SDK" && git fetch -q origin "$SDK_COMMIT" && git checkout -q --detach "$SDK_COMMIT" )
actual="$(cd "$SDK" && git rev-parse HEAD)"
if [ "$actual" != "$SDK_COMMIT" ]; then echo "dacs-sdk is at $actual, expected $SDK_COMMIT" >&2; exit 1; fi
( cd "$SDK" && npm ci && npm run build )
# demosdk 4.0.18 and the tools this package needs, installed in ONE call (each
# `npm install --no-save` prunes what a previous one added), at pinned versions.
( cd "$SDK" && npm install --no-save @kynesyslabs/demosdk@4.0.18 tsx@4.21.0 better-sqlite3@12.6.2 vitest@4.1.8 @types/better-sqlite3@9.6.0 @types/node@20.19.42 )
node -e 'const v=require(process.argv[1]).version; if (v!=="4.0.18") { console.error("demosdk", v, "installed; 4.0.18 required"); process.exit(1) }' "$SDK/node_modules/@kynesyslabs/demosdk/package.json"
for m in tsx better-sqlite3 vitest @types/better-sqlite3 @types/node; do [ -e "$SDK/node_modules/$m/package.json" ] || { echo "$m missing after install" >&2; exit 1; }; done
mkdir -p "$HERE/node_modules/@kynesyslabs" "$HERE/node_modules/@types"
ln -sfn "$SDK" "$HERE/node_modules/@kynesyslabs/dacs"
ln -sfn "$SDK/node_modules/@kynesyslabs/demosdk" "$HERE/node_modules/@kynesyslabs/demosdk"
ln -sfn "$SDK/node_modules/better-sqlite3" "$HERE/node_modules/better-sqlite3"
ln -sfn "$SDK/node_modules/@types/better-sqlite3" "$HERE/node_modules/@types/better-sqlite3"
ln -sfn "$SDK/node_modules/@types/node" "$HERE/node_modules/@types/node"
ln -sfn "$SDK/node_modules/vitest" "$HERE/node_modules/vitest"
ln -sfn "$SDK/node_modules/tsx" "$HERE/node_modules/tsx"
mkdir -p "$HERE/node_modules/.bin"
ln -sfn "$SDK/node_modules/.bin/tsx" "$HERE/node_modules/.bin/tsx"
ln -sfn "$SDK/node_modules/.bin/vitest" "$HERE/node_modules/.bin/vitest"
echo "ok: run commands from $HERE with ./node_modules/.bin/tsx (or: export PATH=\"$HERE/node_modules/.bin:\$PATH\")"
