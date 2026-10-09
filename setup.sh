#!/usr/bin/env bash
# One-shot setup for a tester machine (Linux/macOS, Node 22, git, npm):
#   bash setup.sh
# Clones the DACS SDK branch this package builds on, builds it, pins demosdk
# 4.0.18 beside it, and links everything so `tsx bin/*.mts` resolves.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="$HERE/../dacs-sdk"
node -e 'const [m]=process.versions.node.split("."); if (+m<22) { console.error("Node 22+ required, found", process.version); process.exit(1) }'
if [ ! -d "$SDK/.git" ]; then
  git clone --depth 1 --branch feat/canonical-channel-message-v06 https://github.com/pallytin88/dacs-sdk.git "$SDK"
fi
( cd "$SDK" && npm ci && npm run build )
# vitest is an SDK dev dependency; tsx, better-sqlite3 and @types/better-sqlite3 are not, so some of these are always missing.
missing=""
for m in tsx better-sqlite3 vitest @types/better-sqlite3; do [ -e "$SDK/node_modules/$m/package.json" ] || missing="$missing $m"; done
( cd "$SDK" && npm install --no-save @kynesyslabs/demosdk@4.0.18 $missing )
node -e 'const v=require(process.argv[1]).version; if (v!=="4.0.18") { console.error("demosdk", v, "installed; 4.0.18 required"); process.exit(1) }' "$SDK/node_modules/@kynesyslabs/demosdk/package.json"
mkdir -p "$HERE/node_modules/@kynesyslabs" "$HERE/node_modules/@types"
ln -sfn "$SDK" "$HERE/node_modules/@kynesyslabs/dacs"
ln -sfn "$SDK/node_modules/@kynesyslabs/demosdk" "$HERE/node_modules/@kynesyslabs/demosdk"
ln -sfn "$SDK/node_modules/better-sqlite3" "$HERE/node_modules/better-sqlite3"
ln -sfn "$SDK/node_modules/@types/better-sqlite3" "$HERE/node_modules/@types/better-sqlite3"
ln -sfn "$SDK/node_modules/vitest" "$HERE/node_modules/vitest"
ln -sfn "$SDK/node_modules/tsx" "$HERE/node_modules/tsx"
mkdir -p "$HERE/node_modules/.bin"
ln -sfn "$SDK/node_modules/.bin/tsx" "$HERE/node_modules/.bin/tsx"
ln -sfn "$SDK/node_modules/.bin/vitest" "$HERE/node_modules/.bin/vitest"
echo "ok: run commands from $HERE with ./node_modules/.bin/tsx (or: export PATH=\"$HERE/node_modules/.bin:\$PATH\")"
