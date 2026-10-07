#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node -e 'if(Number(process.versions.node.split(".")[0])<24)process.exit(1)' || { echo 'Install Node.js 24 or newer first.'; exit 1; }
npm ci --no-audit --no-fund
npm run build
npm start
