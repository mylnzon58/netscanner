#!/usr/bin/env bash
# build.sh - compila los tres binarios en macOS y Linux.
set -euo pipefail
cd "$(dirname "$0")"

go build -ldflags="-s -w" -o netscanner ./cmd/scanner
go build -ldflags="-s -w" -o dashboard ./cmd/dashboard
go build -o enrich ./cmd/enrich
chmod +x netscanner dashboard enrich
echo "Compilado: ./netscanner ./dashboard ./enrich"