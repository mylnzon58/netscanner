#!/usr/bin/env bash
# deploy.sh - compila todo y despliega el servidor del panel en macOS y
# Linux, abriendo el navegador automáticamente.
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/build.sh

mkdir -p data/logs
if [[ -f data/.dashboard.pid ]] && kill -0 "$(cat data/.dashboard.pid)" 2>/dev/null; then
  echo "Deteniendo el panel anterior (pid $(cat data/.dashboard.pid)) ..."
  kill "$(cat data/.dashboard.pid)" 2>/dev/null || true
  sleep 1
fi

nohup ./dashboard -file data/casa.jsonl > data/logs/dashboard.log 2>&1 &
echo $! > data/.dashboard.pid
sleep 2

url="http://127.0.0.1:8080"
if [[ "$(uname -s)" == "Darwin" ]]; then
  open "$url"
else
  xdg-open "$url" 2>/dev/null || true
fi

echo "Panel desplegado: $url"
echo "Log: data/logs/dashboard.log  ·  detener: kill $(cat data/.dashboard.pid)"