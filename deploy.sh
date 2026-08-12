#!/usr/bin/env bash
# deploy.sh - compila todo y despliega el servidor del panel en macOS y
# Linux, abriendo el navegador automáticamente.
set -euo pipefail
cd "$(dirname "$0")"

./build.sh

mkdir -p logs
if [[ -f .dashboard.pid ]] && kill -0 "$(cat .dashboard.pid)" 2>/dev/null; then
  echo "Deteniendo el panel anterior (pid $(cat .dashboard.pid)) ..."
  kill "$(cat .dashboard.pid)" 2>/dev/null || true
  sleep 1
fi

nohup ./dashboard -file casa.jsonl > logs/dashboard.log 2>&1 &
echo $! > .dashboard.pid
sleep 2

url="http://127.0.0.1:8080"
if [[ "$(uname -s)" == "Darwin" ]]; then
  open "$url"
else
  xdg-open "$url" 2>/dev/null || true
fi

echo "Panel desplegado: $url"
echo "Log: logs/dashboard.log  ·  detener: kill $(cat .dashboard.pid)"