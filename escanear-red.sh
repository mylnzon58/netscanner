#!/usr/bin/env bash
# escanear-red.sh - escaneo de un clic de la red local en macOS y Linux:
# detecta la red sola, la escanea con la lista completa de puertos y
# abre el panel con los resultados.
set -uo pipefail
cd "$(dirname "$0")"

if [[ ! -x ./netscanner || ! -x ./dashboard ]]; then
  echo "Compilando binarios..."
  ./build.sh || { echo "ERROR al compilar. ¿Tenés Go instalado?" >&2; exit 1; }
fi

net="$(./detectar-red.sh)" || exit 1
echo "Red local detectada: $net"

out="casa-local-$(date +%Y%m%d-%H%M%S).jsonl"
echo "Escaneando $net (80,443,8080,8000,554,21,22,5000,5001) ..."
./netscanner -c "$net" -p 80,443,8080,8000,554,21,22,5000,5001 -w 200 -t 1500 -o "$out"

echo "Abriendo el panel..."
pkill -f "dashboard -file" 2>/dev/null || true
nohup ./dashboard -file "$out" >/dev/null 2>&1 &
sleep 2
if [[ "$(uname -s)" == "Darwin" ]]; then open "http://127.0.0.1:8080"; else xdg-open "http://127.0.0.1:8080" 2>/dev/null || true; fi
echo "Panel: http://127.0.0.1:8080 (resultados en $out)"