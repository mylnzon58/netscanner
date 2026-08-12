#!/usr/bin/env bash
# anon.sh - instala y arranca un Tor SOCKS5 privado dentro del proyecto
# (tools/tor) para que netscanner corra anónimo, en macOS y Linux.
# Uso:      ./anon.sh            (instala + arranca; repetir solo arranca)
#           ./anon.sh --stop
#           ./anon.sh --check
# Después:  ./netscanner -c 203.0.113.0/24 --proxy socks5://127.0.0.1:9050
set -uo pipefail

SocksPort=9050
TorDir="$(cd "$(dirname "$0")" && pwd)/tools/tor"
TorExe="$TorDir/tor"
Torrc="$TorDir/torrc"
DataDir="$TorDir/data"
LogFile="$TorDir/tor.log"

stop_tor() {
  pkill -f "$TorExe" 2>/dev/null && echo "Tor detenido." || echo "Tor no estaba corriendo."
}

check_tor() {
  if curl -s -m 5 -x "socks5h://127.0.0.1:$SocksPort" https://check.torproject.org/api/ip >/dev/null 2>&1; then
    echo "TOR ACTIVO en 127.0.0.1:$SocksPort"
    return 0
  fi
  echo "TOR NO activo. Ejecuta: ./anon.sh"
  return 1
}

if [[ "${1:-}" == "--stop" ]]; then stop_tor; exit 0; fi
if [[ "${1:-}" == "--check" ]]; then check_tor; exit $?; fi

if [[ ! -x "$TorExe" ]]; then
  echo "Tor no está instalado en tools/tor. Descargando Expert Bundle oficial..."
  mkdir -p "$TorDir"

  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin)
      plat="macos-universal"
      ;;
    Linux)
      case "$arch" in
        x86_64|amd64) plat="linux-x86_64" ;;
        aarch64|arm64) plat="linux-aarch64" ;;
        *) echo "ERROR: arquitectura no soportada: $arch" >&2; exit 1 ;;
      esac
      ;;
    *) echo "ERROR: sistema no soportado: $os" >&2; exit 1 ;;
  esac

  index="https://archive.torproject.org/tor-package-archive/torbrowser/"
  html="$(curl -fsSL -m 30 "$index")"
  vers="$(printf '%s' "$html" | grep -oE 'href="[0-9]+\.[0-9]+\.[0-9]+/"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -Vr | uniq)"

  if [[ -z "$vers" ]]; then
    echo "ERROR: no se pudo leer la lista de versiones de Tor. Revisa la conexión." >&2
    exit 1
  fi

  tmp="$(mktemp /tmp/tor-expert-bundle.XXXXXX.tar.gz)"
  downloaded=0
  for ver in $(printf '%s\n' "$vers" | head -5); do
    file="tor-expert-bundle-$plat-$ver.tar.gz"
    url="$index$ver/$file"
    echo "Probando $file ..."
    if curl -fsSL -m 180 -o "$tmp" "$url" && [[ $(stat -f%z "$tmp" 2>/dev/null || stat -c%s "$tmp" 2>/dev/null || echo 0) -gt 1048576 ]]; then
      echo "Descargado: $url"
      downloaded=1
      break
    fi
    echo "  (no disponible)"
    rm -f "$tmp"
  done
  if [[ $downloaded -ne 1 ]]; then
    echo "ERROR: no se encontró un Expert Bundle disponible para $plat." >&2
    exit 1
  fi

  echo "Extrayendo..."
  tar -xzf "$tmp" -C "$TorDir"
  rm -f "$tmp"

  if [[ -d "$TorDir/tor" && ! -x "$TorExe" ]]; then
    mv "$TorDir"/tor/* "$TorDir"/ && rmdir "$TorDir/tor"
  fi

  if [[ ! -x "$TorExe" ]]; then
    echo "ERROR: el binario tor no apareció tras la extracción." >&2
    exit 1
  fi
  chmod +x "$TorExe"
  echo "Tor instalado en $TorDir"
else
  echo "Tor ya está instalado."
fi

if [[ -d "$DataDir" ]] && pgrep -f "$TorExe" >/dev/null 2>&1; then
  echo "Tor ya está corriendo."
  check_tor
  exit 0
fi

mkdir -p "$DataDir"
# geoip/geoip6: el bundle no los trae; se descargan del repo de Tor.
[[ -f "$DataDir/geoip" ]] || curl -fsSL -m 60 -o "$DataDir/geoip" "https://raw.githubusercontent.com/torproject/tor/main/src/config/geoip" || true
[[ -f "$DataDir/geoip6" ]] || curl -fsSL -m 60 -o "$DataDir/geoip6" "https://raw.githubusercontent.com/torproject/tor/main/src/config/geoip6" || true

cat > "$Torrc" <<EOF
SOCKSPort $SocksPort
DataDirectory $DataDir
Log notice file $LogFile
GeoIPFile $DataDir/geoip
GeoIPv6File $DataDir/geoip6
ExitNodes {ar}
StrictNodes 0
EOF

echo "Arrancando Tor..."
nohup "$TorExe" -f "$Torrc" >> "$LogFile" 2>&1 &
sleep 8

if check_tor; then
  echo ""
  echo "Ejemplos:"
  echo "  ./netscanner -c 203.0.113.0/24 -p 80,443,554 -w 20 -t 5000 -o anon.jsonl --proxy socks5://127.0.0.1:$SocksPort"
else
  echo "ERROR: Tor no responde en el puerto $SocksPort. Revisa $LogFile" >&2
  exit 1
fi
