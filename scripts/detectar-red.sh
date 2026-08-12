#!/usr/bin/env bash
# detectar-red.sh - imprime la red local (CIDR) del equipo en macOS y
# Linux. Uso:  ./detectar-red.sh
set -uo pipefail

if command -v ip >/dev/null 2>&1; then
  # Linux: la ruta con scope link es la red local.
  net="$(ip route 2>/dev/null | awk '/scope link/ {print $1; exit}')"
  if [[ -n "$net" ]]; then echo "$net"; exit 0; fi
fi

# macOS (y fallback Linux): gateway + máscara de la interfaz por defecto.
if command -v route >/dev/null 2>&1; then
  iface="$(route -n get default 2>/dev/null | awk '/interface/ {print $2}')"
  if [[ -n "$iface" ]]; then
    read -r ip maskhex <<< "$(ifconfig "$iface" 2>/dev/null | awk '/inet / {print $2, $4}')"
    if [[ -n "$ip" && -n "$maskhex" ]]; then
      # Máscara en hex (mac) a bits y red en base 2.
      mask_bits="$(printf '%08x' "$((16#$maskhex))")"
      bits=0
      while [[ "$mask_bits" == ff* ]]; do
        ((bits += 8)); mask_bits="${mask_bits#ff}"
      done
      case "$mask_bits" in
        "") ;;
        f*) ((bits += 4)) ;;
        c*) ((bits += 2)) ;;
        e*) ((bits += 3)) ;;
        8*) ((bits += 1)) ;;
      esac
      a="${ip%%.*}"; rest="${ip#*.}"; b="${rest%%.*}"; rest="${rest#*.}"; c="${rest%%.*}"; d="${rest#*.}"
      hex=$(( (a << 24) | (b << 16) | (c << 8) | d ))
      mh=$(( 16#$maskhex ))
      nethex=$(( hex & mh ))
      printf "%d.%d.%d.%d/%d\n" $(( (nethex >> 24) & 255 )) $(( (nethex >> 16) & 255 )) $(( (nethex >> 8) & 255 )) $(( nethex & 255 )) "$bits"
      exit 0
    fi
  fi
fi

echo "no se pudo detectar la red local" >&2
exit 1
