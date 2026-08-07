# netscanner

High-performance network discovery and indexing engine for **Windows**, written in **pure Go** (no CGO, standard `net` stack).

It streams IPv4 CIDR ranges, probes open TCP ports, fingerprints services (HTTP, FTP, WebDAV, RTSP), geolocates hosts, and persists everything to **JSON Lines** in real time. A live web panel visualizes results on a map with automatic previews of exposed content.

> ⚠️ Scan only networks you own or have explicit authorization to test. Unauthorized scanning may violate local laws.
> Guía en español: [GUIA.md](GUIA.md).

## Features

- **Fast parallel scanning** — bounded worker pool with graceful `Ctrl+C` shutdown.
- **Service fingerprinting** — HTTP banners/titles/bodies, raw banners, **anonymous FTP login probe** (`USER/PASS anonymous`), **WebDAV PROPFIND** detection, NAS/RTSP identification.
- **Geolocation** — local MaxMind `.mmdb` or online fallback (ip-api.com), plus a `enrich` tool that batch-geolocates existing results.
- **Anonymity** — every connection can be routed through a SOCKS5 proxy (Tor/VPN) with `--proxy`; bundled `anon.ps1` installs and starts a private Tor inside the project.
- **Live dashboard** — map with per-IP markers and clusters, risk scoring, findings list, exposure alerts, timeline/heatmap/content analytics, live proxied browsing of discovered hosts, automatic camera snapshots and file listings.
- **Lab console** — resolve any IP/domain (DNS), look up its ISP/city and publicly indexed ports via Shodan InternetDB, without scanning.

## Requirements

- Go 1.22+ (tested with 1.26)
- Windows (the code is cross-platform; Tor setup script is PowerShell)

## Build

```powershell
go mod tidy
go build -ldflags="-s -w" -o netscanner.exe ./cmd/scanner
go build -o dashboard.exe ./cmd/dashboard
go build -o enrich.exe ./cmd/enrich
```

Or use the Makefile: `make build` / `make test` / `make clean`.

## Usage

```powershell
netscanner.exe -c 192.168.1.0/24
netscanner.exe -c 10.0.0.0/8 -p 80,443,8080,554,21 -w 1000 -t 1500 -o out.jsonl
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--cidr` | `-c` | `192.168.1.0/24` | IPv4 range to scan |
| `--ports` | `-p` | `80,443,8080,8000,554,21,22` | comma-separated TCP ports |
| `--ftp-ports` | | `21` | ports that get the anonymous FTP probe |
| `--dav` | | `true` | PROPFIND web ports to detect WebDAV |
| `--workers` | `-w` | `500` | max concurrent connections |
| `--timeout` | `-t` | `2000` | connection timeout (ms) |
| `--max-body` | | `16` | max HTTP body captured per web port (KiB) |
| `--geoip` | `-g` | `./GeoLite2-City.mmdb` | local MaxMind database |
| `--output` | `-o` | `results.jsonl` | JSONL output file |
| `--stats` | | | live progress file for the dashboard |
| `--proxy` | | | SOCKS5 proxy for all connections, e.g. `socks5://127.0.0.1:9050` |
| `--user-agent` | | browser UA | HTTP User-Agent sent by probes |

### Anonymous scanning (Tor)

```powershell
# one-time: downloads the official Tor Expert Bundle into tools\tor and starts it
.\anon.ps1

# now every connection goes through Tor
.\netscanner.exe -c 203.0.113.0/22 -p 80,443,554 -w 20 -t 5000 -o anon.jsonl --proxy socks5://127.0.0.1:9050
```

The dashboard can use the same proxy for its live browser and FTP listing:
`.\dashboard.exe -file anon.jsonl --proxy socks5://127.0.0.1:9050`.

Notes:
- The **MAC address never leaves your LAN**; remote hosts only ever see your public IP (or the proxy's).
- Probes send a neutral browser User-Agent, not a scanner fingerprint.
- Tor is intentionally slow: for large scans use a VPN instead of `--proxy`.

## Dashboard

```powershell
# terminal 1: the scan (as usual)
.\netscanner.exe -c 192.168.1.0/24 -o results.jsonl --stats stats.json

# terminal 2: the panel
.\dashboard.exe -file results.jsonl -stats stats.json
```

Open `http://127.0.0.1:8080`. The panel:

- streams results in real time over SSE (it also works with pre-existing JSONL files);
- shows a **map** with one marker per geolocated IP, colored ring per ISP range, type icons and clusters; clicking a marker opens the device card;
- **previews automatically**: camera snapshots (`/snapshot.cgi`, `/image.jpg`, …), thumbnails of images in exposed listings, and a button to **list anonymous FTP directories** in real time;
- provides a **live browser** (`/proxy`) to navigate any discovered host inline;
- computes an **exposure risk score** per device (file listings, cameras, logins, FTP, WebDAV, port sprawl) with high/medium/low badges;
- includes the **lab console** for DNS/ISP/Shodan lookups of any IP or domain (no scanning involved).

### Geolocating results

```powershell
.\enrich.exe -in results.jsonl            # writes results_geo.jsonl
.\dashboard.exe -file results_geo.jsonl   # map now shows city coordinates
```

`scan-isp.ps1` automates the whole pipeline (scan ISP ranges → geolocate → reload dashboard), optionally through a proxy: `.\scan-isp.ps1 -Proxy socks5://127.0.0.1:9050`.

## Output (JSONL)

One JSON object per open port:

```json
{"timestamp":"2026-01-01T00:00:00Z","ip":"8.8.8.8","port":21,"status":"open","banner":{"http":false,"ftp_auth":"anonymous","ftp_banner":"220 FTP ready"},"geo":{"label":"Public","country":"United States","city":"Mountain View","latitude":37.42,"longitude":-122.08,"isp":"Example ISP","asn":"AS15169"}}
```

Optional fields (omitted when empty): `ftp_auth`, `ftp_banner`, `dav`, `dav_body`, `geo.isp`, `geo.asn`, `geo.org`.

## Tests

```powershell
go vet ./...
go test ./...
```

The suite includes end-to-end probes against fake FTP/WebDAV/SOCKS5 servers (`pkg/banner`, `pkg/socks`).

## Structure

```
cmd/scanner/    CLI entrypoint, flags, graceful shutdown
cmd/dashboard/  live web panel (embedded index.html) + proxy + lab endpoints
cmd/enrich/     batch geolocation of existing JSONL results
pkg/config/     flag parsing and validation
pkg/engine/     streaming IP generator + worker pool + probing pipeline
pkg/banner/     HTTP/raw/FTP/WebDAV probes
pkg/geo/        MaxMind .mmdb + online geolocation (ip-api)
pkg/socks/      minimal SOCKS5 client (no-auth and user/pass)
pkg/exporter/   async JSONL writer
pkg/live/       SSE hub + file tailer for the dashboard
```

See `SPEC.md` for the technical specification.
