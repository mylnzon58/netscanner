# SPEC — netscanner

Motor de descubrimiento e indexación masiva de red (MVP) para Windows, escrito en Go puro (sin CGO) sobre el stack TCP de la librería estándar `net`.

## 1. Resumen

`netscanner` recorre un rango CIDR IPv4, sondea los puertos TCP configurados con un worker pool acotado, extrae banners de servicio (probe HTTP para puertos web, banner de bienvenida para el resto), enriquece cada resultado con geolocalización local (MaxMind GeoLite2 `.mmdb`) y persiste todo de forma continua en formato JSON Lines (JSONL). El proceso soporta apagado controlado (*graceful shutdown*) ante `Ctrl+C`.

## 2. Arquitectura

```
cmd/scanner (main)
   │  flags → pkg/config
   │  contexto cancelable (os.Interrupt / SIGTERM)
   ▼
pkg/engine ── generador de IPs streaming (canal, sin cargar RAM)
   │            worker pool acotado por --workers
   │            net.DialTimeout TCP (puerto abierto →)
   ▼
pkg/banner ── puertos web (80,443,8080,8000): GET / HTTP/1.1 + parseo de
   │          status code, Server: y <title>…</title>
   │          otros puertos (21,22,554): lectura del banner raw (≤ 4KB)
   ▼
pkg/geo ──── RFC 1918 → "Internal/Private"; públicas → consulta local
   │          GeoLite2 (.mmdb) → País, Ciudad, Lat, Lon; sin DB → "Unknown"
   ▼
pkg/exporter ─ canal asíncrono + goroutine I/O única → data/*.jsonl (local, gitignored)
```

### Flujo de datos

1. `config.Parse` valida las banderas y produce `Options`.
2. `engine.Run(ctx, opts, geoDB, out)`:
   - un goroutine generador emite `(ip, puerto)` en un canal `jobs` (las IPs se generan incrementalmente desde el CIDR; nunca se materializan en RAM);
   - `N = workers` goroutines consumen `jobs`, ejecutan el dial TCP con timeout y, si el puerto está abierto, obtienen banner + geo y envían el `Result` al canal `out`;
   - un `WaitGroup` espera a que todos los workers terminen antes de retornar.
3. `exporter.Writer` drena `out` en una única goroutine de I/O y escribe JSONL con búfer de 64 KiB.
4. Al finalizar (rango completo o cancelación), `main` cierra el exporter: flush del búfer y cierre limpio del archivo.

## 3. Módulos

### 3.1 `pkg/config`

Bandera | Corta | Default | Descripción
---|---|---|---
`--cidr` | `-c` | `192.168.1.0/24` | Red IPv4 a escanear (p.ej. `10.0.0.0/8`).
`--ports` | `-p` | `80,443,8080,8000,554,21,22` | Puertos TCP separados por coma (1–65535, sin duplicados).
`--workers` | `-w` | `500` | Conexiones concurrentes máximas (límite del pool).
`--timeout` | `-t` | `2000` | Timeout de conexión en milisegundos.
`--geoip` | `-g` | `./GeoLite2-City.mmdb` | Ruta a la base MaxMind GeoLite2 City.
`--output` | `-o` | `results.jsonl` | Archivo de salida JSONL (el panel y los scripts usan `data/*.jsonl`, que está gitignored).

Validaciones: CIDR IPv4 obligatorio, puertos únicos y en rango, workers ≥ 1, timeout ≥ 10 ms. Con `-h` se imprime la ayuda. Solo se soporta IPv4 en el MVP (los CIDR IPv6 se rechazan con un error explícito).

### 3.2 `pkg/engine`

- `HostCount(*net.IPNet) (uint64, error)`: hosts utilizables; para `/31` y `/32` se cuentan todas las direcciones, para máscaras mayores se excluyen red y broadcast.
- `IPs(ctx, *net.IPNet) <-chan net.IP`: generador streaming por canal (búfer 256), cancelable por contexto.
- `Run(ctx, opts, geoDB, out) (*Stats, error)`: orquesta el pool. El límite de concurrencia es exactamente `--workers` (canal `jobs` acotado + pool de goroutines): en Windows esto evita agotar los descriptores de sockets. Cada dial está acotado por `--timeout`.
- `Stats`: contadores atómicos `Attempts`, `Open`, `Timeout`, `Errored` (leídos por `Snapshot()`).

### 3.3 `pkg/banner`

- `IsWebPort(int) bool`: `{80, 443, 8080, 8000}`.
- `Probe(conn, ip, port) Info`: para puertos web envía `GET / HTTP/1.1\r\nHost: <ip>\r\nUser-Agent: NetScanner/1.0\r\nConnection: close\r\n\r\n` y parsea la respuesta inicial (máx. 4 KiB): código de estado HTTP, encabezado `Server:` (case-insensitive) y contenido de `<title>…</title>`. Para el resto lee el banner de bienvenida directo del socket.
- El texto crudo se sanitiza (se eliminan bytes de control, se conserva UTF-8) y se trunca a 4 KiB.
- En `443` (TLS) el probe se degrada de forma natural: la respuesta binaria no produce status code y queda solo el `raw`.

### 3.4 `pkg/geo`

- `Open(path) (*GeoDB, error)`: abre el `.mmdb` con `geoip2-golang`. Si el archivo no existe, el llamador usa `Unavailable()` y el escaneo continúa marcando todo como `Unknown`.
- `Lookup(net.IP) Location`: IP privada (RFC 1918 + loopback + link-local) → `Internal/Private`; pública → consulta al `.mmdb` local (País, Ciudad, Latitud, Longitud); fallo de consulta o sin DB → `Unknown`.

### 3.5 `pkg/exporter`

- `NewWriter(path, buffer) (*Writer, error)`: abre el archivo en modo append, inicia la goroutine I/O dedicada y devuelve el canal `Results()`.
- Cada `Result` se serializa como una línea JSON (`json.Encoder`, que añade `\n`).
- `Close()`: cierra el canal, espera a la goroutine, hace flush del búfer y cierra el archivo. Reporta el primer error de I/O.

### 3.6 `cmd/scanner`

- `signal.NotifyContext(os.Interrupt, syscall.SIGTERM)` crea un contexto cancelable.
- Ante `Ctrl+C`: se cancela el contexto → el generador deja de emitir trabajos, los workers terminan los dials en vuelo (acotados por `--timeout`), el `WaitGroup` espera, `exporter.Close()` vacía el búfer a disco y se imprime el resumen final.
- Avisa por stderr si el rango implica más de un millón de pares `(ip, puerto)`.

## 4. Esquema JSONL

```json
{"timestamp":"2026-01-01T00:00:00Z","ip":"8.8.8.8","port":80,"status":"open","banner":{"http":true,"status_code":200,"server":"nginx/1.24.0","title":"Example Domain","raw":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n..."},"geo":{"label":"Public","country":"United States","city":"Mountain View","latitude":37.42,"longitude":-122.08}}
```

| Campo | Tipo | Descripción |
|---|---|---|
| `timestamp` | string (RFC3339) | Momento UTC del hallazgo |
| `ip` | string | Dirección del host |
| `port` | int | Puerto TCP abierto |
| `status` | string | Siempre `"open"` (solo se registran puertos abiertos) |
| `banner.http` | bool | True si se aplicó el probe HTTP |
| `banner.status_code` | int | Código HTTP (0 si no aplica) |
| `banner.server` | string | Encabezado `Server:` |
| `banner.title` | string | Contenido de `<title>` |
| `banner.raw` | string | Respuesta cruda inicial (≤ 4 KiB) |
| `geo.label` | string | `Internal/Private` \| `Public` \| `Unknown` |
| `geo.country` / `geo.city` | string | País y ciudad (si hay DB y es pública) |
| `geo.latitude` / `geo.longitude` | float | Coordenadas (si hay DB y es pública) |

## 5. Concurrencia y límites

- Generación de IPs por canal: consumo de memoria constante, independiente del tamaño del rango (`0.0.0.0/0` no se materializa).
- Concurrencia de sockets limitada estrictamente a `--workers` (semáforo/canal acotado), evitando el agotamiento de descriptores en Windows.
- Toda lectura/escritura de red tiene deadline = `--timeout`.
- La escritura a disco es serializada en una única goroutine; el rendimiento queda desacoplado del I/O del archivo.

## 6. Limitaciones del MVP

- Solo IPv4 y TCP (sin UDP, ICMP ni IPv6).
- `443` se sondea en texto plano: el tráfico TLS no se decodifica (queda el `raw` binario sanitizado).
- Banners limitados a 4 KiB.
- Geolocalización 100 % local: requiere descargar `GeoLite2-City.mmdb` (gratis con cuenta MaxMind); sin el archivo el escaneo funciona igual con `geo.label = "Unknown"`.

## 7. Uso ético y legal

Escanea únicamente redes propias o con autorización explícita. El escaneo no autorizado puede violar leyes locales y términos de servicio de terceros. El operador es responsable del uso.

## 8. Privacidad del repositorio

- El repo público contiene **solo código**: `cmd/`, `pkg/`, `scripts/`, `docs/`, `Makefile`, workflows y raíz. Todo dato de escaneos (`.jsonl`), progreso (`.stats`), `geo-cache.json`, `comments.json` y `ai_key.json` vive en `data/`, excluido por `.gitignore` (`data/`, `*.jsonl`, `*.stats`, …).
- Los ejemplos del README/GUIA y la documentación usan exclusivamente IPs de documentación (RFC 5737) y ASN ficticios (`AS64500`).
- El job de CI `privacy` falla si `git ls-files` contiene archivos de datos fuera de los directorios permitidos (`^(cmd|pkg|scripts|docs|\.github|README\.md|LICENSE|Makefile|go\.mod|go\.sum|\.gitignore)$`).

## 9. Panel: histórico, reset y pausa (dashboard)

- `GET /histories` — lista los `data/*.jsonl` disponibles (nombre, tamaño, fecha) para el selector del hero.
- `POST /history/load` — reabre un histórico guardado sin reescanear: valida el nombre (sin `..` ni subdirectorios), rechaza con 409 si hay un escaneo en curso, hace switch del tailer al archivo, resetea el hub (`ResetAll`) y reenvía todos los registros por SSE (`event: reset` + snapshot).
- Al lanzar un escaneo nuevo, `/scan` hace `hub.ResetAll()` y guarda el resultado en un archivo datado `data/<prefijo>-YYYYMMDD-HHMMSS.jsonl` (nunca pisa históricos).
- Preflight `checkReachability`: si el objetivo es público o `asn:`, se intenta obtener la IP/geo propia (`geo.LookupMyIP`); si falla (sin conexión), `/scan` responde 503 con "sin conexión a internet (no se pudo obtener tu IP/geo…)" y el escaneo se pausa en vez de sondear a ciegas.
- SSE: los eventos del hub se envían como `event: <nombre>` + `data: <JSON>`; el cliente limpia mapas/fichas al recibir `reset`.
