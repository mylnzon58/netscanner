# Arquitectura de `netscanner`

Documentación técnica completa del código, de extremo a extremo. Está pensada
para que cualquiera que lea el repositorio entienda **qué hace cada archivo,
cómo fluye la información y cómo se comportan las decisiones de diseño**.

> Convención de lectura: los nombres de tipo o función van en `código`; las
> referencias a archivos usan `ruta/archivo.go:línea`. Las rutas son relativas
> a la raíz del repo.

---

## 0. Glosario mínimo

| Término | Significado en este proyecto |
|---------|------------------------------|
| **Escaneo** | Sondeo TCP de un rango de IPs en busca de puertos abiertos. |
| **Banner** | Huella del servicio tras un puerto abierto (HTTP, FTP, crudo…). |
| **Resultado** | Un par `(ip, puerto)` abierto, serializado como 1 línea JSONL. |
| **JSONL** | *JSON Lines*: un objeto JSON por línea, sin corchetes de array. |
| **Hub** | Estructura en memoria que guarda los resultados y los emite en vivo. |
| **Tailer** | Sigue un archivo `.jsonl` y entrega solo las líneas nuevas. |
| **SSE** | *Server-Sent Events*: el panel recibe resultados por HTTP en streaming. |
| **CDN** | Red de distribución de contenido (Cloudflare, Google, AWS…). |
| **ASN** | *Autonomous System Number*: el identificador del bloque de un ISP. |

---

## 1. Estructura del repositorio

```
cmd/
  scanner/    netscanner.exe  — CLI del motor de escaneo
  dashboard/  dashboard.exe    — panel web en vivo (index.html embebido)
  enrich/     enrich.exe      — geolocalización en lote de resultados existentes
pkg/
  config/     parseo y validación de flags (-c, -p, -w, -t, -o, --proxy…)
  engine/     generador de IPs en streaming + pool de workers + sondeo
  banner/     sondeos HTTP/crudo/FTP/WebDAV + detección de tecnologías
  geo/        GeoLite2 (.mmdb) + ip-api online + clasificación de CDN + ASN
  socks/      cliente SOCKS5 mínimo (RFC 1928/1929) para anonimato (Tor)
  exporter/   escritor JSONL asíncrono (1 goroutine de I/O)
  live/       Hub (historial + difusión) y Tailer (seguimiento de archivo)
scripts/      deploy/build/anon/detectar-red/escanear-red/scan-isp (Win+Linux)
docs/         GUIA.md (uso), SPEC.md (especificación), ARQUITECTURA.md (este)
data/         SOLO local: resultados, caché geo, notas, claves IA, logs
tools/        SOLO local: bundle Tor descargado por anon.ps1
```

**Regla de oro (privacidad):** el repo es solo código. `data/` y `tools/` están
en `.gitignore`. Nunca se suben IPs, cuentas ni webs reales. Un job de CI
(`privacy`) falla si aparece un archivo de datos fuera de donde corresponde.

---

## 2. Flujo general (de extremo a extremo)

```
 USUARIO
   │  netscanner.exe -c <rango> -p <puertos> -o data/X.jsonl
   ▼
cmd/scanner/main.go
   │ 1) config.Parse()            → Options validadas
   │ 2) resolveTarget() por cada  → CIDR /32 (red, IP o dominio)
   │ 3) geo.Open()                → base .mmdb (o Unavailable)
   │ 4) exporter.NewWriter()      → canal de resultados
   │ 5) engine.Run() en loop      → sondea y emite Result por el canal
   ▼
pkg/engine  (IPs streaming → pool de workers → dial TCP → banner.Probe → geo.Lookup)
   │  cada Result  ──────────────► exporter.Writer (goroutine I/O)
   ▼                                  │
                              data/X.jsonl  (1 objeto JSON por línea)
                                        │
                            pkg/live.Tailer  (lee solo lo nuevo)
                                        ▼
                            pkg/live.Hub  (historial en memoria + difusión)
                                        ▼
cmd/dashboard  /events (SSE)  ───────►  navegador  (mapa, fichas, timeline)
```

El `dashboard` NO escanea: solo **observa** el `.jsonl` y lo transmite al
navegador. El mismo `.jsonl` sirve de fuente única de verdad.

---

## 3. `cmd/scanner/main.go` — punto de entrada del motor

Responsabilidades:

1. **Parseo de flags** → `config.Parse` (cmd/scanner/main.go:53).
2. **Resolución de objetivos** → `resolveTarget` (cmd/scanner/main.go:27):
   - Si ya es CIDR válido, lo deja igual.
   - Si es `http(s)://host` o `host`, le quita el path y resuelve la primera
     IPv4 con `net.LookupHost` → lo convierte en `/32`.
   - Múltiples objetivos separados por `,`, `;`, o espacio
     (cmd/scanner/main.go:65, `strings.FieldsFunc`).
3. **Cierre prolijo** → `signal.NotifyContext` con `SIGINT`/`SIGTERM`
   (cmd/scanner/main.go:78). Al cancelar, el generador deja de emitir y los
   dials en vuelo terminan por su `timeout`.
4. **Aviso de tamaño** → si el total de pares `(ip,puerto)` supera 1.000.000,
   avisa por stderr (cmd/scanner/main.go:89).
5. **Anonimato** → si hay `--proxy`, construye un `socks.Dialer` y lo inyecta
   en `engine.Dialer.Dial` y `banner.DialTCP` (cmd/scanner/main.go:97). Así
   **todas** las conexiones (incluido FTP) salen por el proxy. Sin proxy,
   avisa que usa la IP directa.
6. **Geo** → `geo.Open(opts.GeoIPPath)`; si falla, `geo.Unavailable()` (la geo
   queda `Unknown` pero el escaneo sigue).
7. **Ejecución** → precarga `TotalJob` (cmd/scanner/main.go:132) para que el
   progreso muestre un solo total desde el inicio, y corre `engine.Run` por
   cada CIDR compartiendo `Stats` (cmd/scanner/main.go:142).

Salida final por stderr: intentos, abiertos, timeouts, errores y duración.

---

## 4. `pkg/config` — flags y validación

`Parse` (pkg/config/config.go:51) define los flags (con alias corto y largo):

| Flag | Alias | Default | Qué controla |
|------|-------|---------|--------------|
| `--cidr` | `-c` | `192.168.1.0/24` | Objetivo (red/IP/dominio). |
| `--ports` | `-p` | `80,443,8080,8000,554,21,22` | Puertos TCP. |
| `--workers` | `-w` | `500` | Conexiones simultáneas. |
| `--timeout` | `-t` | `2000` ms | Timeout de cada dial. |
| `--geoip` | `-g` | `./GeoLite2-City.mmdb` | Base MaxMind. |
| `--output` | `-o` | `results.jsonl` | Archivo JSONL. |
| `--max-body` | — | `16` KiB | Cuerpo HTTP capturado. |
| `--stats` | — | `""` | Progreso en vivo (JSON). |
| `--ftp-ports` | — | `21` | Puertos con sondeo FTP anónimo. |
| `--dav` | — | `true` | Sondear WebDAV (PROPFIND). |
| `--proxy` | — | `""` | Proxy SOCKS5 (`socks5://host:puerto`). |
| `--user-agent` | — | Chrome/Windows neutro | User-Agent de los sondeos. |

`validate` (pkg/config/config.go:94):
- Rechaza IPv6 en `--cidr` (solo IPv4 en el MVP).
- `parsePorts` (pkg/config/config.go:137) separa, valida 1–65535, **elimina
  duplicados** y ordena.
- Workers en `[1, 65536]`; timeout en `[10 ms, 5 min]`; max-body en `[0, 512]` KiB.

---

## 5. `pkg/engine` — el corazón del escaneo

### 5.1 Tipos

- `job{ip, port}` — una unidad de sondeo.
- `Stats` (pkg/engine/engine.go:32): contadores atómicos (`Attempts`, `Open`,
  `Timeout`, `Errored`) + `TotalJob` (para el progreso global) + muestra
  circular de las últimas 48 IPs (`Seen`/`Sample`, `sampleN = 48`).
- `Snapshot` (pkg/engine/engine.go:67): copia plana de los contadores.

### 5.2 `HostCount` (pkg/engine/engine.go:87)

Cuenta direcciones **usables**: `/31` y `/32` usan todas; el resto resta red y
broadcast (`count - 2`). Rechaza IPv6 (`bits != 32`).

### 5.3 `IPs` (pkg/engine/engine.go:102) — generación en streaming

Devuelve `<-chan net.IP` con **buffer 256**. Recorre el rango convertido a
`uint32` y envía cada IP; se corta en `ctx.Done()`. Esto es clave: **el rango
nunca se materializa en RAM** (un `/0` no explota la memoria), y el cierre es
inmediato porque el generador deja de producir.

### 5.4 `Run` (pkg/engine/engine.go:142)

1. Parsea el CIDR y calcula `hosts × len(ports)` = `jobCount`.
2. Ajusta `workers` a `min(opts.Workers, jobCount)` (nunca más workers que
   trabajos).
3. Si `opts.StatsFile != ""`, arranca una goroutine que cada 500 ms escribe el
   progreso (`writeStats`) para el panel.
4. **Productor**: un goroutine lee `IPs` y, para cada IP, empuja un `job` por
   puerto al canal `jobs` (buffer = workers).
5. **Consumidores**: `workers` goroutines que, por cada `job`:
   - `stats.Attempts.Add(1)` + `stats.Seen(ip)`.
   - `dial` (pkg/engine/engine.go:270): usa `engine.Dialer` si está seteado
     (proxy) o `net.DialTimeout`. Clasifica el error: timeout vs. otro.
   - Si abre → `stats.Open.Add(1)` → `collect`.
6. `wg.Wait()` espera a todos; cierra el archivo de stats.

### 5.5 `collect` (pkg/engine/engine.go:283)

Para cada conexión abierta:
- `banner.Probe` (o `ProbeFTP` si el puerto está en `--ftp-ports`).
- Si `--dav` y es puerto web, hace un segundo dial y `banner.ProbeDAV`.
- `db.Lookup(ip)` → ciudad/coordenadas (GeoLite2 local).
- Arma `exporter.Result` y lo envía por `out`. El campo `Banner.CDN` se llena
  con `geo.ClassifyIP(ip)` (tabla local de rangos CDN).

`dial` y `Dialer` (pkg/engine/engine.go:266) son variables globales que el CLI
sobrescribe para enrutar por proxy. **No hay estado global compartido salvo
este dialer**, que es seteado una sola vez al arrancar.

---

## 6. `pkg/banner` — huellas de servicio

`Probe` (pkg/banner/banner.go:68):
- Puertos web (`webPorts`: 80, 443, 8080, 8000, 5000, 5001, 8081, 9000) →
  `probeHTTP`: manda `GET / HTTP/1.1` con User-Agent neutro y parsea
  status, `Server:`, `<title>`, `Location` y headers relevantes.
- Resto → `readRaw`: lee el banner de bienvenida (hasta `MaxRead = 4096` bytes).

Detalles de diseño:
- `UserAgent` (pkg/banner/banner.go:22) es neutro a propósito: los servidores
  no deducen que es un escáner.
- `DialTCP` (pkg/banner/banner.go:26) es reemplazable para mandar por proxy;
  lo usa también `FTPList`.
- `ProbeFTP` (pkg/banner/banner.go:105): lee el banner y prueba login
  anónimo (`USER/PASS anonymous`) → `Auth = "anonymous" | "denied"`.
- `ProbeDAV` (pkg/banner/banner.go:141): manda `PROPFIND /` y acepta si la
  respuesta es `207 Multi-Status`.
- `FTPList` (pkg/banner/banner.go:192): sesión FTP anónima + `PASV` + `LIST`,
  devuelve los nombres de archivo del directorio (usa `pasvRe` para la IP/puerto
  del canal de datos).
- `sanitize` (pkg/banner/banner.go:178): borra bytes de control, conserva UTF-8
  imprimible. Nada de esto se manda a ningún lado externo salvo el dial del
  sondeo.
- `detectTech` (pkg/banner/banner.go:333): marca tecnologías (nginx, WordPress,
  Cloudflare, jQuery…) mirando **solo** headers y HTML ya capturados — sin
  peticiones extra.

---

## 7. `pkg/geo` — geolocalización

Tres fuentes, jerarquía clara:

1. **Local (GeoLite2 `.mmdb`)** — `geo.go`:
   - `Open`/`Unavailable` cargan (o no) la base MaxMind.
   - `Lookup` (pkg/geo/geo.go:52): IP privada → `Internal/Private` (sin red);
     pública → consulta `.mmdb` → ciudad/país/lat/lon; sin base → `Unknown`.
   - `IsPrivate` (pkg/geo/geo.go:79): RFC 1918 + loopback + link-local.
2. **Online (ip-api.com, gratis)** — `online.go`:
   - `LookupOnline` (pkg/geo/online.go:67): endpoint **batch** (hasta 100 IPs
     por request, 1 request = 1 del límite de 45/min; pausa de 1,5 s entre
     lotes). Devuelve un mapa `ip → OnlineInfo` (solo `status:"success"` con
     coords). Es la fuente **más precisa** para residencial.
   - `LookupMyIP` (pkg/geo/online.go:98): resuelve la IP pública propia (para
     el pin 🏠 "Mi conexión" del panel).
   - `SampleBy24` (pkg/geo/online.go:44): deja una IP representativa por
     bloque `/24` (estable y ordenada) para no repetir consultas.
   - `ASNRoutes` (pkg/geo/online.go:120): dado un ASN, devuelve sus prefijos
     IPv4 anunciados vía RIPEstat (RIPE) y, si falla, BGPView. **Tope actual:
     128 prefijos** (ver limitación en la sección 12).
3. **Clasificación CDN** — `cdn.go`:
   - `ClassifyIP` (pkg/geo/cdn.go:93): tabla local de rangos (Cloudflare,
     Google, AWS, Akamai, Fastly, Azure, Meta, OVH, DigitalOcean, Vercel,
     Netlify, GitHub Pages, Hostinger). No hace red: es una tabla estática en
     memoria (`sync.Once`).

**Precisión honesta:** tanto `.mmdb` como ip-api son a **nivel de ciudad**. El
panel prioriza ip-api cuando la tiene (es más precisa para residencial); el
jitter de los marcadores es de ~90–350 m (solo para separar puntos del mismo
`/24`). Nunca es dirección de calle.

---

## 8. `pkg/exporter` — salida JSONL

`Result` (pkg/exporter/exporter.go:47) es el esquema en disco:

```json
{
  "timestamp": "2026-01-01T00:00:00Z",
  "ip": "8.8.8.8",
  "port": 80,
  "status": "open",
  "banner": {
    "http": true, "status_code": 200, "server": "nginx/1.24.0",
    "title": "Example Domain", "raw": "…", "tech": ["nginx"],
    "cdn": "", "ftp_auth": "", "dav": false
  },
  "geo": { "label": "Public", "country": "United States", "city": "Ashburn",
           "latitude": 39.03, "longitude": -77.5 }
}
```

Campos opcionales (`omitempty`): `body`, `headers`, `redirect`, `cdn`,
`ftp_auth`, `ftp_banner`, `dav`, `dav_body`, y en geo `isp`/`asn`/`org` (solo
tras enriquecimiento online).

`Writer` (pkg/exporter/exporter.go:58):
- `NewWriter` abre el archivo en modo **append** y arranca `loop` (una sola
  goroutine de I/O).
- `Results()` devuelve el canal por donde el engine empuja.
- `Close()` cierra el canal, espera a la goroutine, hace flush y cierra el
  archivo (pkg/exporter/exporter.go:102). **El I/O de disco queda desacoplado
  del sondeo**, así el rendimiento no depende del disco.

---

## 9. `cmd/dashboard` — panel web en vivo

### 9.1 `main.go`

- `-file` default `data/results.jsonl`; `-addr` `127.0.0.1:8080`; `-limit` 5000
  registros en memoria; `-poll` 500 ms; `-stats` progreso; `-proxy` SOCKS5
  (para el navegador `/proxy` y `/ftplist`).
- Crea el `dataDir` y fija rutas locales: `geo-cache.json`, `comments.json`,
  `ai_key.json` (cmd/dashboard/main.go:107). Todo junto a los resultados.
- Si el `-file` está vacío/inexistente, abre el `.jsonl` más reciente del
  directorio (`newestJSONL`, cmd/dashboard/main.go:190).
- `openTailerRetry` (cmd/dashboard/main.go:213) reintenta hasta que el archivo
  aparece (el escáner lo crea al arrancar).
- Carga los registros iniciales en el `Hub`, luego una goroutine lee el
  `Tailer` cada `poll` y hace `hub.Add` (cmd/dashboard/main.go:117).
- `index.html` está embebido con `//go:embed` (cmd/dashboard/main.go:31).

**Rutas HTTP** (cmd/dashboard/main.go:136):

| Ruta | Handler | Función |
|------|---------|---------|
| `/` | embebido | HTML del panel. |
| `/events` | `handleEvents` | SSE: `snapshot` inicial + `data:` por resultado + `event: reset`. |
| `/snapshot` | — | Historial completo en JSON. |
| `/stats` | `handleStats` | Progreso del escáner (caché 250 ms). |
| `/proxy` | `handleProxy` | Descarga una URL para mostrarla inline. |
| `/myip` | `handleMyIP` | IP pública + ISP propio (caché 10 min). |
| `/lookup` | `handleLookup` | Resolución DNS. |
| `/shodan` | `handleShodan` | Shodan InternetDB (puertos públicos). |
| `/iplookup` | `handleIPLookup` | ip-api por IP (caché 10 min). |
| `/geo/enrich` | `handleGeoEnrich` | Geo online de un lote de IPs (caché + filtro LAN). |
| `/os` | `handleOS` | SO del servidor (logo en el panel). |
| `/scan` | `app.handleScan` | Lanza netscanner desde el panel. |
| `/scanstop` | `app.handleScanStop` | Detiene el escaneo. |
| `/scanstatus` | `app.handleScanStatus` | Estado + log + stats. |
| `/suggest` | `app.handleSuggest` | Objetivos sugeridos (red local, ASN propio, dominio). |
| `/histories` | `app.handleHistories` | Lista `data/*.jsonl`. |
| `/history/load` | `app.handleHistoryLoad` | Reabre un histórico sin reescanear. |
| `/comments` `/comments/set` | comentarios por dispositivo. |
| `/ai/config` `/ai/analyze` | Análisis con IA (Groq/Gemini). |

### 9.2 `endpoints.go`

- **`geoCache`** (cmd/dashboard/endpoints.go:58): mapa `ip → OnlineInfo`
  persistido en `data/geo-cache.json` (no repite pedidos a ip-api entre
  reinicios). `handleGeoEnrich` filtra IPs privadas y cachea.
- **`checkReachability`** (cmd/dashboard/endpoints.go:148): si el objetivo es
  público o `asn:`, intenta `geo.LookupMyIP`. Si falla (sin internet), el
  escaneo responde **503** y se pausa con mensaje claro.
- **`handleScan`** (cmd/dashboard/endpoints.go:177):
  - Rechaza si ya hay uno en curso (409).
  - Si `asn:`, resuelve los rangos con `geo.ASNRoutes` y los junta.
  - Valida cada objetivo (CIDR válido o dominio resoluble).
  - Guarda en `data/<prefijo>-YYYYMMDD-HHMMSS.jsonl` (nunca pisa históricos).
  - `tailer.Switch` + `hub.ResetAll()` (vacía el panel antes de empezar).
  - Lanza `netscanner.exe` al lado del dashboard (Windows) con los flags y
    `--stats` al lado del `.jsonl`.
- **`handleHistoryLoad`** (cmd/dashboard/endpoints.go:449): valida nombre
  simple (sin `..`, sin subdirectorios), rechaza si hay escaneo en curso
  (409), hace `Switch` + `ResetAll` + `Rewind` + reenvía todos los registros
  al Hub. Así se "refleja" un escaneo viejo sin volver a sondear.
- **Comentarios / IA**: se guardan en `data/`; la IA solo analiza lo ya
  capturado (no abre nada nuevo).

### 9.3 `pkg/live`

- **`Hub`** (pkg/live/hub.go:24): mantiene `history` (limit registros) y
  difunde cada `Add` a los clientes suscritos. `ResetAll`
  (pkg/live/hub.go:79) vacía y emite `event: reset`. `Frame{Event, Data}`:
  evento vacío = registro nuevo; `"reset"` = limpiar.
- **`Tailer`** (pkg/live/tailer.go:18): sigue un `.jsonl` por `offset`. `Read`
  devuelve solo lo nuevo; `Switch` cambia de archivo (desde el final);
  `Rewind` reinicia desde el principio. **Nunca borra** el archivo viejo.

### 9.4 `index.html` (frontend)

- Mapa Leaflet + `markerCluster`. `jitterOf` (desplazamiento ~90–350 m
  determinista por IP) separa puntos del mismo `/24`.
- `enrichTick` (cada 10 s, 100 IPs/lote = 1 pedido ip-api): consulta
  **cada IP pública de forma individual** (no un representante por /24) para
  usar la coordenada real de ip-api, que gana sobre MaxMind. Lo cachea en
  `geo-cache.json`. El jitter es mínimo (~40–130 m) y solo separa puntos con
  la misma coordenada exacta.
- `buildMap` prioriza `coExtra` (geo online) sobre las coords del escaneo.
- Eventos SSE: al recibir `reset`, el cliente limpia `records`, `coExtra`,
  `groupPt` y refresca el selector de históricos.
- Selector **📂 Históricos guardados**: lista `data/*.jsonl` y los reabre sin
  escanear.

---

## 10. `cmd/enrich` — geolocalización en lote

Lee un `.jsonl` ya existente (cmd/enrich/main.go:31), descarta duplicados por
IP, aplica `SampleBy24` y consulta `geo.LookupOnline`. Por cada IP resuelta,
rellena `geo.city/lat/lon/isp/asn/org` en **todos** los registros de ese
bloque `/24` (cmd/enrich/main.go:82). Escribe `<in>_geo.jsonl` sin tocar el
original. Es la forma de darle coordenadas precisas a un escaneo ya hecho
(lo usa `scripts/scan-isp.ps1`).

---

## 11. `pkg/socks` — anonimato (Tor / VPN)

`Dialer` (pkg/socks/socks.go:28) implementa SOCKS5 (RFC 1928) con auth
usuario/pass (RFC 1929). `NewDialer(spec, timeout)` acepta `socks5://`
(spec vacía = conexión directa, devuelve `nil`). `Dial` hace el handshake y
un `CONNECT` (soporta IPv4 y dominio; **no IPv6**). Lo usa el CLI (para
enrutar el escaneo) y el dashboard (para el navegador proxy). `scripts/anon.ps1`
descarga el Tor Expert Bundle a `tools/tor` y lo levanta en `127.0.0.1:9050`.

---

## 12. Limitaciones conocidas (honestas)

1. **Solo IPv4 / TCP.** No hay UDP, ICMP ni IPv6 (el motor y socks rechazan
   v6).
2. **ASNRoutes está capado a 128 prefijos** (pkg/geo/online.go:157). Un ISP
   nacional con más bloques anunciados se trunca en silencio. Mejora posible:
   subir el tope y descartar prefijos anidados.
3. **Precisión de geo = ciudad.** Nunca calle. El medio físico (fibra/cable)
   no se deduce de los datos.
4. **El mapa no dibuja infraestructura.** Solo muestra IPs con puerto abierto,
   geolocalizadas por ciudad. Entre localidades no hay "nodos de ruta" porque
   no hay dispositivos expuestos ahí.
5. **ip-api free** ≈ 45 req/min. El batch (100 IPs/req) lo hace viable; el
   panel cachea en `geo-cache.json`.
6. **TLS no se decodifica**: el puerto 443 se sondea en texto plano; queda el
   `raw` binario sanitizado.

---

## 13. Build, test y despliegue

- `Makefile` detecta el SO y elige extensión (`.exe` en Windows, nada en
  macOS/Linux). `make all` construye los tres binarios con `-s -w`.
- `scripts/deploy.{sh,ps1}` compilan, arrancan el panel sobre
  `data/casa.jsonl` y abren el navegador.
- `scripts/escanear-red.{sh,bat}` detectan la red local y escanean.
- `scripts/scan-isp.ps1` orquesta: escaneo de rangos → `enrich` → recarga del
  panel con coordenadas.
- Verificación: `go build ./...`, `go vet ./...`, `go test ./...`.
- CI (`.github/workflows/ci.yml`) corre build/vet/test y un job `privacy` que
  falla si aparecen archivos de datos fuera de `cmd/ pkg/ scripts/ docs/
  .github/ README.md LICENSE Makefile go.mod go.sum .gitignore`.

---

## 14. Cómo extender el código

- **Nuevo sondeo de puerto**: añadir el puerto a `webPorts` o `isFTPPort`; si
  necesita lógica propia, agregar una rama en `collect` (engine.go:283).
- **Nueva fuente de geo**: implementar en `pkg/geo` y elegirla en `Lookup`.
- **Nuevo endpoint del panel**: registrarlo en `mux` (dashboard/main.go) y
  escribir el handler en `endpoints.go`.
- **Nuevo tipo de resultado**: extender `exporter.Result` (se propaga solo a
  JSONL, Hub y SSE).
- **Soporte IPv6**: requiere cambios en `engine.IPs`/`HostCount`, `geo`,
  `socks.connect` y la generación de jobs; es el trabajo más grande pendiente.
