# netscanner — escáner de red TCP en Go con panel en vivo

Descubrimiento de dispositivos y servicios en redes IPv4, escrito en **Go puro** (sin CGO, usa el `net` estándar) y pensado para **Windows**.

El motor recorre rangos CIDR en streaming, sondea puertos TCP abiertos, identifica el servicio que hay detrás (HTTP, FTP, WebDAV, RTSP, NAS…), geolocaliza los hosts y guarda todo en **JSON Lines** mientras escanea. El panel web muestra los resultados en un mapa con vistas previas automáticas del contenido expuesto, listados FTP anónimos, puntaje de riesgo por dispositivo y una consola de laboratorio para consultar cualquier IP o dominio.

> ⚠️ **Aviso importante**: escaneá únicamente redes propias o sobre las que tengas autorización explícita por escrito. Escanear redes ajenas sin permiso puede violar la ley en tu país. Leé el [descargo de responsabilidad](#descargo-de-responsabilidad) al final. Guía completa: [GUIA.md](GUIA.md).

## Qué hace

- **Escaneo paralelo rápido** — pool de workers acotado, cierre prolijo con `Ctrl+C`.
- **Identificación de servicios** — banner HTTP (título, servidor, cuerpo), banners crudos, intento de **login FTP anónimo** (`USER/PASS anonymous`), detección de **WebDAV** con PROPFIND, cámaras IP RTSP.
- **Geolocalización** — base local MaxMind `.mmdb` o respaldo online (ip-api.com), más la herramienta `enrich` que geolocaliza en lote resultados ya guardados.
- **Anonimato** — todas las conexiones pueden salir por un proxy SOCKS5 (Tor o VPN) con `--proxy`; el script `anon.ps1` descarga e inicia un Tor privado dentro del proyecto.
- **Panel en vivo** — mapa con un marcador por IP y clusters, colores por rango ISP, fichas de dispositivo, alertas de exposición, timeline y analítica de contenido, navegador proxy para ver los hosts descubiertos, capturas automáticas de cámaras y listados de archivos.
- **Consola de laboratorio** — resolver cualquier IP o dominio (DNS), ver su ISP y ciudad, y los puertos indexados públicamente con Shodan InternetDB, sin escanear nada.

## Requisitos

- Go 1.22 o más nuevo (probado con 1.26)
- Windows (el código es multiplataforma; el instalador de Tor es PowerShell)
- Conexión a internet si querés geolocalización online o Tor

## Compilar

```powershell
go mod tidy
go build -ldflags="-s -w" -o netscanner.exe ./cmd/scanner
go build -o dashboard.exe ./cmd/dashboard
go build -o enrich.exe ./cmd/enrich
```

También hay un Makefile: `make build` / `make test` / `make clean`.

## Uso básico

```powershell
netscanner.exe -c 192.168.1.0/24
netscanner.exe -c 10.0.0.0/8 -p 80,443,8080,554,21 -w 1000 -t 1500 -o out.jsonl
netscanner.exe -c delco-digital.com -p 80,443,8080 -o web.jsonl
```

`-c` acepta un rango CIDR, una IP suelta (`203.0.113.7`) o un dominio (se resuelve por DNS y se escanea esa IP).

| Flag | Corto | Por defecto | Descripción |
|---|---|---|---|
| `--cidr` | `-c` | `192.168.1.0/24` | rango IPv4, IP suelta o dominio a escanear |
| `--ports` | `-p` | `80,443,8080,8000,554,21,22` | puertos TCP separados por coma |
| `--ftp-ports` | | `21` | puertos que reciben el sondeo FTP anónimo |
| `--dav` | | `true` | sondear puertos web con PROPFIND para detectar WebDAV |
| `--workers` | `-w` | `500` | máximo de conexiones en paralelo |
| `--timeout` | `-t` | `2000` | timeout de conexión (ms) |
| `--max-body` | | `16` | máximo del cuerpo HTTP capturado por puerto web (KiB) |
| `--geoip` | `-g` | `./GeoLite2-City.mmdb` | base local de MaxMind |
| `--output` | `-o` | `results.jsonl` | archivo JSONL de salida |
| `--stats` | | | archivo de progreso en vivo para el dashboard |
| `--proxy` | | | proxy SOCKS5 para todas las conexiones, p.ej. `socks5://127.0.0.1:9050` |
| `--user-agent` | | UA de navegador | User-Agent HTTP de los sondeos |

### Escaneo anónimo (Tor)

```powershell
# una sola vez: descarga el Tor Expert Bundle oficial a tools\tor y lo inicia
.\anon.ps1

# a partir de acá todas las conexiones salen por Tor
.\netscanner.exe -c 203.0.113.0/24 -p 80,443,554 -w 20 -t 5000 -o anon.jsonl --proxy socks5://127.0.0.1:9050
```

El dashboard puede usar el mismo proxy para el navegador en vivo y el listado FTP: `.\dashboard.exe -file anon.jsonl --proxy socks5://127.0.0.1:9050`.

Notas:

- La dirección **MAC nunca sale de tu red local**; los hosts remotos solo ven tu IP pública (o la del proxy).
- Los sondeos mandan un User-Agent neutro de navegador, no una firma de escáner.
- Tor es lento a propósito: para escaneos grandes conviene una VPN en vez de `--proxy`.

## Panel web

```powershell
# terminal 1: el escaneo (como siempre)
.\netscanner.exe -c 192.168.1.0/24 -o results.jsonl --stats stats.json

# terminal 2: el panel
.\dashboard.exe -file results.jsonl -stats stats.json
```

Abrís `http://127.0.0.1:8080`. El panel:

- transmite los resultados en tiempo real por SSE (también funciona con archivos JSONL ya existentes);
- muestra un **mapa** con un marcador por IP geolocalizada, aros de color por rango ISP, iconos por tipo y clusters; al hacer clic en un marcador se abre la ficha del dispositivo;
- **previsualiza automáticamente**: capturas de cámaras (`/snapshot.cgi`, `/image.jpg`, …), miniaturas de imágenes en listados expuestos y un botón para **listar directorios FTP anónimos** en vivo;
- ofrece un **navegador en vivo** (`/proxy`) para recorrer cualquier host descubierto dentro del panel;
- calcula un **puntaje de riesgo de exposición** por dispositivo (listados de archivos, cámaras, logins, FTP, WebDAV, puertos abiertos) con badges alto/medio/bajo;
- incluye la **consola de laboratorio** para consultar DNS, ISP y Shodan de cualquier IP o dominio (sin escanear).

### Geolocalizar resultados

```powershell
.\enrich.exe -in results.jsonl            # escribe results_geo.jsonl
.\dashboard.exe -file results_geo.jsonl   # el mapa ahora muestra las ciudades
```

`scan-isp.ps1` automatiza todo el flujo (escaneo de rangos ISP → geolocalización → recarga del panel), opcionalmente por proxy: `.\scan-isp.ps1 -Proxy socks5://127.0.0.1:9050`.

## Formato de salida (JSONL)

Un objeto JSON por puerto abierto:

```json
{"timestamp":"2026-01-01T00:00:00Z","ip":"8.8.8.8","port":21,"status":"open","banner":{"http":false,"ftp_auth":"anonymous","ftp_banner":"220 FTP ready"},"geo":{"label":"Public","country":"United States","city":"Mountain View","latitude":37.42,"longitude":-122.08,"isp":"Example ISP","asn":"AS15169"}}
```

Campos opcionales (se omiten si están vacíos): `ftp_auth`, `ftp_banner`, `dav`, `dav_body`, `geo.isp`, `geo.asn`, `geo.org`.

## Tests

```powershell
go vet ./...
go test ./...
```

La suite incluye sondeos de punta a punta contra servidores fake de FTP, WebDAV y SOCKS5 (`pkg/banner`, `pkg/socks`).

## Estructura

```
cmd/scanner/    punto de entrada del CLI, flags, cierre prolijo
cmd/dashboard/  panel web en vivo (index.html embebido) + proxy + endpoints de laboratorio
cmd/enrich/     geolocalización en lote de resultados JSONL existentes
pkg/config/     parseo y validación de flags
pkg/engine/     generador de IPs en streaming + pool de workers + pipeline de sondeo
pkg/banner/     sondeos HTTP/crudo/FTP/WebDAV
pkg/geo/        MaxMind .mmdb + geolocalización online (ip-api)
pkg/socks/      cliente SOCKS5 mínimo (sin auth y con user/pass)
pkg/exporter/   escritor JSONL asíncrono
pkg/live/       hub SSE + tailer de archivo para el dashboard
```

La especificación técnica completa está en `SPEC.md`.

## Autor

Código y diseño por **Juanjoclassic** ([TikTok](https://www.tiktok.com/@juanjoclassic)). Licencia [MIT](LICENSE).

## Descargo de responsabilidad

Este proyecto es una **herramienta de seguridad informática y administración de redes** creada con fines educativos, de auditoría propia y de investigación. Está pensada para que cada persona audite sus propios equipos, su red local o infraestructura sobre la que tenga autorización expresa.

El uso indebido de esta herramienta —escanear, sondear o acceder a sistemas ajenos sin permiso— puede ser un delito en tu país. El escaneo de puertos y la conexión a servicios expuestos en internet pueden violar leyes de acceso no autorizado (como la CFAA en Estados Unidos, la Ley 26.388 en Argentina o la legislación equivalente en otros países), incluso cuando la intención sea solo "mirar".

Al usar este software aceptás que:

- sos el único responsable de lo que hagas con él y de los datos que obtengas;
- el autor no se hace responsable de daños directos, indirectos o consecuentes derivados de su uso;
- los datos de ejemplo en este repositorio y en la documentación son ficticios salvo que se indique lo contrario.

Si no estás seguro de tener permiso para escanear una red, no la escanees.
