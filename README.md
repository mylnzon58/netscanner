# netscanner — escáner de red TCP en Go con panel en vivo

Descubrimiento de dispositivos y servicios en redes IPv4, escrito en **Go puro** (sin CGO, usa el `net` estándar) y pensado para **Windows**.

El motor recorre rangos CIDR en streaming, sondea puertos TCP abiertos, identifica el servicio que hay detrás (HTTP, FTP, WebDAV, RTSP, NAS…), geolocaliza los hosts y guarda todo en **JSON Lines** mientras escanea. El panel web muestra los resultados en un mapa con vistas previas automáticas del contenido expuesto, listados FTP anónimos, puntaje de riesgo por dispositivo y una consola de laboratorio para consultar cualquier IP o dominio.

> ⚠️ **Aviso importante**: escaneá únicamente redes propias o sobre las que tengas autorización explícita por escrito. Escanear redes ajenas sin permiso puede violar la ley en tu país. Leé el [descargo de responsabilidad](#descargo-de-responsabilidad) al final. Guía completa: [docs/GUIA.md](docs/GUIA.md).

## Qué hace

- **Escaneo paralelo rápido** — pool de workers acotado, cierre prolijo con `Ctrl+C`.
- **Identificación de servicios** — banner HTTP (título, servidor, cuerpo), banners crudos, intento de **login FTP anónimo** (`USER/PASS anonymous`), detección de **WebDAV** con PROPFIND, cámaras IP RTSP.
- **Geolocalización** — base local MaxMind `.mmdb` o respaldo online (ip-api.com), más la herramienta `enrich` que geolocaliza en lote resultados ya guardados.
- **Anonimato** — todas las conexiones pueden salir por un proxy SOCKS5 (Tor o VPN) con `--proxy`; el script `scripts/anon.ps1` descarga e inicia un Tor privado dentro del proyecto.
- **Panel en vivo** — mapa con un marcador por IP y clusters, colores por rango ISP, fichas de dispositivo, alertas de exposición, timeline y analítica de contenido, navegador proxy para ver los hosts descubiertos, capturas automáticas de cámaras y listados de archivos.
- **Históricos guardados** — cada escaneo del panel se guarda en `data/` como archivo propio (con fecha y hora); un selector en el hero permite **reabrir cualquier escaneo anterior sin volver a escanear**. Al lanzar un objetivo nuevo, el panel se vacía solo para no mezclar resultados.
- **Pausa automática sin conexión** — si no se puede obtener tu IP/geo (sin internet), el escaneo remoto se pausa con un mensaje claro en vez de sondear al pedo.
- **Consola de laboratorio** — resolver cualquier IP o dominio (DNS), ver su ISP y ciudad, y los puertos indexados públicamente con Shodan InternetDB, sin escanear nada.

## Requisitos

- Go 1.22 o más nuevo (probado con 1.26)
- Windows, macOS (Intel o Apple Silicon) o Linux: el código es Go puro y compila igual en las tres
- Conexión a internet si querés geolocalización online o Tor

## Instalar y desplegar (un solo comando)

El repositorio trae scripts de despliegue automático por sistema (`scripts/`): compilan los tres binarios, arrancan el panel y abren el navegador solo. El panel trabaja sobre `data/resultados`, por eso el repositorio nunca muestra datos de escaneos.

```powershell
# Windows
.\scripts\deploy.ps1

# macOS / Linux
./scripts/deploy.sh
```

Después abrí `http://127.0.0.1:8080`. El panel muestra en el título el **logo y el nombre del sistema operativo donde corre** (Windows, macOS o Linux, detectado en el servidor). Si el binario ya está compilado y solo querés el panel:

```powershell
# Windows (macOS/Linux: ./dashboard sin extensión)
.\dashboard.exe -file data\casa.jsonl   # y abrís http://127.0.0.1:8080
```

Compilar a mano (si querés):

```powershell
# Windows: .\scripts\build.ps1 · macOS / Linux: ./scripts/build.sh (o: make build && make dashboard && make enrich)
```

Los binarios en Windows son `netscanner.exe` / `dashboard.exe` / `enrich.exe`; en macOS y Linux son `netscanner` / `dashboard` / `enrich` (sin extensión). El resto de comandos de este documento usa `netscanner.exe`, pero la única diferencia en macOS/Linux es la extensión.

## Estructura del repositorio y privacidad

```text
cmd/        escáner, panel web y herramienta de geolocalización
pkg/        motor, geo, banner, exportador, socks, en vivo
scripts/    automatizaciones (deploy, build, anonimato Tor, red local)
docs/       guía de uso (GUIA.md) y especificación técnica (SPEC.md)
data/       SOLO local: resultados, caché geo, notas y logs (ignorado por git)
tools/      SOLO local: bundle Tor descargado por anon.ps1 (ignorado)
```

**Regla de oro**: el repositorio es solo código. Los resultados de escaneo (`*.jsonl`), el progreso (`*.stats`), la caché de geolocalización (`geo-cache.json`), las notas por dispositivo (`comments.json`) y las claves de IA (`ai_key.json`) viven en `data/`, que `.gitignore` excluye siempre. Se suben IPs, redes, cuentas ni webs de nadie; las tareas de build y un job de privacidad en CI fallan si aparece un archivo de datos en el repo.

## Uso básico

```powershell
netscanner.exe -c 192.168.1.0/24 -o data\casa.jsonl
netscanner.exe -c 10.0.0.0/8 -p 80,443,8080,554,21 -w 1000 -t 1500 -o data\out.jsonl
netscanner.exe -c delco-digital.com -p 80,443,8080 -o data\web.jsonl
```

`-c` acepta un rango CIDR, una IP suelta (`203.0.113.7`), un dominio (se resuelve por DNS y se escanea esa IP) o **varios objetivos a la vez** separados por coma:

```powershell
netscanner.exe -c 192.168.1.0/24,10.0.0.1
netscanner.exe -c "198.51.100.0/24,203.0.114.7" -p 80,554 -w 1000
```

| Flag | Corto | Por defecto | Descripción |
|---|---|---|---|
| `--cidr` | `-c` | `192.168.1.0/24` | rango IPv4, IP suelta, dominio o varios separados por coma |
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

### Escaneo de un operador completo (ASN)

Con `asn:XXXX` (o `asn:` para tu propio proveedor) el panel y la CLI resuelven los rangos IPv4 anunciados por ese sistema autónomo —vía RIPEstat de RIPE, público y sin clave— y los escanean completos. Sirve para ver qué hay expuesto en una zona (cámaras, DVR, NAS, servidores sin protección):

```powershell
netscanner.exe -c asn:AS64500 -p 80,554 -w 500 -t 600 -o operador.jsonl
```

En el panel: el botón **"Tu operador de internet completo"** hace exactamente esto con un clic. Antes de arrancar, el log muestra cuántos rangos e IPs va a recorrer (p.ej. `operador AS64500: 4 rangos (5112 IPs)`). Para bloques grandes bajá `-t` y subí `-w`; también podés probar puertos de a uno.

> ⚠️ Escaneá solo tu propio operador, y usá lo que encuentres para **reportar lo expuesto**, no para atacar: lo abierto suele ser de gente de tu zona.

### Escaneo anónimo (Tor)

Windows:

```powershell
# una sola vez: descarga el Tor Expert Bundle oficial a tools\tor y lo inicia
.\scripts\anon.ps1

# a partir de acá todas las conexiones salen por Tor
.\netscanner.exe -c 203.0.113.0/24 -p 80,443,554 -w 20 -t 5000 -o data\anon.jsonl --proxy socks5://127.0.0.1:9050
```

macOS / Linux: lo mismo con `./scripts/anon.sh` (detecta la plataforma y baja el bundle correspondiente). Parar con `--stop`, verificar con `--check`.

El dashboard puede usar el mismo proxy para el navegador en vivo y el listado FTP: `.\dashboard.exe -file data\anon.jsonl --proxy socks5://127.0.0.1:9050`.

Notas:

- La dirección **MAC nunca sale de tu red local**; los hosts remotos solo ven tu IP pública (o la del proxy).
- Los sondeos mandan un User-Agent neutro de navegador, no una firma de escáner.
- Tor es lento a propósito: para escaneos grandes conviene una VPN en vez de `--proxy`.

## Panel web

```powershell
# terminal 1: el escaneo (como siempre)
.\netscanner.exe -c 192.168.1.0/24 -o data\results.jsonl --stats data\stats.json

# terminal 2: el panel
.\dashboard.exe -file data\results.jsonl -stats data\stats.json
```

Abrís `http://127.0.0.1:8080`. El panel:

- transmite los resultados en tiempo real por SSE (también funciona con archivos JSONL ya existentes);
- muestra un **mapa** con un marcador por IP geolocalizada, aros de color por rango ISP, iconos por tipo y clusters; al hacer clic en un marcador se abre la ficha del dispositivo;
- **previsualiza automáticamente**: capturas de cámaras (`/snapshot.cgi`, `/image.jpg`, …), miniaturas de imágenes en listados expuestos y un botón para **listar directorios FTP anónimos** en vivo;
- ofrece un **navegador en vivo** (`/proxy`) para recorrer cualquier host descubierto dentro del panel;
- calcula un **puntaje de riesgo de exposición** por dispositivo (listados de archivos, cámaras, logins, FTP, WebDAV, puertos abiertos) con badges alto/medio/bajo;
- incluye la **consola de laboratorio** para consultar DNS, ISP y Shodan de cualquier IP o dominio (sin escanear);
- **escanea desde la web**: cuando no hay datos, el panel propone objetivos —tu red local, **todo el bloque de tu proveedor de internet** o un dominio— y un formulario para lanzar el escaneo con puertos, timeout, workers y proxy opcional, viendo el progreso en vivo;
- muestra **tecnologías y CDN** detectadas (jQuery, nginx, Cloudflare, WordPress, …) como etiquetas en cada ficha;
- deja **notas por dispositivo** (por ejemplo, "es un honeypot, no tocar") guardadas en `data/comments.json`;
- analiza cada dispositivo con **IA gratuita opcional** (Groq o Gemini): explica qué es, qué señales raras tiene, el riesgo y qué hacer, sin abrir nada más en el host;
- guarda **cada escaneo como histórico** en `data/` y permite **reabrirlos desde el hero** (📂 Históricos guardados) sin volver a escanear; al lanzar un objetivo nuevo se **vacía el panel solo** para no mezclar escaneos;
- **pausa el escaneo remoto si no hay conexión** (no se pudo obtener tu IP/geo), avisando por qué, en vez de sondear al pedo.

### Geolocalizar resultados

```powershell
.\enrich.exe -in data\results.jsonl            # escribe data\results_geo.jsonl
.\dashboard.exe -file data\results_geo.jsonl   # el mapa ahora muestra las ciudades
```

### Escaneo de la red local con un clic

Windows: `scripts\escanear-red.bat` (doble clic) — detecta la red sola (`scripts\detectar-red.ps1`), la escanea con la lista completa de puertos y abre el panel con los resultados. macOS/Linux: `./scripts/escanear-red.sh` (usa `scripts/detectar-red.sh`).

`scripts/scan-isp.ps1` automatiza todo el flujo (escaneo de rangos ISP → geolocalización → recarga del panel), opcionalmente por proxy: `.\scripts\scan-isp.ps1 -Proxy socks5://127.0.0.1:9050`.

### Análisis con IA (opcional)

En cualquier ficha del dispositivo, el botón "analizar con IA" manda el sondeo ya capturado a Groq o Gemini:

```powershell
# la clave se guarda localmente en ai_key.json (nunca se sube al repo)
Invoke-RestMethod http://127.0.0.1:8080/ai/config -Method Post -Body '{"provider":"groq","key":"TU_CLAVE"}' -ContentType "application/json"
```

La IA responde en español: qué es el dispositivo, qué señales delatadoras tiene (trampas, configuraciones expuestas), el riesgo y qué hacer. Solo analiza la información ya capturada: **no abre ni toca nada en el host**. Los datos de `data/comments.json` y `data/ai_key.json` están en `.gitignore` y nunca se suben.

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
pkg/geo/        MaxMind .mmdb + geolocalización online (ip-api) + rangos por ASN (RIPEstat)
pkg/socks/      cliente SOCKS5 mínimo (sin auth y con user/pass)
pkg/exporter/   escritor JSONL asíncrono
pkg/live/       hub SSE + tailer de archivo para el dashboard
```

## Documentación

| Documento | Para qué sirve |
|-----------|----------------|
| [`docs/GUIA.md`](docs/GUIA.md) | Guía de uso paso a paso (modo anónimo, cámaras, laboratorio). |
| [`docs/SPEC.md`](docs/SPEC.md) | Especificación técnica del formato y módulos base. |
| [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md) | Arquitectura completa del código, de extremo a extremo. **Empezá por acá si querés entender cómo funciona todo.** |

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
