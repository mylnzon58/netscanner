# Guía didáctica · netscanner

Todo lo que se puede (y no se puede) hacer con esta herramienta, explicado simple.

---

## 1. ¿Me pueden ver la MAC o el hardware? NO.

- La **MAC** de tu placa de red **no sale nunca de tu casa**: se queda en el router WiFi/cable. Internet solo ve tu **IP pública**. Nadie puede "leerte la MAC" desde afuera.
- El escáner **no manda ningún dato de hardware**: los paquetes TCP no llevan información del equipo. En las peticiones HTTP solo se envía el **User-Agent**, y este scanner ya usa uno neutro de navegador (Chrome en Windows), no uno que diga "NetScanner".
- Lo único que queda registrado en el servidor que escaneas es tu **IP pública** (y la hora). Para eso existen las soluciones de abajo.

## 2. Ocultar tu IP real (proxy / TOR / VPN)

| Método | Cómo | Velocidad | Qué oculta |
|---|---|---|---|
| **Sin nada** | `netscanner.exe -c ...` | máxima | nada (usas tu IP) |
| **VPN** (recomendada) | conectás tu VPN y escaneás normal | alta | tu IP (aparece la del VPN) |
| **TOR** | `.\scripts\anon.ps1` (instala y arranca TOR solo) y usás `--proxy socks5://127.0.0.1:9050` | muy lenta | tu IP (aparece un nodo TOR) |

**TOR automático (no requiere instalar nada aparte)** — el script descarga el Expert Bundle oficial de Tor dentro del proyecto (`tools\tor`) y lo arranca:

```
.\scripts\anon.ps1
```

Después de ver "TOR LISTO", ya podés escanear anónimo:

```
.\netscanner.exe -c 192.0.2.0/24 -p 80,443 -w 20 -t 5000 -o data\tor.jsonl --proxy socks5://127.0.0.1:9050
```

Otros subcomandos: `.\scripts\anon.ps1 -Check` (¿está corriendo?) y `.\scripts\anon.ps1 -Stop`. En macOS/Linux: `./scripts/anon.sh` con `--check` y `--stop`.

**Ojo con TOR**: el escaneo masivo por TOR es *extremadamente lento* (20-50 conexiones/seg) y muchos servidores bloquean nodos TOR. Para escaneos grandes usá una VPN. El panel también puede usar el proxy:

```
.\dashboard.exe -file data\tor.jsonl --proxy socks5://127.0.0.1:9050
```

(esto anonimiza el navegador en vivo `/proxy` y el listado FTP `/ftplist`).

## 3. ¿Por qué no hay FTP anónimos en mi zona?

Es normal. El FTP anónimo público **prácticamente desapareció**:

- Los routers de fibra/ADSL **bloquean el puerto 21 por defecto** (UPnP/Firewall).
- Los servidores modernos **deshabilitan el login anónimo**.
- Lo que SÍ existe y es abundante:
  - **Listados web "Index of /"** (Apache/nginx sin índices deshabilitados) → archivos visibles sin login.
  - **WebDAV expuesto** (PROPFIND sin credenciales).
  - **Cámaras y DVRs** con web accesible (algunas sin login, otras con contraseña de fábrica).
  - **Logins de routers** (KAON, Mikrotik, ePMP…) con credenciales por defecto.

El escaneo completo de tu ISP (3.300 puertos abiertos) encontró 0 FTP anónimos: es la realidad de la red, no una falla del detector (el detector está verificado con servidores de prueba). Para encontrar FTP/NAS/cámaras: escaneá tu **red local** (192.168.x.0/24), donde los dispositivos viejos (impresoras, NAS, DVRs) suelen tener FTP y web sin login.

## 4. Cámaras

- Se detectan por **puerto 554** (RTSP) o por su web (títulos Hikvision, Dahua, XMeye, Netvision…).
- **Snapshot automático**: el panel intenta `/snapshot.cgi`, `/image.jpg`, `/cgi-bin/liveimg.cgi`, etc. en cámaras web sin login. Si pide login, no hay snapshot (entrar con contraseñas ajenas, aunque sean de fábrica, es **ilegal** sin autorización).
- Puertos típicos de cámaras: `554` (RTSP), `80/8080` (web), `34567` (XMEye), `37777` (Dahua DVR), `5000` (ONVIF).

## 5. Consultar OTROS ISP, IPs o dominios (sin escanear)

El panel tiene una sección **🔬 Laboratorio**: escribís una IP o un dominio y te dice:

1. **DNS** → la(s) IP(s) real(es) del dominio.
2. **ISP y ciudad** (ip-api.com).
3. **Puertos y servicios públicos** indexados por **Shodan InternetDB** (lo que el mundo ya sabe de esa IP, sin tocar nada → 100% legal).

Para escanear un rango de otro operador de tu zona necesitás sus bloques de IP. Se obtienen con `whois` (ej: `whois 203.0.113.0`), o buscando el ASN del operador. ⚠️ **Escanear redes de terceros sin autorización es un delito en Argentina** (acceso ilegítimo a sistemas). Hacelo solo en tu red, la de tu trabajo (con permiso) o con el dueño de la red de acuerdo.

## 6. Mapa

- El mapa muestra **cada IP** como un punto con icono de su tipo (cámara, servidor, FTP, NAS…) y anillo del color de su rango.
- La precisión es a **nivel ciudad** (las bases públicas no dan dirección exacta): los puntos se dispersan dentro del área de la ciudad. Un punto no es la ubicación exacta del dispositivo.

## 7. Históricos guardados y privacidad

- **Cada escaneo del panel se guarda solo** en `data/` con su fecha y hora (`data\casa-20260812-022418.jsonl`). El hero tiene un selector **📂 Históricos guardados** que los lista (nombre, tamaño, fecha): elegí uno y tocá **Abrir histórico** para **reflejarlo sin volver a escanear** (el archivo se lee tal cual está guardado).
- Al lanzar un **objetivo nuevo**, el panel se **vacía solo** (mapa, fichas, timeline) para no mezclar escaneos; los históricos anteriores quedan intactos en `data/`.
- **Sin conexión = pausa**: antes de escanear un objetivo público, el panel se fija si puede obtener tu IP/geo. Si no hay internet, el escaneo **se pausa** con un mensaje claro ("Revisá el router y volvé a intentar") en vez de sondear sin sentido.
- **Regla de oro del repo**: el repositorio es solo código. Resultados (`*.jsonl`), progreso (`*.stats`), caché geo (`geo-cache.json`), notas (`comments.json`) y claves de IA (`ai_key.json`) viven en `data/`, que `.gitignore` excluye siempre: **no se suben IPs, cuentas ni webs de nadie al repo público**. El CI lo verifica y falla si aparece un archivo de datos.

## 8. Comandos rápidos

| Tarea | Comando |
|---|---|
| Tu red local | `.\netscanner.exe -c 192.168.1.0/24 -o data\casa.jsonl` |
| Tu operador completo | `.\netscanner.exe -c asn: -p 80,554 -w 500 -t 600 -o data\operador.jsonl` (o `asn:AS64500` para otro; en el panel, un clic en "Tu operador de internet completo") |
| Una IP suelta | `.\netscanner.exe -c 203.0.113.7/32 -p 80,443,554,21 -o data\ip.jsonl` |
| Un dominio | `.\netscanner.exe -c delco-digital.com -p 80,443,8080,554 -o data\web.jsonl` (resuelve la IP y la escanea) |
| Varios objetivos | `.\netscanner.exe -c 192.168.1.0/24,10.0.0.1 -p 80 -o data\mix.jsonl` |
| Un rango de ISP (conocido/tuyo) | `.\netscanner.exe -c 198.51.100.0/24 -p 80,443,8080,8000,554,21,22,5000,5001 -w 400 -t 1500 -o data\isp.jsonl --stats data\scan_stats.json` |
| Anónimo por TOR | agregar `--proxy socks5://127.0.0.1:9050` (y bajar `-w` a 20-50) |
| Ver resultados | `.\dashboard.exe -file data\isp.jsonl` → http://127.0.0.1:8080 |
| Geolocalizar | `.\enrich.exe -in data\isp.jsonl` (genera `data\isp_geo.jsonl`) |

> Los puertos `554` (RTSP), `34567` (XMEye) y `37777` (Dahua) sirven para detectar cámaras; `21` + `--ftp-ports 21` para FTP anónimo; `5000/5001` (Synology/QNAP) y `8081` (QNAP) para NAS.
