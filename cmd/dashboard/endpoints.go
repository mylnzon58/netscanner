// Endpoints de acción del panel: lanzar escaneos, propuestas,
// comentarios por dispositivo y análisis con IA opcional.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"netscanner/pkg/geo"
	"netscanner/pkg/live"
)

type app struct {
	tailer     *live.Tailer
	hub        *live.Hub
	filePrefix string // prefijo fijo para los archivos de cada escaneo
}

// statsPath devuelve dónde escribe el escáner su progreso en vivo,
// al lado del archivo que vigila el panel.
func (a *app) statsPath() string { return a.tailer.Path() + ".stats" }

// routesHosts suma las direcciones usables de una lista de rangos.
func routesHosts(routes []string) uint64 {
	var total uint64
	for _, r := range routes {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		count := uint64(1) << (32 - ones)
		if bits == 32 && ones <= 30 {
			count -= 2
		}
		total += count
	}
	return total
}

// ---- enriquecimiento geográfico en vivo ----

// geoCache persiste en disco las coordenadas consultadas (ip-api tiene
// un límite de ~45 p/min sin clave), para no repetir pedidos entre
// reinicios del panel. La ruta la fija main según data/.
var geoCache = struct {
	mu   sync.Mutex
	path string
	data map[string]geo.OnlineInfo
}{data: make(map[string]geo.OnlineInfo)}

func geoCacheSave() {
	if len(geoCache.data) == 0 {
		return
	}
	geoCache.mu.Lock()
	defer geoCache.mu.Unlock()
	d, err := json.Marshal(geoCache.data)
	if err != nil {
		return
	}
	_ = os.WriteFile(geoCache.path, d, 0o644)
}

// handleGeoEnrich geolocaliza un lote de IPs (GET /geo/enrich?ips=a,b,c,
// como máximo 50 por pedido) usando la caché local y ip-api. Las IPs
// privadas (LAN, loopback, link-local) se descartan: ip-api no las
// geolocaliza y no vale la pena consultarlas.
func handleGeoEnrich(w http.ResponseWriter, r *http.Request) {
	var ips []string
	seen := map[string]bool{}
	for _, s := range strings.Split(r.URL.Query().Get("ips"), ",") {
		s = strings.TrimSpace(s)
		ip := net.ParseIP(s)
		if ip == nil || seen[s] {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil || geo.IsPrivate(ip4) {
			continue
		}
		seen[s] = true
		ips = append(ips, s)
		if len(ips) == 100 {
			break
		}
	}
	if len(ips) == 0 {
		http.Error(w, "pedido inválido", http.StatusBadRequest)
		return
	}
	out := map[string]geo.OnlineInfo{}
	geoCache.mu.Lock()
	var miss []string
	for _, ip := range ips {
		if g, ok := geoCache.data[ip]; ok && g.Lat != 0 {
			out[ip] = g
		} else {
			miss = append(miss, ip)
		}
	}
	if len(miss) > 0 {
		if infos, err := geo.LookupOnline(miss); err == nil {
			for ip, g := range infos {
				geoCache.data[ip] = g
				out[ip] = g
			}
		}
	}
	geoCache.mu.Unlock()
	if len(miss) > 0 {
		go geoCacheSave()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ---- escaneo desde el panel ----

var scanState struct {
	mu    sync.Mutex
	run   *exec.Cmd
	log   []string
	busy  bool
	start time.Time
	file  string
}

const scanLogMax = 300

func (a *app) scanLog(line string) {
	scanState.mu.Lock()
	defer scanState.mu.Unlock()
	scanState.log = append(scanState.log, line)
	if len(scanState.log) > scanLogMax {
		scanState.log = scanState.log[len(scanState.log)-scanLogMax:]
	}
}

// handleScan lanza netscanner con los parámetros que manda el panel,
// trunca el archivo de resultados y deja que el tailer siga escribiendo.
// checkReachability pausa el escaneo cuando no hay conexión a internet:
// si ni siquiera se puede obtener la propia IP pública (geo), sondear
// objetivos remotos no tiene sentido. La red local se escanea igual,
// aunque ip-api no responda.
func (a *app) checkReachability(cidr string) error {
	var needsCheck bool
	for _, part := range strings.Split(cidr, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "asn:") {
			needsCheck = true
			break
		}
		ip := net.ParseIP(part)
		if ip == nil {
			if _, ipnet, err := net.ParseCIDR(part); err == nil {
				ip = ipnet.IP
			}
		}
		if ip == nil || geo.IsPrivate(ip) {
			continue
		}
		needsCheck = true
		break
	}
	if !needsCheck {
		return nil
	}
	if _, err := geo.LookupMyIP(); err != nil {
		return fmt.Errorf("sin conexión a internet (no se pudo obtener tu IP/geo: %v). Revisá el router y volvé a intentar", err)
	}
	return nil
}

func (a *app) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	scanState.mu.Lock()
	if scanState.busy {
		scanState.mu.Unlock()
		http.Error(w, "ya hay un escaneo en curso", http.StatusConflict)
		return
	}
	scanState.busy = true
	scanState.run = nil
	scanState.log = nil
	scanState.file = ""
	scanState.start = time.Now()
	// Si algo falla antes de lanzar el proceso, se libera busy acá;
	// si el proceso arrancó, el busy lo libera la goroutine que espera
	// a que termine (el escaneo sigue "en curso" aunque el handler ya
	// haya respondido).
	scanStarted := false
	defer func() {
		if scanStarted {
			return
		}
		scanState.mu.Lock()
		scanState.busy = false
		scanState.mu.Unlock()
	}()
	scanState.mu.Unlock()

	var req struct {
		Cidr    string `json:"cidr"`
		Ports   string `json:"ports"`
		Workers int    `json:"workers"`
		Timeout int    `json:"timeout"`
		Proxy   string `json:"proxy"`
		Output  string `json:"output"`
		NoGeoIP bool   `json:"no_geoip"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	req.Cidr = strings.TrimSpace(req.Cidr)
	if req.Cidr == "" {
		http.Error(w, "falta el objetivo (CIDR, IP o dominio)", http.StatusBadRequest)
		return
	}
	if err := a.checkReachability(req.Cidr); err != nil {
		http.Error(w, "escaneo pausado: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	target := req.Cidr
	// "asn:XXXX" escanea todos los rangos que anuncia ese proveedor
	// (si viene solo "asn:", se usa el ASN de la propia conexión).
	if strings.HasPrefix(req.Cidr, "asn:") {
		asn := strings.TrimPrefix(req.Cidr, "asn:")
		if asn == "" {
			if info, err := geo.LookupMyIP(); err == nil && info.AS != "" {
				asn = strings.Fields(info.AS)[0]
			}
		}
		routes, err := geo.ASNRoutes(asn)
		if err != nil {
			http.Error(w, "no se pudieron obtener los rangos del operador: "+err.Error(), http.StatusBadRequest)
			return
		}
		target = strings.Join(routes, ",")
		a.scanLog(fmt.Sprintf("[netscanner] operador %s: %d rangos (%d IPs)", asn, len(routes), routesHosts(routes)))
	}
	// Se valida el objetivo ANTES de tocar los resultados: un CIDR
	// mal escrito no debe borrar lo que ya había escaneado.
	for _, part := range strings.Split(target, ",") {
		part = strings.TrimSpace(part)
		if _, _, err := net.ParseCIDR(part); err != nil {
			if net.ParseIP(part) == nil {
				if _, err := net.LookupHost(part); err != nil {
					http.Error(w, "no se pudo resolver el objetivo: "+part, http.StatusBadRequest)
					return
				}
			}
		}
	}
	if req.Ports == "" {
		req.Ports = "80,443,8080,8000,554,21,22,5000,5001"
	}
	if req.Workers < 1 {
		req.Workers = 200
	}
	if req.Timeout < 100 {
		req.Timeout = 1500
	}
	if req.Output == "" {
		// Cada escaneo del panel guarda su propio archivo con fecha y
		// hora en data/: los históricos nunca se borran y se pueden
		// volver a abrir desde el panel sin reescanear.
		dir := filepath.Dir(a.tailer.Path())
		req.Output = filepath.Join(dir, a.filePrefix+"-"+time.Now().Format("20060102-150405")+".jsonl")
	}

	if err := os.Truncate(req.Output, 0); err != nil && !os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("no se pudo limpiar %s: %v", req.Output, err), http.StatusInternalServerError)
		return
	}
	if err := a.tailer.Switch(req.Output); err != nil {
		http.Error(w, fmt.Sprintf("no se pudo abrir %s: %v", req.Output, err), http.StatusInternalServerError)
		return
	}
	// Objetivo nuevo: se vacía todo lo anterior en el panel y en los
	// navegadores conectados, para que no queden resultados mezclados.
	a.hub.ResetAll()
	scanState.mu.Lock()
	scanState.file = req.Output
	scanState.mu.Unlock()

	args := []string{
		"-c", target,
		"-p", req.Ports,
		"-w", fmt.Sprint(req.Workers),
		"-t", fmt.Sprint(req.Timeout),
		"-o", req.Output,
		"--stats", a.statsPath(),
	}
	if req.Proxy != "" {
		args = append(args, "--proxy", req.Proxy)
	}
	// Windows no ejecuta "netscanner.exe" relativo al directorio actual;
	// se busca el binario al lado del propio dashboard.
	bin := "netscanner.exe"
	if exe, err := os.Executable(); err == nil {
		if d := filepath.Dir(exe); d != "" {
			bin = filepath.Join(d, "netscanner.exe")
		}
	}
	cmd := exec.Command(bin, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(io.MultiReader(stdout, stderr))
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	go func() {
		for l := range lines {
			a.scanLog(l)
		}
	}()

	if err := cmd.Start(); err != nil {
		http.Error(w, fmt.Sprintf("no se pudo lanzar netscanner.exe: %v", err), http.StatusInternalServerError)
		return
	}
	scanStarted = true
	scanState.mu.Lock()
	scanState.run = cmd
	scanState.mu.Unlock()

	go func() {
		_ = cmd.Wait()
		scanState.mu.Lock()
		scanState.run = nil
		scanState.busy = false
		scanState.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"ok":     "escaneo iniciado",
		"output": req.Output,
		"cidr":   req.Cidr,
	})
}

func (a *app) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	scanState.mu.Lock()
	run := scanState.run
	scanState.mu.Unlock()
	if run != nil && run.Process != nil {
		_ = run.Process.Kill()
		_, _ = json.Marshal(map[string]string{"ok": "detenido"})
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":"detenido"}`))
}

func (a *app) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	scanState.mu.Lock()
	defer scanState.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"busy":  scanState.busy,
		"log":   scanState.log,
		"since": scanState.start,
		"file":  scanState.file,
	}
	// El escáner escribe su progreso en vivo a este archivo; se lo
	// reenvía al panel para dibujar la barra de avance y la traza.
	var s struct {
		Total    uint64   `json:"total"`
		Attempts uint64   `json:"attempts"`
		Open     uint64   `json:"open"`
		Timeouts uint64   `json:"timeouts"`
		Errors   uint64   `json:"errors"`
		Sample   []string `json:"sample"`
		Last     string   `json:"last"`
	}
	if data, err := os.ReadFile(a.statsPath()); err == nil {
		if err := json.Unmarshal(data, &s); err == nil && (s.Total > 0 || len(s.Sample) > 0) {
			resp["stats"] = s
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ---- historiales guardados ----

// handleHistories lista los escaneos guardados (data/*.jsonl) con su
// tamaño y fecha, para poder reabrir uno sin volver a escanear.
func (a *app) handleHistories(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Dir(a.tailer.Path())
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "no se pudo leer el directorio de datos: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type hist struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		At   string `json:"at"`
	}
	var out []hist
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, hist{Name: e.Name(), Size: fi.Size(), At: fi.ModTime().Format("2006-01-02 15:04")})
	}
	if len(out) == 0 {
		out = []hist{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleHistoryLoad reabre un escaneo guardado: cambia el tailer a ese
// archivo y vuelca todo su contenido al panel, sin escanear de nuevo.
func (a *app) handleHistoryLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	scanState.mu.Lock()
	busy := scanState.busy
	scanState.mu.Unlock()
	if busy {
		http.Error(w, "hay un escaneo en curso: detenelo antes de abrir un histórico", http.StatusConflict)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err := json.Unmarshal(body, &req); err != nil || req.Name == "" {
		http.Error(w, "falta el nombre del histórico", http.StatusBadRequest)
		return
	}
	// Solo se permite un nombre de archivo simple dentro de data/:
	// nada de rutas, subdirectorios ni escapes del directorio local.
	name := filepath.Base(req.Name)
	if name != req.Name || !strings.HasSuffix(name, ".jsonl") {
		http.Error(w, "nombre de histórico inválido", http.StatusBadRequest)
		return
	}
	path := filepath.Join(filepath.Dir(a.tailer.Path()), name)
	if _, err := os.Stat(path); err != nil {
		http.Error(w, "ese histórico no existe: "+name, http.StatusNotFound)
		return
	}
	if err := a.tailer.Switch(path); err != nil {
		http.Error(w, "no se pudo abrir el histórico: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.hub.ResetAll()
	a.tailer.Rewind()
	recs, err := a.tailer.Read()
	if err == nil {
		for _, rec := range recs {
			a.hub.Add(rec)
		}
	}
	scanState.mu.Lock()
	scanState.file = path
	scanState.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"file":    path,
		"records": len(recs),
	})
}

// ---- sistema operativo del servidor ----

// handleOS describe el sistema operativo donde corre el panel, para
// mostrarlo con su logo en la web.
func handleOS(w http.ResponseWriter, r *http.Request) {
	name := osName()
	if name == "" {
		switch runtime.GOOS {
		case "windows":
			name = "Windows"
		case "darwin":
			name = "macOS"
		case "linux":
			name = "Linux"
		default:
			name = runtime.GOOS
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"os":   runtime.GOOS,
		"arch": runtime.GOARCH,
		"name": name,
	})
}

// osName devuelve el nombre bonito del sistema operativo (Windows 11,
// macOS 15.1, Ubuntu 24.04…); vacío si no se puede determinar.
func osName() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "ProductName").Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if i := strings.LastIndex(line, "REG_SZ"); i >= 0 {
				return strings.TrimSpace(line[i+len("REG_SZ"):])
			}
		}
	case "darwin":
		if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			return "macOS " + strings.TrimSpace(string(out))
		}
	case "linux":
		if d, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, l := range strings.Split(string(d), "\n") {
				if strings.HasPrefix(l, "PRETTY_NAME=") {
					return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
				}
			}
		}
	}
	return ""
}

// ---- propuestas de escaneo ----

func (a *app) handleSuggest(w http.ResponseWriter, r *http.Request) {
	type item struct {
		Label string `json:"label"`
		Value string `json:"value"`
		Hint  string `json:"hint"`
	}
	var out []item

	if ifaces, err := net.Interfaces(); err == nil {
		seen := map[string]bool{}
		for _, ifc := range ifaces {
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, ad := range addrs {
				ipnet, ok := ad.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipnet.IP.To4()
				if ip4 == nil || !geo.IsPrivate(ip4) {
					continue
				}
				// Se descartan loopback y link-local (169.254), y las
				// redes gigantes se recortan a /24 para que el escaneo
				// propuesto sea rápido.
				if ip4[0] == 127 || ip4[0] == 169 && ip4[1] == 254 {
					continue
				}
				ones, _ := ipnet.Mask.Size()
				if ones < 24 {
					ipnet.Mask = net.CIDRMask(24, 32)
					ones = 24
				}
				// Se muestra la red base (192.168.1.0/24), no la IP del host.
				base := make(net.IP, len(ip4))
				for i := 0; i < 4; i++ {
					base[i] = ip4[i] & ipnet.Mask[i]
				}
				red := fmt.Sprintf("%s/%d", base.To4(), ones)
				if seen[red] {
					continue
				}
				seen[red] = true
				out = append(out, item{
					Label: "Tu red local " + red,
					Value: red,
					Hint:  "todo lo de tu casa: routers, cámaras, NAS, impresoras, PCs",
				})
			}
		}
	}

	if info, err := geo.LookupMyIP(); err == nil && info.AS != "" {
		asn := strings.Fields(info.AS)[0]
		out = append(out, item{
			Label: "Tu operador de internet completo (" + info.ISP + ")",
			Value: "asn:" + asn,
			Hint:  "todo el bloque de IPs de tu proveedor: cámaras, DVR, servidores y cosas expuestas de la zona",
		})
	}

	out = append(out, item{
		Label: "Un dominio o web",
		Value: "",
		Hint:  "cualquier sitio: escribí ejemplo.com y lo analizo",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ---- comentarios por dispositivo ----

var commentsFile = "comments.json"

type commentStore struct {
	mu   sync.Mutex
	data map[string]string
}

func loadComments() *commentStore {
	s := &commentStore{data: map[string]string{}}
	if b, err := os.ReadFile(commentsFile); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	return s
}

func (s *commentStore) save() {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.data)
	_ = os.WriteFile(commentsFile, b, 0o644)
}

func (s *commentStore) handleGet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.data)
}

func (s *commentStore) handleSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key  string `json:"key"`
		Text string `json:"text"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err := json.Unmarshal(body, &req); err != nil || req.Key == "" {
		http.Error(w, "falta key", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" {
		delete(s.data, req.Key)
	} else {
		s.data[req.Key] = req.Text
	}
	s.mu.Unlock()
	s.save()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// ---- análisis con IA (opcional, gratis) ----

type aiConfig struct {
	Provider string `json:"provider"`
	Key      string `json:"key"`
}

var aiConf = struct {
	mu sync.Mutex
	*aiConfig
}{aiConfig: &aiConfig{}}

var aiConfFile = "data/ai_key.json"

func loadAIConf() {
	if b, err := os.ReadFile(aiConfFile); err == nil {
		var c aiConfig
		if json.Unmarshal(b, &c) == nil {
			aiConf.mu.Lock()
			aiConf.aiConfig = &c
			aiConf.mu.Unlock()
		}
	}
}

func saveAIConf() {
	aiConf.mu.Lock()
	b, _ := json.Marshal(aiConf.aiConfig)
	aiConf.mu.Unlock()
	_ = os.WriteFile(aiConfFile, b, 0o600)
}

func (a *app) handleAIConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var c aiConfig
		if err := json.Unmarshal(body, &c); err != nil || (c.Provider != "groq" && c.Provider != "gemini") {
			http.Error(w, "config inválida (provider: groq o gemini)", http.StatusBadRequest)
			return
		}
		c.Key = strings.TrimSpace(c.Key)
		aiConf.mu.Lock()
		aiConf.aiConfig = &c
		aiConf.mu.Unlock()
		saveAIConf()
	}
	aiConf.mu.Lock()
	defer aiConf.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"provider": aiConf.aiConfig.Provider,
		"set":      aiConf.aiConfig.Key != "",
	})
}

// handleAIAnalyze arma un resumen del dispositivo con los datos ya
// capturados (sin abrir nada nuevo) y lo manda al proveedor elegido.
func (a *app) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	aiConf.mu.Lock()
	prov := aiConf.aiConfig.Provider
	key := aiConf.aiConfig.Key
	aiConf.mu.Unlock()
	if key == "" {
		http.Error(w, "no hay clave de IA configurada", http.StatusBadRequest)
		return
	}

	var req struct {
		Key string `json:"key"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	_ = json.Unmarshal(body, &req)
	if req.Key == "" {
		http.Error(w, "falta el identificador del hallazgo (ip:puerto)", http.StatusBadRequest)
		return
	}

	snap := a.hub.Snapshot()
	var recs []map[string]interface{}
	_ = json.Unmarshal(snap, &recs)
	var target map[string]interface{}
	for _, rec := range recs {
		ip, _ := rec["ip"].(string)
		p, _ := rec["port"].(float64)
		if ip+":"+fmt.Sprint(int(p)) == req.Key {
			target = rec
			break
		}
	}
	if target == nil {
		http.Error(w, "ese hallazgo no está en el panel", http.StatusNotFound)
		return
	}

	prompt := "Sos un asistente de ciberseguridad para un escaneo de red con autorización. " +
		"Analizá este hallazgo y respondé en español, breve (máx 10 líneas), con esta estructura: " +
		"1) QUÉ ES: qué servicio/dispositivo parece. 2) SEÑALES: si algo sugiere trampa, honeypot, " +
		"backdoor o configuración peligrosa, decilo. 3) RIESGO: bajo/medio/alto y por qué. " +
		"4) QUÉ HACER: un consejo concreto y seguro. No sugieras acciones ilegales ni exploits. " +
		"Hallazgo (JSON): " + string(mustJSON(target))

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var answer string
	var err error
	switch prov {
	case "groq":
		answer, err = askGroq(ctx, key, prompt)
	case "gemini":
		answer, err = askGemini(ctx, key, prompt)
	default:
		http.Error(w, "proveedor desconocido", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "la IA respondió con error: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"answer": answer})
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func askGroq(ctx context.Context, key, prompt string) (string, error) {
	payload := map[string]interface{}{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  900,
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.groq.com/openai/v1/chat/completions", strings.NewReader(string(mustJSON(payload))))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("groq %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("groq no devolvió respuestas")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

func askGemini(ctx context.Context, key, prompt string) (string, error) {
	payload := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     0.3,
			"maxOutputTokens": 900,
		},
	}
	url := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + key
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(mustJSON(payload))))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	if len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini no devolvió respuestas")
	}
	return strings.TrimSpace(out.Candidates[0].Content.Parts[0].Text), nil
}
