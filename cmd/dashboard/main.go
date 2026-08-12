// El comando dashboard es un visor web en vivo de los resultados
// JSONL de netscanner.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"netscanner/pkg/banner"
	"netscanner/pkg/geo"
	"netscanner/pkg/live"
	"netscanner/pkg/socks"
)

//go:embed index.html
var indexHTML []byte

func main() {
	file := flag.String("file", "results.jsonl", "archivo JSONL de resultados a vigilar")
	addr := flag.String("addr", "127.0.0.1:8080", "dirección de escucha del panel web")
	limit := flag.Int("limit", 5000, "máximo de registros retenidos en memoria")
	poll := flag.Duration("poll", 500*time.Millisecond, "intervalo de revisión del archivo")
	statsFile := flag.String("stats", "", "archivo de progreso del escáner para el panel en vivo (opcional)")
	proxySpec := flag.String("proxy", "", "mandar /proxy y /ftplist por un proxy SOCKS5 (p.ej. socks5://127.0.0.1:9050)")
	flag.Parse()

	if *limit < 100 {
		*limit = 100
	}

	proxy, err := socks.NewDialer(*proxySpec, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if proxy != nil {
		banner.DialTCP = func(addr string, timeout time.Duration) (net.Conn, error) {
			return proxy.Dial(addr)
		}
		proxyTransport := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return proxy.Dial(addr)
			},
			DisableKeepAlives: true,
		}
		proxyClient = &http.Client{Transport: proxyTransport, Timeout: 12 * time.Second}
		fmt.Fprintf(os.Stderr, "[dashboard] proxy SOCKS5 activo: %s (proxy/ftplist anónimos)\n", proxy.URL())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Si el archivo indicado está vacío o no existe, abrir el JSONL de
	// resultados más reciente del directorio: el panel siempre muestra
	// el último escaneo, aunque se reinicie.
	if fi, err := os.Stat(*file); err != nil || fi.Size() == 0 {
		if newest := newestJSONL(filepath.Dir(*file)); newest != "" && newest != *file {
			fmt.Fprintf(os.Stderr, "[dashboard] %s vacío o inexistente; usando %s\n", *file, newest)
			*file = newest
		}
	}

	tailer, err := openTailerRetry(*file, ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer tailer.Close()

	hub := live.NewHub(*limit)
	tailer.Rewind()
	if initial, err := tailer.Read(); err == nil {
		for _, r := range initial {
			hub.Add(r)
		}
	}

	loadCommentsRef := loadComments()
	loadAIConf()
	app := &app{tailer: tailer, hub: hub}

	go func() {
		t := time.NewTicker(*poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				recs, err := tailer.Read()
				if err != nil {
					continue
				}
				for _, r := range recs {
					hub.Add(r)
				}
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		handleEvents(hub, w, r)
	})
	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(hub.Snapshot())
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		handleStats(w, r, *statsFile)
	})
	mux.HandleFunc("/proxy", handleProxy)
	mux.HandleFunc("/myip", handleMyIP)
	mux.HandleFunc("/ftplist", handleFTPList)
	mux.HandleFunc("/lookup", handleLookup)
	mux.HandleFunc("/shodan", handleShodan)
	mux.HandleFunc("/iplookup", handleIPLookup)
	mux.HandleFunc("/scan", app.handleScan)
	mux.HandleFunc("/scanstop", app.handleScanStop)
	mux.HandleFunc("/scanstatus", app.handleScanStatus)
	mux.HandleFunc("/suggest", app.handleSuggest)
	mux.HandleFunc("/comments", loadCommentsRef.handleGet)
	mux.HandleFunc("/comments/set", loadCommentsRef.handleSet)
	mux.HandleFunc("/ai/config", app.handleAIConfig)
	mux.HandleFunc("/ai/analyze", app.handleAIAnalyze)

	srv := &http.Server{Addr: *addr, Handler: mux}
	go func() {
		fmt.Fprintf(os.Stderr, "[dashboard] vigilando %s en http://%s\n", *file, *addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "error del servidor:", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

// newestJSONL devuelve el archivo .jsonl con modificación más reciente
// del directorio (ignorando vacíos), o "" si no hay ninguno.
func newestJSONL(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var newest string
	var newestAt time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		fi, err := e.Info()
		if err != nil || fi.Size() == 0 {
			continue
		}
		if fi.ModTime().After(newestAt) {
			newestAt = fi.ModTime()
			newest = filepath.Join(dir, e.Name())
		}
	}
	return newest
}

func openTailerRetry(path string, ctx context.Context) (*live.Tailer, error) {
	for {
		t, err := live.NewTailer(path)
		if err == nil {
			return t, nil
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(1 * time.Second):
			fmt.Fprintf(os.Stderr, "[dashboard] esperando %s...\n", path)
		}
	}
}

var statsCache struct {
	mu   sync.Mutex
	at   time.Time
	data []byte
}

// handleStats sirve el archivo de progreso del escáner con caché corta.
func handleStats(w http.ResponseWriter, r *http.Request, path string) {
	if path == "" {
		http.NotFound(w, r)
		return
	}
	statsCache.mu.Lock()
	defer statsCache.mu.Unlock()
	if time.Since(statsCache.at) > 250*time.Millisecond {
		if d, err := os.ReadFile(path); err == nil {
			statsCache.data = d
		} else if len(statsCache.data) == 0 {
			statsCache.data = []byte("{}")
		}
		statsCache.at = time.Now()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(statsCache.data)
}

const maxProxyBytes = 2 << 20

var proxyClient = http.DefaultClient

// handleProxy baja una página o imagen de un host escaneado para que el
// panel pueda mostrarla inline.
func handleProxy(w http.ResponseWriter, r *http.Request) {
	p, err := url.Parse(r.URL.Query().Get("u"))
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		http.Error(w, "url inválida", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.String(), nil)
	if err != nil {
		http.Error(w, "pedido inválido", http.StatusBadRequest)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36")
	resp, err := proxyClient.Do(req)
	if err != nil {
		http.Error(w, "no se pudo descargar", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.CopyN(w, resp.Body, maxProxyBytes)
}

// handleLookup resuelve un hostname a sus direcciones IP (DNS).
func handleLookup(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" || len(host) > 255 {
		http.Error(w, "pedido inválido", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		http.Error(w, "dns: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"host": host, "ips": ips})
}

// handleShodan consulta el Shodan InternetDB público (sin API key) por
// los puertos y servicios que están indexados para una IP.
func handleShodan(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "pedido inválido", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://internetdb.shodan.io/"+ip, nil)
	if err != nil {
		http.Error(w, "pedido inválido", http.StatusBadRequest)
		return
	}
	req.Header.Set("Accept", "application/json")
	resp, err := proxyClient.Do(req)
	if err != nil {
		http.Error(w, "shodan: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleIPLookup resuelve el ISP y la ciudad de una IP con ip-api.com
// (con caché de 10 minutos por IP).
var ipLookupCache = struct {
	mu   sync.Mutex
	data map[string]json.RawMessage
	at   map[string]time.Time
}{data: make(map[string]json.RawMessage), at: make(map[string]time.Time)}

func handleIPLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "pedido inválido", http.StatusBadRequest)
		return
	}
	ipLookupCache.mu.Lock()
	defer ipLookupCache.mu.Unlock()
	if d, ok := ipLookupCache.data[ip]; ok && time.Since(ipLookupCache.at[ip]) < 10*time.Minute {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(d)
		return
	}
	info, err := geo.LookupOnline([]string{ip})
	if err != nil || len(info) == 0 {
		http.Error(w, "no disponible", http.StatusBadGateway)
		return
	}
	d, err := json.Marshal(info[ip])
	if err != nil {
		http.Error(w, "no disponible", http.StatusInternalServerError)
		return
	}
	ipLookupCache.data[ip] = d
	ipLookupCache.at[ip] = time.Now()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(d)
}

var myipCache struct {
	mu   sync.Mutex
	at   time.Time
	data []byte
}

// handleMyIP resuelve la dirección pública y el ISP de quien consulta
// con ip-api.com, con caché de 10 minutos.
func handleMyIP(w http.ResponseWriter, r *http.Request) {
	myipCache.mu.Lock()
	defer myipCache.mu.Unlock()
	if time.Since(myipCache.at) > 10*time.Minute {
		info, err := geo.LookupMyIP()
		if err != nil {
			http.Error(w, "no disponible", http.StatusBadGateway)
			return
		}
		d, err := json.Marshal(info)
		if err != nil {
			http.Error(w, "no disponible", http.StatusInternalServerError)
			return
		}
		myipCache.data = d
		myipCache.at = time.Now()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(myipCache.data)
}

type ftpListEntry struct {
	at    time.Time
	files []string
}

var ftpListCache = struct {
	mu   sync.Mutex
	data map[string]ftpListEntry
}{data: make(map[string]ftpListEntry)}

// handleFTPList lista un directorio FTP anónimo (GET /ftplist?ip=X&port=Y),
// con caché por host de 30 segundos.
func handleFTPList(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	if err != nil || ip == "" || port < 1 || port > 65535 {
		http.Error(w, "pedido inválido", http.StatusBadRequest)
		return
	}
	key := ip + ":" + strconv.Itoa(port)
	ftpListCache.mu.Lock()
	defer ftpListCache.mu.Unlock()
	entry, ok := ftpListCache.data[key]
	if !ok || time.Since(entry.at) > 30*time.Second {
		files, err := banner.FTPList(ip, port, 6*time.Second)
		if err != nil {
			http.Error(w, "ftp: "+err.Error(), http.StatusBadGateway)
			return
		}
		entry = ftpListEntry{at: time.Now(), files: files}
		ftpListCache.data[key] = entry
	}
	w.Header().Set("Content-Type", "application/json")
	body, _ := json.Marshal(map[string]interface{}{
		"files": entry.files,
	})
	_, _ = w.Write(body)
}

func handleEvents(hub *live.Hub, w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming no soportado", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	if snap := hub.Snapshot(); len(snap) > 0 {
		fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", snap)
		flusher.Flush()
	}

	client, ch := hub.Subscribe()
	defer hub.Unsubscribe(client)

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
