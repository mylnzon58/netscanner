// Package engine genera las direcciones de un CIDR en streaming y arma
// el pool de workers que ejecuta los sondeos TCP.
package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"netscanner/pkg/banner"
	"netscanner/pkg/config"
	"netscanner/pkg/exporter"
	"netscanner/pkg/geo"
)

type job struct {
	ip   net.IP
	port int
}

// Stats acumula los contadores de una corrida de escaneo. Puede
// compartirse entre varias corridas (múltiples objetivos) para que el
// progreso en vivo sea el global.
type Stats struct {
	Attempts atomic.Uint64
	Open     atomic.Uint64
	Timeout  atomic.Uint64
	Errored  atomic.Uint64
	TotalJob atomic.Uint64 // trabajos totales agregados al escanear

	mu     sync.Mutex
	sample []string // últimas IPs probadas, en orden
}

const sampleN = 48

// Seen registra una dirección recién probada en la muestra de progreso.
func (s *Stats) Seen(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sample = append(s.sample, ip)
	if n := len(s.sample) - sampleN; n > 0 {
		s.sample = append(s.sample[:0], s.sample[n:]...)
	}
}

// Sample devuelve la muestra actual de IPs probadas, de la más vieja a
// la más reciente.
func (s *Stats) Sample() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.sample))
	copy(out, s.sample)
	return out
}

// Snapshot es una copia simple de los contadores, segura de imprimir
// desde cualquier goroutine.
type Snapshot struct {
	Attempts uint64
	Open     uint64
	Timeout  uint64
	Errored  uint64
}

// Snapshot devuelve los valores actuales de los contadores.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		Attempts: s.Attempts.Load(),
		Open:     s.Open.Load(),
		Timeout:  s.Timeout.Load(),
		Errored:  s.Errored.Load(),
	}
}

// HostCount devuelve cuántas direcciones usables hay en ipnet. Las
// redes /31 y /32 usan todas sus direcciones; las más grandes excluyen
// la dirección de red y la de broadcast.
func HostCount(ipnet *net.IPNet) (uint64, error) {
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return 0, errors.New("solo se soportan redes IPv4")
	}
	count := uint64(1) << (32 - ones)
	if ones >= 31 {
		return count, nil
	}
	return count - 2, nil
}

// IPs envía por el canal las direcciones usables de ipnet en streaming.
// La generación se corta apenas se cancela ctx, así el cierre puede
// detener los sondeos sin tener que bufferear todo el rango.
func IPs(ctx context.Context, ipnet *net.IPNet) <-chan net.IP {
	ch := make(chan net.IP, 256)
	go func() {
		defer close(ch)
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return
		}
		first := uint64(binary.BigEndian.Uint32(ipnet.IP.To4()))
		count := uint64(1) << (32 - ones)
		start, end := first, first+count-1
		if ones < 31 {
			start, end = first+1, first+count-2
		}
		for cur := start; ; cur++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, uint32(cur))
			select {
			case <-ctx.Done():
				return
			case ch <- ip:
			}
			if cur == end {
				return
			}
		}
	}()
	return ch
}

// Run ejecuta el escaneo: las direcciones de opts.CIDR entran en
// streaming a un pool de workers acotado por opts.Workers, y cada par
// (ip, puerto) abierto se identifica, se geolocaliza y se manda a out.
//
// Run bloquea hasta sondear todo el rango o hasta que cancelen ctx. Al
// cancelar, el generador deja de mandar trabajos y los dials en vuelo
// (acotados por opts.Timeout) terminan, así el cierre es prolijo.
//
// Si shared no es nil, los contadores se acumulan ahí (útil para
// escanear varios objetivos con un solo progreso global).
func Run(ctx context.Context, opts *config.Options, db *geo.GeoDB, out chan<- exporter.Result, shared *Stats) (*Stats, error) {
	_, ipnet, err := net.ParseCIDR(opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("CIDR inválido %q: %w", opts.CIDR, err)
	}
	hosts, err := HostCount(ipnet)
	if err != nil {
		return nil, err
	}
	if hosts == 0 {
		return nil, fmt.Errorf("la red %s no tiene direcciones usables", opts.CIDR)
	}

	stats := &Stats{}
	if shared != nil {
		stats = shared
	}
	jobCount := hosts * uint64(len(opts.Ports))
	stats.TotalJob.Add(jobCount)
	workers := opts.Workers
	if uint64(workers) > jobCount {
		workers = int(jobCount)
	}
	if workers < 1 {
		workers = 1
	}

	statsDone := make(chan struct{})
	if opts.StatsFile != "" {
		go func() {
			t := time.NewTicker(500 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-statsDone:
					return
				case <-t.C:
					writeStats(opts.StatsFile, jobCount, stats)
				}
			}
		}()
	}

	jobs := make(chan job, workers)
	var wg sync.WaitGroup

	go func() {
		defer close(jobs)
		for ip := range IPs(ctx, ipnet) {
			for _, port := range opts.Ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{ip: ip, port: port}:
				}
			}
		}
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				stats.Attempts.Add(1)
				stats.Seen(j.ip.String())
				conn, err := dial(j, opts.Timeout)
				if err != nil {
					if isTimeout(err) {
						stats.Timeout.Add(1)
					} else {
						stats.Errored.Add(1)
					}
					continue
				}
				stats.Open.Add(1)
				collect(ctx, conn, j, opts, db, out)
			}
		}()
	}

	wg.Wait()
	if opts.StatsFile != "" {
		writeStats(opts.StatsFile, jobCount, stats)
		close(statsDone)
	}
	return stats, nil
}

// writeStats guarda el progreso en vivo de un escaneo para el panel.
func writeStats(path string, total uint64, s *Stats) {
	if s.TotalJob.Load() > total {
		total = s.TotalJob.Load()
	}
	snap := struct {
		Total    uint64   `json:"total"`
		Attempts uint64   `json:"attempts"`
		Open     uint64   `json:"open"`
		Timeouts uint64   `json:"timeouts"`
		Errors   uint64   `json:"errors"`
		Sample   []string `json:"sample"`
		Last     string   `json:"last"`
	}{
		Total:    total,
		Attempts: s.Attempts.Load(),
		Open:     s.Open.Load(),
		Timeouts: s.Timeout.Load(),
		Errors:   s.Errored.Load(),
		Sample:   s.Sample(),
	}
	if n := len(snap.Sample); n > 0 {
		snap.Last = snap.Sample[n-1]
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

// Dialer enruta las conexiones TCP: si es nil, se dialea directo.
var Dialer = struct {
	Dial func(addr string) (net.Conn, error)
}{}

func dial(j job, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(j.ip.String(), strconv.Itoa(j.port))
	if Dialer.Dial != nil {
		return Dialer.Dial(addr)
	}
	return net.DialTimeout("tcp", addr, timeout)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func collect(ctx context.Context, conn net.Conn, j job, opts *config.Options, db *geo.GeoDB, out chan<- exporter.Result) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	info := banner.Info{}
	if isFTPPort(j.port, opts.FTPPorts) {
		fi := banner.ProbeFTP(conn)
		info.Raw = fi.Banner
		info.FTPBanner = fi.Banner
		info.FTPAuth = fi.Auth
	} else {
		info = banner.Probe(conn, j.ip.String(), j.port, opts.MaxBodyBytes)
	}

	if opts.DAV && banner.IsWebPort(j.port) && info.IsHTTP && info.StatusCode != 0 {
		if c2, err := dial(j, opts.Timeout); err == nil {
			_ = c2.SetDeadline(time.Now().Add(opts.Timeout))
			dav, body := banner.ProbeDAV(c2, j.ip.String())
			_ = c2.Close()
			if dav {
				info.DAV = true
				info.DAVBody = body
			}
		}
	}

	loc := db.Lookup(j.ip)

	res := exporter.Result{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        j.ip.String(),
		Port:      j.port,
		Status:    "open",
		Banner: exporter.Banner{
			IsHTTP:     info.IsHTTP,
			StatusCode: info.StatusCode,
			Server:     info.Server,
			Title:      info.Title,
			Raw:        info.Raw,
			Body:       info.Body,
			Headers:    info.Headers,
			Tech:       info.Tech,
			Redirect:   info.Redirect,
			CDN:        geo.ClassifyIP(j.ip.String()),
			FTPAuth:    info.FTPAuth,
			FTPBanner:  info.FTPBanner,
			DAV:        info.DAV,
			DAVBody:    info.DAVBody,
		},
		Geo: exporter.Geo{
			Label:     loc.Label,
			Country:   loc.Country,
			City:      loc.City,
			Latitude:  loc.Latitude,
			Longitude: loc.Longitude,
		},
	}

	select {
	case out <- res:
	case <-ctx.Done():
	}
}

func isFTPPort(port int, ports []int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
