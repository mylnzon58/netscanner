// Package engine implements streaming CIDR address generation and the
// bounded worker pool that performs the TCP probes.
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

// Stats holds the cumulative counters of a scan run.
type Stats struct {
	Attempts atomic.Uint64
	Open     atomic.Uint64
	Timeout  atomic.Uint64
	Errored  atomic.Uint64
}

// Snapshot is a plain copy of the counters, safe to print from any goroutine.
type Snapshot struct {
	Attempts uint64
	Open     uint64
	Timeout  uint64
	Errored  uint64
}

// Snapshot returns the current counter values.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		Attempts: s.Attempts.Load(),
		Open:     s.Open.Load(),
		Timeout:  s.Timeout.Load(),
		Errored:  s.Errored.Load(),
	}
}

// HostCount returns the number of usable host addresses inside ipnet.
// For IPv4 networks /31 and /32 use every address; larger networks
// exclude the network and broadcast addresses.
func HostCount(ipnet *net.IPNet) (uint64, error) {
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return 0, errors.New("only IPv4 networks are supported")
	}
	count := uint64(1) << (32 - ones)
	if ones >= 31 {
		return count, nil
	}
	return count - 2, nil
}

// IPs streams the usable addresses of ipnet through the returned channel.
// Generation stops as soon as ctx is cancelled, which lets a graceful
// shutdown stop probing immediately without buffering the whole range.
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

// Run executes the scan: the addresses of opts.CIDR are streamed into a
// worker pool bounded by opts.Workers, and every open (ip, port) pair is
// fingerprinted, geolocated and sent to out.
//
// Run blocks until the whole range has been probed or ctx is cancelled.
// On cancellation the generator stops feeding new jobs and the in-flight
// dials (each bounded by opts.Timeout) are allowed to finish, which makes
// the shutdown graceful.
func Run(ctx context.Context, opts *config.Options, db *geo.GeoDB, out chan<- exporter.Result) (*Stats, error) {
	_, ipnet, err := net.ParseCIDR(opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", opts.CIDR, err)
	}
	hosts, err := HostCount(ipnet)
	if err != nil {
		return nil, err
	}
	if hosts == 0 {
		return nil, fmt.Errorf("network %s has no usable host addresses", opts.CIDR)
	}

	stats := &Stats{}

	jobCount := hosts * uint64(len(opts.Ports))
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

// writeStats persists the live progress of a scan for the dashboard.
func writeStats(path string, total uint64, s *Stats) {
	snap := struct {
		Total    uint64 `json:"total"`
		Attempts uint64 `json:"attempts"`
		Open     uint64 `json:"open"`
		Timeouts uint64 `json:"timeouts"`
		Errors   uint64 `json:"errors"`
	}{
		Total:    total,
		Attempts: s.Attempts.Load(),
		Open:     s.Open.Load(),
		Timeouts: s.Timeout.Load(),
		Errors:   s.Errored.Load(),
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

// Dialer routes TCP connections: nil means direct dialing.
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
