package engine

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"netscanner/pkg/config"
	"netscanner/pkg/exporter"
	"netscanner/pkg/geo"
)

func TestHostCount(t *testing.T) {
	cases := []struct {
		cidr string
		want uint64
	}{
		{"192.168.1.0/24", 254},
		{"10.0.0.0/30", 2},
		{"10.0.0.1/31", 2},
		{"127.0.0.1/32", 1},
		{"0.0.0.0/0", 4294967294},
	}
	for _, c := range cases {
		_, ipnet, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatal(err)
		}
		got, err := HostCount(ipnet)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("HostCount(%s) = %d, want %d", c.cidr, got, c.want)
		}
	}
}

func TestIPsStreamsUsableAddresses(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/30")
	var got []string
	for ip := range IPs(context.Background(), ipnet) {
		got = append(got, ip.String())
	}
	want := []string{"10.0.0.1", "10.0.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IPs = %v, want %v", got, want)
	}
}

func TestIPsSingleHostAndPair(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("127.0.0.1/32")
	var got []string
	for ip := range IPs(context.Background(), ipnet) {
		got = append(got, ip.String())
	}
	if !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Errorf("IPs /32 = %v", got)
	}

	_, ipnet, _ = net.ParseCIDR("192.168.0.0/31")
	got = nil
	for ip := range IPs(context.Background(), ipnet) {
		got = append(got, ip.String())
	}
	if !reflect.DeepEqual(got, []string{"192.168.0.0", "192.168.0.1"}) {
		t.Errorf("IPs /31 = %v", got)
	}
}

func TestIPsCancellation(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("0.0.0.0/0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := IPs(ctx, ipnet)

	seen := 0
	for range ch {
		seen++
		if seen == 5 {
			cancel()
		}
	}
	if seen < 5 {
		t.Errorf("cancelled too early, seen = %d", seen)
	}
}

func TestRunFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("220 FTP banner test\r\n"))
			}(conn)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	opts := &config.Options{
		CIDR:    "127.0.0.1/32",
		Ports:   []int{port},
		Workers: 2,
		Timeout: 1 * time.Second,
	}

	out := make(chan exporter.Result, 8)
	stats, err := Run(context.Background(), opts, geo.Unavailable(), out)
	if err != nil {
		t.Fatal(err)
	}
	close(out)

	var results []exporter.Result
	for r := range out {
		results = append(results, r)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(results))
	}
	if results[0].IP != "127.0.0.1" || results[0].Port != port || results[0].Status != "open" {
		t.Errorf("resultado inesperado: %+v", results[0])
	}
	if results[0].Banner.Raw != "220 FTP banner test" {
		t.Errorf("raw banner = %q", results[0].Banner.Raw)
	}
	if results[0].Geo.Label != "Internal/Private" {
		t.Errorf("geo label = %q, want Internal/Private", results[0].Geo.Label)
	}
	if stats.Open.Load() != 1 {
		t.Errorf("Open = %d, want 1", stats.Open.Load())
	}
}

func TestRunStatsFile(t *testing.T) {
	dir := t.TempDir()
	sf := filepath.Join(dir, "stats.json")
	opts := &config.Options{
		CIDR:      "127.0.0.1/32",
		Ports:     []int{1, 2, 3, 4, 5},
		Workers:   2,
		Timeout:   200 * time.Millisecond,
		StatsFile: sf,
	}
	if _, err := Run(context.Background(), opts, geo.Unavailable(), make(chan exporter.Result, 8)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sf)
	if err != nil {
		t.Fatal(err)
	}
	var snap struct {
		Total    uint64 `json:"total"`
		Attempts uint64 `json:"attempts"`
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Total != 5 || snap.Attempts != 5 {
		t.Errorf("stats = total %d attempts %d, want 5/5", snap.Total, snap.Attempts)
	}
}

func TestRunCancellationIsGraceful(t *testing.T) {
	opts := &config.Options{
		CIDR:    "0.0.0.0/0",
		Ports:   []int{80, 443},
		Workers: 8,
		Timeout: 1 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *Stats, 1)
	go func() {
		s, err := Run(ctx, opts, geo.Unavailable(), make(chan exporter.Result, 16))
		if err != nil {
			done <- nil
			return
		}
		done <- s
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}
