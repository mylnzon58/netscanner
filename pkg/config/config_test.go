package config

import (
	"reflect"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	o, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.CIDR != DefaultCIDR {
		t.Errorf("CIDR = %q, want %q", o.CIDR, DefaultCIDR)
	}
	wantPorts := []int{21, 22, 80, 443, 554, 8000, 8080}
	if !reflect.DeepEqual(o.Ports, wantPorts) {
		t.Errorf("Ports = %v, want %v", o.Ports, wantPorts)
	}
	if o.Workers != DefaultWorkers {
		t.Errorf("Workers = %d, want %d", o.Workers, DefaultWorkers)
	}
	if o.Timeout != 2000*time.Millisecond {
		t.Errorf("Timeout = %v, want 2s", o.Timeout)
	}
	if o.GeoIPPath != DefaultGeoIPPath {
		t.Errorf("GeoIPPath = %q, want %q", o.GeoIPPath, DefaultGeoIPPath)
	}
	if o.Output != DefaultOutput {
		t.Errorf("Output = %q, want %q", o.Output, DefaultOutput)
	}
	if o.MaxBodyKB != DefaultMaxBodyKB || o.MaxBodyBytes != DefaultMaxBodyKB*1024 {
		t.Errorf("MaxBody = %d/%d", o.MaxBodyKB, o.MaxBodyBytes)
	}
	if o.StatsFile != "" {
		t.Errorf("StatsFile = %q, want empty", o.StatsFile)
	}
}

func TestParseCustomAndShorthands(t *testing.T) {
	o, err := Parse([]string{
		"-c", "10.0.0.0/30",
		"-p", "80,80,443,8080",
		"-w", "10",
		"-t", "500",
		"-g", "geo.mmdb",
		"-o", "out.jsonl",
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.CIDR != "10.0.0.0/30" {
		t.Errorf("CIDR = %q", o.CIDR)
	}
	wantPorts := []int{80, 443, 8080}
	if !reflect.DeepEqual(o.Ports, wantPorts) {
		t.Errorf("Ports = %v, want %v (dedupe+sorted)", o.Ports, wantPorts)
	}
	if o.Workers != 10 || o.Timeout != 500*time.Millisecond {
		t.Errorf("Workers=%d Timeout=%v", o.Workers, o.Timeout)
	}
	if o.GeoIPPath != "geo.mmdb" || o.Output != "out.jsonl" {
		t.Errorf("GeoIPPath=%q Output=%q", o.GeoIPPath, o.Output)
	}
}

func TestParseLongFlags(t *testing.T) {
	o, err := Parse([]string{"--cidr", "192.168.2.0/24", "--ports", "22", "--workers", "1", "--timeout", "100", "--geoip", "x.mmdb", "--output", "y.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if o.CIDR != "192.168.2.0/24" || !reflect.DeepEqual(o.Ports, []int{22}) || o.Workers != 1 {
		t.Errorf("opciones inesperadas: %+v", o)
	}
}

func TestParseInvalid(t *testing.T) {
	cases := [][]string{
		{"-c", "2001:db8::/64"},
		{"-p", "99999"},
		{"-p", "abc"},
		{"-p", ","},
		{"-w", "0"},
		{"-w", "-3"},
		{"-t", "5"},
		{"--max-body", "9999"},
		{"positional-arg"},
	}
	for _, args := range cases {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%v): expected error, got nil", args)
		}
	}
}
