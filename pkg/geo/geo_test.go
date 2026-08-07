package geo

import (
	"net"
	"testing"
)

func TestIsPrivate(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.1.1", "192.168.255.254",
		"127.0.0.1",
		"169.254.1.1",
	}
	public := []string{
		"8.8.8.8", "1.1.1.1",
		"172.15.0.1", "172.32.0.1",
		"11.0.0.1", "200.1.2.3",
	}
	for _, s := range private {
		if !IsPrivate(net.ParseIP(s)) {
			t.Errorf("IsPrivate(%s) = false, want true", s)
		}
	}
	for _, s := range public {
		if IsPrivate(net.ParseIP(s)) {
			t.Errorf("IsPrivate(%s) = true, want false", s)
		}
	}
}

func TestLookupWithoutDatabase(t *testing.T) {
	db := Unavailable()
	loc := db.Lookup(net.ParseIP("192.168.1.5"))
	if loc.Label != "Internal/Private" {
		t.Errorf("private label = %q, want Internal/Private", loc.Label)
	}
	loc = db.Lookup(net.ParseIP("8.8.8.8"))
	if loc.Label != "Unknown" {
		t.Errorf("public label without DB = %q, want Unknown", loc.Label)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
}

func TestOpenMissingFileFails(t *testing.T) {
	if _, err := Open("does-not-exist.mmdb"); err == nil {
		t.Error("Open(missing) expected error")
	}
}
