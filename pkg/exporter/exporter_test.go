package exporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterProducesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	w, err := NewWriter(path, 8)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		w.Results() <- Result{
			Timestamp: "2026-01-01T00:00:00Z",
			IP:        "10.0.0.1",
			Port:      80 + i,
			Status:    "open",
			Banner:    Banner{IsHTTP: true, StatusCode: 200, Server: "nginx", Title: "t", Raw: "r"},
			Geo:       Geo{Label: "Internal/Private"},
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 JSONL lines, got %d", len(lines))
	}
	for i, ln := range lines {
		var r Result
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if r.IP != "10.0.0.1" || r.Port != 80+i {
			t.Errorf("line %d fields: %+v", i, r)
		}
	}
}

func TestWriterAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	w, err := NewWriter(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	w.Results() <- Result{IP: "1.1.1.1", Port: 80, Status: "open"}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w, err = NewWriter(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	w.Results() <- Result{IP: "1.1.1.1", Port: 443, Status: "open"}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if got := strings.Count(string(data), "\n"); got != 2 {
		t.Errorf("expected 2 lines after append, got %d", got)
	}
}

func TestWriterBadPath(t *testing.T) {
	if _, err := NewWriter(filepath.Join(t.TempDir(), "no", "dir", "out.jsonl"), 4); err == nil {
		t.Error("NewWriter with missing directory: expected error")
	}
}
