package live

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"netscanner/pkg/exporter"
)

func rec(ip string, port int) exporter.Result {
	return exporter.Result{
		Timestamp: "2026-01-01T00:00:00Z",
		IP:        ip,
		Port:      port,
		Status:    "open",
		Banner:    exporter.Banner{IsHTTP: true, StatusCode: 200, Server: "s", Title: "t"},
		Geo:       exporter.Geo{Label: "Internal/Private"},
	}
}

func TestTailerFollowsAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	line := `{"timestamp":"2026-01-01T00:00:00Z","ip":"1.1.1.1","port":80,"status":"open","banner":{"http":true},"geo":{"label":"Public"}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	tl, err := NewTailer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	tl.Rewind()

	recs, err := tl.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Port != 80 {
		t.Fatalf("initial read = %+v", recs)
	}

	more := `{"timestamp":"2026-01-01T00:00:01Z","ip":"1.1.1.1","port":443,"status":"open","banner":{"http":true},"geo":{"label":"Public"}}` + "\n" +
		"this is not valid json\n" +
		`{"timestamp":"2026-01-01T00:00:02Z","ip":"1.1.1.1","port":22,"status":"open","banner":{},"geo":{}}` + "\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(more); err != nil {
		t.Fatal(err)
	}
	f.Close()

	recs, err = tl.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Port != 443 || recs[1].Port != 22 {
		t.Fatalf("follow read = %+v", recs)
	}
}

func TestTailerMissingFile(t *testing.T) {
	if _, err := NewTailer(filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestHubBroadcastAndSnapshot(t *testing.T) {
	h := NewHub(100)
	h.Add(rec("1.1.1.1", 80))
	h.Add(rec("1.1.1.1", 443))

	var snap []exporter.Result
	if err := json.Unmarshal(h.Snapshot(), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d", len(snap))
	}

	c, ch := h.Subscribe()
	h.Add(rec("1.1.1.1", 22))
	select {
	case f := <-ch:
		if f.Event != "" {
			t.Fatalf("expected record frame, got event %q", f.Event)
		}
		var r exporter.Result
		if err := json.Unmarshal(f.Data, &r); err != nil {
			t.Fatal(err)
		}
		if r.Port != 22 {
			t.Errorf("broadcast port = %d", r.Port)
		}
	default:
		t.Fatal("expected broadcast event")
	}
	h.Unsubscribe(c)

	h.Add(rec("1.1.1.1", 21))
	select {
	case <-ch:
		t.Error("unsubscribed client still receives events")
	default:
	}
}

func TestHubResetAll(t *testing.T) {
	h := NewHub(10)
	h.Add(rec("1.1.1.1", 80))
	c, ch := h.Subscribe()
	h.ResetAll()
	var snap []exporter.Result
	if err := json.Unmarshal(h.Snapshot(), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap) != 0 {
		t.Fatalf("history after ResetAll = %+v", snap)
	}
	select {
	case f := <-ch:
		if f.Event != "reset" {
			t.Fatalf("expected reset event, got %q", f.Event)
		}
	default:
		t.Fatal("expected reset broadcast")
	}
	_ = c
}

func TestHubHistoryLimit(t *testing.T) {
	h := NewHub(2)
	for i := 0; i < 5; i++ {
		h.Add(rec("1.1.1.1", 80+i))
	}
	var snap []exporter.Result
	if err := json.Unmarshal(h.Snapshot(), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap) != 2 || snap[0].Port != 83 || snap[1].Port != 84 {
		t.Fatalf("limited history = %+v", snap)
	}
}
