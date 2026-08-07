// Package live tails a JSONL results file and broadcasts new records
// to subscribed web clients in real time.
package live

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"netscanner/pkg/exporter"
)

// Tailer reads records appended to a JSONL file, resuming from where
// the previous read stopped.
type Tailer struct {
	path   string
	file   *os.File
	offset int64
	mu     sync.Mutex
}

// NewTailer opens the JSONL file at path for following.
func NewTailer(path string) (*Tailer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &Tailer{path: path, file: f}, nil
}

// Close releases the underlying file.
func (t *Tailer) Close() error { return t.file.Close() }

// Rewind makes the next Read start from the beginning of the file.
func (t *Tailer) Rewind() {
	t.mu.Lock()
	t.offset = 0
	t.mu.Unlock()
}

// Read returns the records appended since the previous call. Lines that
// are not valid JSON are skipped.
func (t *Tailer) Read() ([]exporter.Result, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := t.file.Seek(t.offset, io.SeekStart); err != nil {
		return nil, err
	}
	br := bufio.NewReader(t.file)
	var out []exporter.Result
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 1 {
			var r exporter.Result
			if jerr := json.Unmarshal(line, &r); jerr == nil {
				out = append(out, r)
			}
		}
		if err != nil {
			break
		}
	}
	offset, err := t.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	t.offset = offset
	return out, nil
}
