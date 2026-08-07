// Package exporter writes scan results to disk in JSON Lines format
// through a dedicated I/O goroutine.
package exporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

const bufSize = 64 * 1024

// Banner is the fingerprint of the service behind an open port.
type Banner struct {
	IsHTTP     bool   `json:"http"`
	StatusCode int    `json:"status_code"`
	Server     string `json:"server"`
	Title      string `json:"title"`
	Raw        string `json:"raw"`
	Body       string `json:"body,omitempty"`
	FTPAuth    string `json:"ftp_auth,omitempty"`
	FTPBanner  string `json:"ftp_banner,omitempty"`
	DAV        bool   `json:"dav,omitempty"`
	DAVBody    string `json:"dav_body,omitempty"`
}

// Geo is the location data of the scanned address. ISP, ASN and Org
// are filled only when an online enrichment pass runs.
type Geo struct {
	Label     string  `json:"label"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp,omitempty"`
	ASN       string  `json:"asn,omitempty"`
	Org       string  `json:"org,omitempty"`
}

// Result is one JSONL record: a single open (ip, port) pair.
type Result struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Status    string `json:"status"`
	Banner    Banner `json:"banner"`
	Geo       Geo    `json:"geo"`
}

// Writer drains a results channel on a single I/O goroutine and writes
// JSONL records to the output file in large buffered chunks.
type Writer struct {
	ch   chan Result
	file *os.File
	bw   *bufio.Writer
	wg   sync.WaitGroup
	mu   sync.Mutex
	err  error
}

// NewWriter opens (or appends to) the file at path and starts the
// dedicated I/O goroutine. buffer is the size of the results channel.
func NewWriter(path string, buffer int) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}
	w := &Writer{
		ch:   make(chan Result, buffer),
		file: f,
		bw:   bufio.NewWriterSize(f, bufSize),
	}
	w.wg.Add(1)
	go w.loop()
	return w, nil
}

func (w *Writer) loop() {
	defer w.wg.Done()
	enc := json.NewEncoder(w.bw)
	for r := range w.ch {
		if err := enc.Encode(r); err != nil {
			w.mu.Lock()
			w.err = err
			w.mu.Unlock()
			return
		}
	}
}

// Results returns the channel where scan results must be sent.
func (w *Writer) Results() chan<- Result { return w.ch }

// Close stops the I/O goroutine, flushes every buffered record to disk
// and closes the file. It must be called exactly once.
func (w *Writer) Close() error {
	close(w.ch)
	w.wg.Wait()
	flushErr := w.bw.Flush()
	closeErr := w.file.Close()
	w.mu.Lock()
	ioErr := w.err
	w.mu.Unlock()
	switch {
	case ioErr != nil:
		return ioErr
	case flushErr != nil:
		return flushErr
	default:
		return closeErr
	}
}
