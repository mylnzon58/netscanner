// Package exporter escribe los resultados a disco en formato JSON
// Lines desde una goroutine dedicada de I/O.
package exporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

const bufSize = 64 * 1024

// Banner es la huella del servicio que hay detrás de un puerto abierto.
type Banner struct {
	IsHTTP     bool              `json:"http"`
	StatusCode int               `json:"status_code"`
	Server     string            `json:"server"`
	Title      string            `json:"title"`
	Raw        string            `json:"raw"`
	Body       string            `json:"body,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Tech       []string          `json:"tech,omitempty"`
	Redirect   string            `json:"redirect,omitempty"`
	CDN        string            `json:"cdn,omitempty"`
	FTPAuth    string            `json:"ftp_auth,omitempty"`
	FTPBanner  string            `json:"ftp_banner,omitempty"`
	DAV        bool              `json:"dav,omitempty"`
	DAVBody    string            `json:"dav_body,omitempty"`
}

// Geo es la ubicación de la dirección escaneada. ISP, ASN y Org solo se
// completan cuando corre una pasada de enriquecimiento online.
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

// Result es un registro JSONL: un par (ip, puerto) abierto.
type Result struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Status    string `json:"status"`
	Banner    Banner `json:"banner"`
	Geo       Geo    `json:"geo"`
}

// Writer drena un canal de resultados en una sola goroutine de I/O y
// escribe los registros JSONL en chunks grandes con buffer.
type Writer struct {
	ch   chan Result
	file *os.File
	bw   *bufio.Writer
	wg   sync.WaitGroup
	mu   sync.Mutex
	err  error
}

// NewWriter abre (o agrega al final de) el archivo en path y arranca la
// goroutine de I/O. buffer es el tamaño del canal de resultados.
func NewWriter(path string, buffer int) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("abriendo el archivo de salida: %w", err)
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

// Results devuelve el canal por donde hay que mandar los resultados.
func (w *Writer) Results() chan<- Result { return w.ch }

// Close frena la goroutine de I/O, descarga todos los registros
// pendientes a disco y cierra el archivo. Solo se llama una vez.
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
