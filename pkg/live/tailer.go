// Package live sigue un archivo de resultados JSONL y difunde los
// registros nuevos a los clientes web suscriptos en tiempo real.
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

// Tailer lee los registros que se agregan a un archivo JSONL, retomando
// desde donde quedó la lectura anterior.
type Tailer struct {
	path   string
	file   *os.File
	offset int64
	mu     sync.Mutex
}

// NewTailer abre el archivo JSONL en path para seguirlo.
func NewTailer(path string) (*Tailer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("abriendo %s: %w", path, err)
	}
	return &Tailer{path: path, file: f}, nil
}

// Close libera el archivo subyacente.
func (t *Tailer) Close() error { return t.file.Close() }

// Rewind hace que la próxima lectura empiece desde el principio.
func (t *Tailer) Rewind() {
	t.mu.Lock()
	t.offset = 0
	t.mu.Unlock()
}

// Read devuelve los registros agregados desde la llamada anterior. Las
// líneas que no son JSON válido se saltan.
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
