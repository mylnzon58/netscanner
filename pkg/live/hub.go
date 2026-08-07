package live

import (
	"encoding/json"
	"sync"

	"netscanner/pkg/exporter"
)

// Client es una sesión de navegador suscrita al flujo de resultados.
type Client struct {
	ch chan []byte
}

// Hub mantiene el historial reciente de resultados y difunde cada
// registro nuevo a todos los clientes suscriptos.
type Hub struct {
	mu      sync.Mutex
	clients map[*Client]struct{}
	history []exporter.Result
	limit   int
}

// NewHub crea un hub que conserva como máximo limit registros en memoria.
func NewHub(limit int) *Hub {
	return &Hub{clients: make(map[*Client]struct{}), limit: limit}
}

// Add agrega un registro al historial y lo difunde a cada cliente.
func (h *Hub) Add(rec exporter.Result) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.history = append(h.history, rec)
	if len(h.history) > h.limit {
		h.history = h.history[len(h.history)-h.limit:]
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	for c := range h.clients {
		select {
		case c.ch <- data:
		default:
		}
	}
}

// Snapshot devuelve todo el historial en memoria como JSON.
func (h *Hub) Snapshot() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, _ := json.Marshal(h.history)
	return data
}

// Subscribe registra un cliente nuevo y devuelve su canal de eventos.
func (h *Hub) Subscribe() (*Client, <-chan []byte) {
	c := &Client{ch: make(chan []byte, 512)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return c, c.ch
}

// Unsubscribe saca un cliente de la lista de difusión.
func (h *Hub) Unsubscribe(c *Client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}
