package live

import (
	"encoding/json"
	"sync"

	"netscanner/pkg/exporter"
)

// Frame es un mensaje difundido a los clientes: Event vacío es un
// registro nuevo; "reset" avisa que el panel debe vaciarse.
type Frame struct {
	Event string
	Data  []byte
}

// Client es una sesión de navegador suscrita al flujo de resultados.
type Client struct {
	ch chan Frame
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

// broadcast manda un frame a cada cliente sin bloquear.
func (h *Hub) broadcast(f Frame) {
	for c := range h.clients {
		select {
		case c.ch <- f:
		default:
		}
	}
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
	h.broadcast(Frame{Data: data})
}

// Snapshot devuelve todo el historial en memoria como JSON.
func (h *Hub) Snapshot() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, _ := json.Marshal(h.history)
	return data
}

// Reset vacía el historial, para empezar un escaneo nuevo desde cero.
func (h *Hub) Reset() {
	h.mu.Lock()
	h.history = nil
	h.mu.Unlock()
}

// ResetAll vacía el historial y además les avisa a los navegadores
// conectados que deben borrar lo que muestran: al escanear un objetivo
// nuevo no quedan resultados de escaneos anteriores.
func (h *Hub) ResetAll() {
	h.Reset()
	h.broadcast(Frame{Event: "reset"})
}

// Subscribe registra un cliente nuevo y devuelve su canal de eventos.
func (h *Hub) Subscribe() (*Client, <-chan Frame) {
	c := &Client{ch: make(chan Frame, 512)}
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
