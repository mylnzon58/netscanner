package live

import (
	"encoding/json"
	"sync"

	"netscanner/pkg/exporter"
)

// Client is a single browser session subscribed to the record stream.
type Client struct {
	ch chan []byte
}

// Hub keeps the recent history of results and broadcasts every new
// record to all subscribed clients.
type Hub struct {
	mu      sync.Mutex
	clients map[*Client]struct{}
	history []exporter.Result
	limit   int
}

// NewHub creates a hub keeping at most limit records in memory.
func NewHub(limit int) *Hub {
	return &Hub{clients: make(map[*Client]struct{}), limit: limit}
}

// Add appends a record to the history and broadcasts it to every client.
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

// Snapshot returns the whole in-memory history as JSON.
func (h *Hub) Snapshot() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, _ := json.Marshal(h.history)
	return data
}

// Subscribe registers a new client and returns its event channel.
func (h *Hub) Subscribe() (*Client, <-chan []byte) {
	c := &Client{ch: make(chan []byte, 512)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return c, c.ch
}

// Unsubscribe removes a client from the broadcast list.
func (h *Hub) Unsubscribe(c *Client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}
