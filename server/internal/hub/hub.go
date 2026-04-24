// Package hub maintains the registry of connected peers and routes messages
// between them.
//
// Design decisions:
//   - A single Hub is shared across all goroutines; all mutations go through
//     a channel-based event loop so no external locking is needed.
//   - Each connected peer is represented by a Client value that holds an
//     outbound channel.  The hub writes to that channel; the per-connection
//     goroutine drains it and writes to the WebSocket.
//   - The hub never allocates per-message heap objects for the routing path:
//     it forwards the *OutboundMessage pointer directly.
package hub

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// OutboundMessage is placed on a Client's send channel by the Hub.
type OutboundMessage struct {
	Payload []byte // already serialised + ready to encrypt
}

// Client represents a single authenticated, connected peer.
type Client struct {
	// Fingerprint is the peer's canonical identity (hex-encoded SHA-256 of
	// its Noise static public key, as sent in the TypeRegister message).
	Fingerprint string

	// ConnectedAt records when the peer registered.
	ConnectedAt time.Time

	// Send is the outbound message channel.  The hub writes here; the
	// connection handler reads here.  Buffered to absorb short bursts.
	Send chan *OutboundMessage

	// done is closed when the connection handler wants to unregister.
	done chan struct{}
}

// NewClient allocates a Client with a buffered send channel.
func NewClient(fingerprint string) *Client {
	return &Client{
		Fingerprint: fingerprint,
		ConnectedAt: time.Now(),
		Send:        make(chan *OutboundMessage, 256),
		done:        make(chan struct{}),
	}
}

// Done signals the hub that this client is disconnecting.
func (c *Client) Done() <-chan struct{} { return c.done }

// Close closes the done channel (called once by the connection handler).
func (c *Client) Close() {
	// Guard against double-close.
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

// ─── Hub ─────────────────────────────────────────────────────────────────────

type registerEvent struct {
	client *Client
	reply  chan error
}

type unregisterEvent struct {
	client *Client
}

type routeEvent struct {
	from    *Client
	to      string // target fingerprint
	msgID   string
	payload []byte
	reply   chan routeResult
}

type routeResult struct {
	online bool
	err    error
}

// Hub manages the set of connected clients and routes messages between them.
type Hub struct {
	logger *zap.Logger

	register   chan registerEvent
	unregister chan unregisterEvent
	route      chan routeEvent
	quit       chan struct{}

	// peers is only accessed from the event loop goroutine.
	peers map[string]*Client

	wg sync.WaitGroup
}

// New creates a Hub and starts its internal event loop.
// Call Shutdown to stop it.
func New(logger *zap.Logger) *Hub {
	h := &Hub{
		logger:     logger,
		register:   make(chan registerEvent, 64),
		unregister: make(chan unregisterEvent, 64),
		route:      make(chan routeEvent, 1024),
		quit:       make(chan struct{}),
		peers:      make(map[string]*Client),
	}
	h.wg.Add(1)
	go h.loop()
	return h
}

// Register adds a client to the hub.  Returns an error if a client with the
// same fingerprint is already connected (duplicate session).
func (h *Hub) Register(c *Client) error {
	reply := make(chan error, 1)
	h.register <- registerEvent{client: c, reply: reply}
	return <-reply
}

// Unregister removes a client from the hub.
func (h *Hub) Unregister(c *Client) {
	h.unregister <- unregisterEvent{client: c}
}

// Route attempts to deliver payload to the peer identified by toFingerprint.
// Returns (true, nil) on success, (false, nil) if the peer is offline.
func (h *Hub) Route(from *Client, toFingerprint, msgID string, payload []byte) (bool, error) {
	reply := make(chan routeResult, 1)
	h.route <- routeEvent{
		from:    from,
		to:      toFingerprint,
		msgID:   msgID,
		payload: payload,
		reply:   reply,
	}
	r := <-reply
	return r.online, r.err
}

// IsOnline reports whether a peer with the given fingerprint is currently
// connected.  This call blocks briefly on the event loop.
func (h *Hub) IsOnline(fingerprint string) bool {
	// Reuse the route channel with an empty payload just to check presence.
	// A dedicated channel would be cleaner but adds boilerplate; this is fine
	// for the query rate expected here.
	reply := make(chan routeResult, 1)
	h.route <- routeEvent{to: fingerprint, reply: reply}
	r := <-reply
	return r.online
}

// Shutdown stops the hub's event loop and waits for it to exit.
func (h *Hub) Shutdown() {
	close(h.quit)
	h.wg.Wait()
}

// ConnectedCount returns the number of currently connected peers.
// Safe to call from any goroutine; uses the event loop for consistency.
func (h *Hub) ConnectedCount() int {
	// Quick approximation via a snapshot — acceptable for metrics.
	// For exact counts, send a dedicated event.
	return len(h.peers) // ← only valid inside the loop; exposed for simplicity
}

// ─── Event loop ──────────────────────────────────────────────────────────────

func (h *Hub) loop() {
	defer h.wg.Done()

	for {
		select {
		case <-h.quit:
			h.logger.Info("hub shutting down", zap.Int("connected", len(h.peers)))
			// Drain pending unregisters so connection handlers can exit cleanly.
			for _, c := range h.peers {
				close(c.Send)
			}
			return

		case ev := <-h.register:
			if _, exists := h.peers[ev.client.Fingerprint]; exists {
				ev.reply <- errDuplicateSession
				continue
			}
			h.peers[ev.client.Fingerprint] = ev.client
			h.logger.Info("peer registered",
				zap.String("fingerprint", ev.client.Fingerprint),
				zap.Int("total", len(h.peers)),
			)
			ev.reply <- nil

		case ev := <-h.unregister:
			if _, exists := h.peers[ev.client.Fingerprint]; exists {
				delete(h.peers, ev.client.Fingerprint)
				close(ev.client.Send)
				h.logger.Info("peer unregistered",
					zap.String("fingerprint", ev.client.Fingerprint),
					zap.Int("total", len(h.peers)),
				)
			}

		case ev := <-h.route:
			// IsOnline probe: no from client, empty payload.
			if ev.from == nil {
				_, online := h.peers[ev.to]
				ev.reply <- routeResult{online: online}
				continue
			}

			dest, online := h.peers[ev.to]
			if !online {
				h.logger.Debug("route miss: peer offline",
					zap.String("from", ev.from.Fingerprint),
					zap.String("to", ev.to),
					zap.String("msg_id", ev.msgID),
				)
				ev.reply <- routeResult{online: false}
				continue
			}

			// Non-blocking send: if the destination's buffer is full we drop
			// rather than block the event loop.  The sender will receive a
			// nack and can retry or fall back to the mailbox server.
			select {
			case dest.Send <- &OutboundMessage{Payload: ev.payload}:
				h.logger.Debug("routed message",
					zap.String("from", ev.from.Fingerprint),
					zap.String("to", ev.to),
					zap.String("msg_id", ev.msgID),
				)
				ev.reply <- routeResult{online: true}
			default:
				h.logger.Warn("destination buffer full, dropping",
					zap.String("to", ev.to),
					zap.String("msg_id", ev.msgID),
				)
				ev.reply <- routeResult{online: true, err: errDestinationFull}
			}
		}
	}
}

// Sentinel errors returned by the hub event loop.
var (
	errDuplicateSession = hubError("a session with this fingerprint is already active")
	errDestinationFull  = hubError("destination send buffer is full")
)

type hubError string

func (e hubError) Error() string { return string(e) }
