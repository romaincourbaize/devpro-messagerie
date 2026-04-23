// Package handler manages the lifecycle of a single peer connection:
//
//  1. Perform the Noise XX handshake.
//  2. Wait for a TypeRegister message.
//  3. Run two concurrent goroutines:
//     - readLoop: decrypt incoming frames → process protocol messages.
//     - writeLoop: drain the client's send channel → encrypt → WebSocket.
//
// The handler is intentionally stateless beyond what is stored in hub.Client
// so it can be unit-tested without a real WebSocket connection.
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/yourname/p2p-relay/internal/hub"
	noiseutil "github.com/yourname/p2p-relay/internal/noise"
	"github.com/yourname/p2p-relay/pkg/protocol"
)

const (
	// pongWait is how long the server waits for a pong before closing.
	pongWait = 60 * time.Second

	// pingInterval must be less than pongWait.
	pingInterval = 50 * time.Second

	// registerTimeout is the budget a client has to send TypeRegister after
	// the Noise handshake completes.
	registerTimeout = 10 * time.Second
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// In production, validate the Origin header here.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Handler holds the shared dependencies injected at startup.
type Handler struct {
	hub    *hub.Hub
	nsCfg  noiseutil.Config
	logger *zap.Logger
}

// New creates a Handler.
func New(h *hub.Hub, noiseCfg noiseutil.Config, logger *zap.Logger) *Handler {
	return &Handler{hub: h, nsCfg: noiseCfg, logger: logger}
}

// ServeWS upgrades an HTTP request to WebSocket and handles the full peer
// lifecycle.  Intended to be called from an http.HandlerFunc.
func (h *Handler) ServeWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("websocket upgrade failed", zap.Error(err))
		return
	}

	ctx := r.Context()

	// ── Noise XX handshake ───────────────────────────────────────────────────
	session, err := noiseutil.AcceptXX(ctx, ws, h.nsCfg)
	if err != nil {
		h.logger.Warn("noise handshake failed",
			zap.String("remote", r.RemoteAddr),
			zap.Error(err),
		)
		_ = ws.Close()
		return
	}

	// Derive the peer's fingerprint from its verified static public key.
	// This is authoritative — the fingerprint in the TypeRegister payload is
	// checked against this value and rejected if it differs.
	rawPub := session.RemoteStatic()
	sum := sha256.Sum256(rawPub)
	serverFingerprint := hex.EncodeToString(sum[:])

	log := h.logger.With(zap.String("fingerprint", serverFingerprint))
	log.Info("noise handshake complete")

	// ── Registration phase ───────────────────────────────────────────────────
	_ = ws.SetReadDeadline(time.Now().Add(registerTimeout))
	plaintext, err := session.Recv()
	if err != nil {
		log.Warn("failed to read register message", zap.Error(err))
		_ = session.Close()
		return
	}
	_ = ws.SetReadDeadline(time.Time{})

	var env protocol.Envelope
	if err := json.Unmarshal(plaintext, &env); err != nil || env.Type != protocol.TypeRegister {
		log.Warn("expected TypeRegister", zap.Error(err))
		_ = session.Close()
		return
	}

	var regPayload protocol.RegisterPayload
	if err := json.Unmarshal(env.Data, &regPayload); err != nil {
		log.Warn("invalid register payload", zap.Error(err))
		_ = session.Close()
		return
	}

	if regPayload.Fingerprint != serverFingerprint {
		log.Warn("fingerprint mismatch",
			zap.String("claimed", regPayload.Fingerprint),
			zap.String("derived", serverFingerprint),
		)
		_ = session.Close()
		return
	}

	// ── Register with the hub ────────────────────────────────────────────────
	client := hub.NewClient(serverFingerprint)
	if err := h.hub.Register(client); err != nil {
		log.Warn("hub register failed", zap.Error(err))
		sendError(session, env.MsgID, err.Error())
		_ = session.Close()
		return
	}

	sendAck(session, env.MsgID)
	log.Info("peer registered with hub")

	defer func() {
		h.hub.Unregister(client)
		client.Close()
		_ = session.Close()
		log.Info("peer disconnected")
	}()

	// ── Concurrent read / write loops ────────────────────────────────────────
	done := make(chan struct{})

	go h.writeLoop(session, client, log, done)
	h.readLoop(session, client, log, done) // blocks until connection closes
}

// ─── Read loop ───────────────────────────────────────────────────────────────

func (h *Handler) readLoop(
	session *noiseutil.Session,
	client *hub.Client,
	log *zap.Logger,
	done chan struct{},
) {
	defer close(done)

	for {
		plaintext, err := session.Recv()
		if err != nil {
			if !isClosedError(err) {
				log.Warn("recv error", zap.Error(err))
			}
			return
		}

		var env protocol.Envelope
		if err := json.Unmarshal(plaintext, &env); err != nil {
			log.Warn("unmarshal error", zap.Error(err))
			continue
		}

		switch env.Type {
		case protocol.TypePing:
			sendPong(session, env.MsgID)

		case protocol.TypeForward:
			h.handleForward(session, client, log, env)

		case protocol.TypePeerStatus:
			h.handlePeerStatus(session, log, env)

		default:
			log.Warn("unknown message type", zap.String("type", string(env.Type)))
		}
	}
}

// handleForward routes a TypeForward message to the target peer.
func (h *Handler) handleForward(
	session *noiseutil.Session,
	client *hub.Client,
	log *zap.Logger,
	env protocol.Envelope,
) {
	if env.To == "" {
		sendError(session, env.MsgID, "missing 'to' field")
		return
	}
	if len(env.Data) == 0 {
		sendError(session, env.MsgID, "missing 'data' field")
		return
	}

	// Build the deliver envelope that the destination will receive.
	deliver, err := marshalEnvelope(protocol.Envelope{
		Type:  protocol.TypeDeliver,
		MsgID: env.MsgID,
		From:  client.Fingerprint,
		Data:  env.Data,
	})
	if err != nil {
		log.Error("marshal deliver envelope", zap.Error(err))
		sendError(session, env.MsgID, "internal error")
		return
	}

	online, err := h.hub.Route(client, env.To, env.MsgID, deliver)
	if err != nil {
		sendError(session, env.MsgID, fmt.Sprintf("delivery failed: %v", err))
		return
	}

	if !online {
		// Inform the sender so it can fall back to the mailbox server.
		sendPeerStatus(session, env.MsgID, env.To, false)
		return
	}

	sendAck(session, env.MsgID)
}

// handlePeerStatus responds to a TypePeerStatus query.
func (h *Handler) handlePeerStatus(
	session *noiseutil.Session,
	log *zap.Logger,
	env protocol.Envelope,
) {
	if env.To == "" {
		sendError(session, env.MsgID, "missing 'to' field")
		return
	}
	online := h.hub.IsOnline(env.To)
	log.Debug("peer status query",
		zap.String("target", env.To),
		zap.Bool("online", online),
	)
	sendPeerStatus(session, env.MsgID, env.To, online)
}

// ─── Write loop ───────────────────────────────────────────────────────────────

func (h *Handler) writeLoop(
	session *noiseutil.Session,
	client *hub.Client,
	log *zap.Logger,
	done <-chan struct{},
) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return

		case msg, ok := <-client.Send:
			if !ok {
				// Hub closed the channel — connection is being torn down.
				return
			}
			if err := session.Send(msg.Payload); err != nil {
				log.Warn("send error", zap.Error(err))
				return
			}

		case <-ticker.C:
			// Application-level ping (distinct from WebSocket ping frames).
			sendPing(session)
		}
	}
}

// ─── Helpers — outbound messages ─────────────────────────────────────────────

func sendAck(s *noiseutil.Session, msgID string) {
	send(s, protocol.Envelope{Type: protocol.TypeAck, MsgID: msgID})
}

func sendError(s *noiseutil.Session, msgID, errMsg string) {
	send(s, protocol.Envelope{Type: protocol.TypeAck, MsgID: msgID, Error: errMsg})
}

func sendPong(s *noiseutil.Session, msgID string) {
	send(s, protocol.Envelope{Type: protocol.TypePong, MsgID: msgID})
}

func sendPing(s *noiseutil.Session) {
	send(s, protocol.Envelope{Type: protocol.TypePing})
}

func sendPeerStatus(s *noiseutil.Session, msgID, fingerprint string, online bool) {
	send(s, protocol.Envelope{
		Type:   protocol.TypePeerStatus,
		MsgID:  msgID,
		To:     fingerprint,
		Online: online,
	})
}

func send(s *noiseutil.Session, env protocol.Envelope) {
	b, err := marshalEnvelope(env)
	if err != nil {
		return
	}
	_ = s.Send(b)
}

func marshalEnvelope(env protocol.Envelope) ([]byte, error) {
	return json.Marshal(env)
}

// ─── Helpers — error classification ──────────────────────────────────────────

func isClosedError(err error) bool {
	return websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
	)
}
