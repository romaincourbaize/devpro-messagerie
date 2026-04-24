// Package noise wraps the flynn/noise library to provide a clean
// Noise_XX_25519_ChaChaPoly_BLAKE2s session over a WebSocket connection.
//
// Pattern XX (→ e, ←  e ee s es, →  s se) gives:
//   - Mutual authentication     — both sides authenticate each other.
//   - Forward secrecy           — ephemeral keys are discarded after the
//     handshake; past sessions cannot be decrypted.
//   - Identity hiding           — the responder's static key is encrypted
//     before it leaves the wire.
//
// Usage (server side):
//
//	cfg, err := noise.NewServerConfig(staticPrivKey)
//	session, err := noise.AcceptXX(ctx, wsConn, cfg)
//	// session.RemoteStatic() — peer's verified static public key
//	// session.Send(plaintext) / session.Recv() — encrypted transport
package noise

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	gwnoise "github.com/flynn/noise"
	"github.com/gorilla/websocket"
)

// maxMessageSize caps a single Noise transport frame to prevent memory
// exhaustion attacks.  The overhead per frame is 16 bytes (AEAD tag).
const maxMessageSize = 64 * 1024 // 64 KiB

// handshakeTimeout is the wall-clock budget for the full 3-message XX exchange.
const handshakeTimeout = 10 * time.Second

// cipherSuite selects the algorithms used by the Noise handshake and
// subsequent transport frames.
var cipherSuite = gwnoise.NewCipherSuite(
	gwnoise.DH25519,
	gwnoise.CipherChaChaPoly,
	gwnoise.HashBLAKE2s,
)

// DHKey is an alias for the underlying key type so callers don't need to
// import the flynn/noise package directly.
type DHKey = gwnoise.DHKey

// GenerateKey creates a new Curve25519 static key pair suitable for use as a
// server or client identity.
func GenerateKey() (DHKey, error) {
	return cipherSuite.GenerateKeypair(rand.Reader)
}

// Config holds the server's static key pair.
type Config struct {
	StaticKey DHKey
}

// NewServerConfig builds a Config from a pre-generated key.
func NewServerConfig(staticKey DHKey) Config {
	return Config{StaticKey: staticKey}
}

// Session represents an established, fully-authenticated Noise session.
// All I/O goes through Send / Recv; the underlying WebSocket connection
// MUST NOT be used directly after the session is created.
type Session struct {
	conn          *websocket.Conn
	send          *gwnoise.CipherState
	recv          *gwnoise.CipherState
	remoteStatic  []byte
}

// RemoteStatic returns the peer's verified static public key bytes.
// This can be fingerprinted (e.g. hex(SHA-256(bytes))) to get a stable
// identity string.
func (s *Session) RemoteStatic() []byte {
	out := make([]byte, len(s.remoteStatic))
	copy(out, s.remoteStatic)
	return out
}

// Send encrypts plaintext and writes it as a single WebSocket binary message.
func (s *Session) Send(plaintext []byte) error {
	if len(plaintext) > maxMessageSize {
		return fmt.Errorf("noise: plaintext too large (%d > %d)", len(plaintext), maxMessageSize)
	}
	ciphertext, err := s.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		return fmt.Errorf("noise: encrypt: %w", err)
	}
	return s.conn.WriteMessage(websocket.BinaryMessage, ciphertext)
}

// Recv reads one WebSocket message and decrypts it.
func (s *Session) Recv() ([]byte, error) {
	_, ciphertext, err := s.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("noise: read: %w", err)
	}
	if len(ciphertext) > maxMessageSize+16 {
		return nil, errors.New("noise: incoming frame too large")
	}
	plaintext, err := s.recv.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("noise: decrypt: %w", err)
	}
	return plaintext, nil
}

// Close shuts down the underlying WebSocket connection.
func (s *Session) Close() error {
	return s.conn.Close()
}

// ─── Handshake helpers ────────────────────────────────────────────────────────

// AcceptXX performs the server side of a Noise_XX handshake over ws.
// It blocks until the 3-message exchange is complete or ctx is cancelled.
//
// Message flow (→ = client→server, ← = server→client):
//
//	→  msg1: e
//	←  msg2: e, ee, s, es
//	→  msg3: s, se
func AcceptXX(ctx context.Context, ws *websocket.Conn, cfg Config) (*Session, error) {
	hs, err := gwnoise.NewHandshakeState(gwnoise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       gwnoise.HandshakeXX,
		Initiator:     false, // server is the responder
		StaticKeypair: cfg.StaticKey,
	})
	if err != nil {
		return nil, fmt.Errorf("noise: new handshake state: %w", err)
	}

	deadline := time.Now().Add(handshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = ws.SetReadDeadline(deadline)
	_ = ws.SetWriteDeadline(deadline)
	defer func() {
		_ = ws.SetReadDeadline(time.Time{})
		_ = ws.SetWriteDeadline(time.Time{})
	}()

	// msg1: receive e (initiator → responder)
	if err := hsRead(ws, hs); err != nil {
		return nil, fmt.Errorf("noise XX msg1: %w", err)
	}

	// msg2: send e, ee, s, es (responder → initiator)
	if err := hsWrite(ws, hs); err != nil {
		return nil, fmt.Errorf("noise XX msg2: %w", err)
	}

	// msg3: receive s, se (initiator → responder)
	cs0, cs1, err := hsReadFinal(ws, hs)
	if err != nil {
		return nil, fmt.Errorf("noise XX msg3: %w", err)
	}

	// For the responder (server): cs0 decrypts, cs1 encrypts.
	return &Session{
		conn:         ws,
		recv:         cs0,
		send:         cs1,
		remoteStatic: hs.PeerStatic(),
	}, nil
}

// InitiateXX performs the client side of a Noise_XX handshake over ws.
// Provided here for completeness and testing; production clients will
// typically be written in a different language / runtime.
func InitiateXX(ctx context.Context, ws *websocket.Conn, staticKey DHKey) (*Session, error) {
	hs, err := gwnoise.NewHandshakeState(gwnoise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       gwnoise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticKey,
	})
	if err != nil {
		return nil, fmt.Errorf("noise: new handshake state: %w", err)
	}

	deadline := time.Now().Add(handshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = ws.SetReadDeadline(deadline)
	_ = ws.SetWriteDeadline(deadline)
	defer func() {
		_ = ws.SetReadDeadline(time.Time{})
		_ = ws.SetWriteDeadline(time.Time{})
	}()

	// msg1: send e
	if err := hsWrite(ws, hs); err != nil {
		return nil, fmt.Errorf("noise XX msg1: %w", err)
	}

	// msg2: receive e, ee, s, es
	if err := hsRead(ws, hs); err != nil {
		return nil, fmt.Errorf("noise XX msg2: %w", err)
	}

	// msg3: send s, se  (final message → splits cipher states)
	cs0, cs1, err := hsWriteFinal(ws, hs)
	if err != nil {
		return nil, fmt.Errorf("noise XX msg3: %w", err)
	}

	// For the initiator (client): cs0 encrypts, cs1 decrypts.
	return &Session{
		conn:         ws,
		send:         cs0,
		recv:         cs1,
		remoteStatic: hs.PeerStatic(),
	}, nil
}

// ─── Low-level handshake I/O ──────────────────────────────────────────────────

// hsWrite produces the next handshake message and sends it as a WebSocket
// binary frame prefixed with a 2-byte big-endian length.
func hsWrite(ws *websocket.Conn, hs *gwnoise.HandshakeState) error {
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	return sendFrame(ws, msg)
}

// hsWriteFinal is like hsWrite but returns the two cipher states produced when
// the handshake completes (i.e. on the last initiator message).
func hsWriteFinal(ws *websocket.Conn, hs *gwnoise.HandshakeState) (*gwnoise.CipherState, *gwnoise.CipherState, error) {
	msg, cs0, cs1, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := sendFrame(ws, msg); err != nil {
		return nil, nil, err
	}
	return cs0, cs1, nil
}

// hsRead receives a framed WebSocket message and feeds it to the handshake
// state as a read step.
func hsRead(ws *websocket.Conn, hs *gwnoise.HandshakeState) error {
	frame, err := recvFrame(ws)
	if err != nil {
		return err
	}
	_, _, _, err = hs.ReadMessage(nil, frame)
	return err
}

// hsReadFinal is like hsRead but returns the cipher states produced when the
// handshake completes (i.e. on the last responder read).
func hsReadFinal(ws *websocket.Conn, hs *gwnoise.HandshakeState) (*gwnoise.CipherState, *gwnoise.CipherState, error) {
	frame, err := recvFrame(ws)
	if err != nil {
		return nil, nil, err
	}
	_, cs0, cs1, err := hs.ReadMessage(nil, frame)
	return cs0, cs1, err
}

// ─── Frame codec ─────────────────────────────────────────────────────────────
//
// Handshake messages are prefixed with a 2-byte big-endian length so the
// receiver knows how many bytes to read.  Transport frames use the raw
// WebSocket message length instead (no prefix needed).

func sendFrame(ws *websocket.Conn, payload []byte) error {
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	return ws.WriteMessage(websocket.BinaryMessage, buf)
}

func recvFrame(ws *websocket.Conn) ([]byte, error) {
	_, buf, err := ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	if len(buf) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	length := binary.BigEndian.Uint16(buf[:2])
	if int(length) != len(buf)-2 {
		return nil, fmt.Errorf("noise: frame length mismatch: header=%d actual=%d", length, len(buf)-2)
	}
	return buf[2:], nil
}
