// Package protocol defines the wire format for all messages exchanged
// between clients and the relay server.
//
// Wire layout (per WebSocket message):
//
//	[2 bytes big-endian: payload length][payload bytes]
//
// After the Noise XX handshake is complete, every WebSocket message is a
// Noise transport frame (AEAD-encrypted). The plaintext inside that frame
// is a JSON-encoded Envelope.
package protocol

import "encoding/json"

// MessageType identifies the purpose of an Envelope.
type MessageType string

const (
	// TypeRegister is sent by a client right after the Noise handshake to
	// publish its public fingerprint so other peers can route messages to it.
	TypeRegister MessageType = "register"

	// TypeForward is sent by a client to route a payload to another peer.
	// The server never reads Data — it forwards the raw bytes opaquely.
	TypeForward MessageType = "forward"

	// TypeDeliver is sent by the server to the destination peer.
	TypeDeliver MessageType = "deliver"

	// TypeAck is sent by the server to confirm delivery (or report an error).
	TypeAck MessageType = "ack"

	// TypePeerStatus is sent by the server to inform a client whether a
	// target peer is currently online or offline.
	TypePeerStatus MessageType = "peer_status"

	// TypePing / TypePong are used for application-level keep-alive.
	TypePing MessageType = "ping"
	TypePong MessageType = "pong"
)

// Envelope is the top-level message container.  All fields are optional
// depending on MessageType; see the constants above for semantics.
type Envelope struct {
	// Type identifies the message kind.
	Type MessageType `json:"type"`

	// MsgID is an opaque identifier chosen by the sender.  The server echoes
	// it back in the Ack so the sender can correlate responses.
	MsgID string `json:"msg_id,omitempty"`

	// From is the sender's fingerprint (set by the server on TypeDeliver,
	// never trusted from the client).
	From string `json:"from,omitempty"`

	// To is the recipient's fingerprint (set by the client on TypeForward).
	To string `json:"to,omitempty"`

	// Data carries the opaque application payload.  The server treats this
	// as an opaque byte slice — it never inspects or modifies its contents.
	// Clients are expected to further encrypt this field (e.g. NaCl Box)
	// before placing it here.
	Data json.RawMessage `json:"data,omitempty"`

	// Online is set on TypePeerStatus responses.
	Online bool `json:"online,omitempty"`

	// Error carries a human-readable error description on TypeAck failures.
	Error string `json:"error,omitempty"`
}

// RegisterPayload is the JSON body placed in Envelope.Data for TypeRegister.
type RegisterPayload struct {
	// Fingerprint is the client's canonical identity string.
	// Recommended format: hex(SHA-256(static_public_key)).
	Fingerprint string `json:"fingerprint"`
}
