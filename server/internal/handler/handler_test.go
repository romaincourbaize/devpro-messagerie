package handler_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/yourname/p2p-relay/internal/handler"
	"github.com/yourname/p2p-relay/internal/hub"
	noiseutil "github.com/yourname/p2p-relay/internal/noise"
	"github.com/yourname/p2p-relay/pkg/protocol"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// testServer starts an httptest server with a fresh hub and handler.
// It returns the WebSocket URL and a cleanup function.
func testServer(t *testing.T) (wsURL string, serverKey noiseutil.DHKey) {
	t.Helper()

	serverKey, err := noiseutil.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	h := hub.New(zap.NewNop())
	t.Cleanup(h.Shutdown)

	hand := handler.New(h, noiseutil.NewServerConfig(serverKey), zap.NewNop())

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hand.ServeWS)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	wsURL = "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	return wsURL, serverKey
}

// connect établit une session Noise XX complète et renvoie la session.
func connect(t *testing.T, wsURL string, clientKey noiseutil.DHKey) *noiseutil.Session {
	t.Helper()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	session, err := noiseutil.InitiateXX(context.Background(), conn, clientKey)
	if err != nil {
		t.Fatalf("InitiateXX: %v", err)
	}
	return session
}

// register envoie TypeRegister et vérifie l'ack.
func register(t *testing.T, session *noiseutil.Session, fingerprint string) {
	t.Helper()

	payload, _ := json.Marshal(protocol.RegisterPayload{Fingerprint: fingerprint})
	send(t, session, protocol.Envelope{
		Type:  protocol.TypeRegister,
		MsgID: "init",
		Data:  json.RawMessage(payload),
	})

	ack := recv(t, session)
	if ack.Error != "" {
		t.Fatalf("register ack error: %s", ack.Error)
	}
}

func fingerprint(key noiseutil.DHKey) string {
	sum := sha256.Sum256(key.Public)
	return hex.EncodeToString(sum[:])
}

func send(t *testing.T, s *noiseutil.Session, env protocol.Envelope) {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := s.Send(b); err != nil {
		t.Fatalf("session.Send: %v", err)
	}
}

func recv(t *testing.T, s *noiseutil.Session) protocol.Envelope {
	t.Helper()
	b, err := s.Recv()
	if err != nil {
		t.Fatalf("session.Recv: %v", err)
	}
	var env protocol.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return env
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestHandshake_And_Register(t *testing.T) {
	wsURL, _ := testServer(t)

	clientKey, _ := noiseutil.GenerateKey()
	session := connect(t, wsURL, clientKey)

	fp := fingerprint(clientKey)
	register(t, session, fp)
	// Si on arrive ici sans t.Fatal, handshake + enregistrement sont OK.
}

func TestRegister_WrongFingerprint(t *testing.T) {
	wsURL, _ := testServer(t)

	clientKey, _ := noiseutil.GenerateKey()
	session := connect(t, wsURL, clientKey)

	// On envoie un fingerprint qui ne correspond pas à la clé Noise.
	payload, _ := json.Marshal(protocol.RegisterPayload{Fingerprint: "deadbeefdeadbeef"})
	send(t, session, protocol.Envelope{
		Type:  protocol.TypeRegister,
		MsgID: "init",
		Data:  json.RawMessage(payload),
	})

	// Le serveur doit fermer la connexion (fingerprint mismatch).
	// session.Recv() doit échouer.
	_, err := session.Recv()
	if err == nil {
		t.Fatal("expected connection close after wrong fingerprint, got nil error")
	}
}

func TestForward_MessageDelivered(t *testing.T) {
	wsURL, _ := testServer(t)

	keyA, _ := noiseutil.GenerateKey()
	keyB, _ := noiseutil.GenerateKey()

	sessA := connect(t, wsURL, keyA)
	sessB := connect(t, wsURL, keyB)

	fpA := fingerprint(keyA)
	fpB := fingerprint(keyB)

	register(t, sessA, fpA)
	register(t, sessB, fpB)

	// A envoie un message à B.
	payload, _ := json.Marshal("bonjour B")
	send(t, sessA, protocol.Envelope{
		Type:  protocol.TypeForward,
		MsgID: "msg-1",
		To:    fpB,
		Data:  json.RawMessage(payload),
	})

	// A doit recevoir un ack.
	ack := recv(t, sessA)
	if ack.Type != protocol.TypeAck {
		t.Fatalf("A: expected TypeAck, got %q", ack.Type)
	}
	if ack.Error != "" {
		t.Fatalf("A: ack error = %q", ack.Error)
	}

	// B doit recevoir le message.
	delivered := recv(t, sessB)
	if delivered.Type != protocol.TypeDeliver {
		t.Fatalf("B: expected TypeDeliver, got %q", delivered.Type)
	}
	if delivered.From != fpA {
		t.Errorf("B: From = %q, want %q", delivered.From, fpA)
	}
}

func TestForward_TargetOffline(t *testing.T) {
	wsURL, _ := testServer(t)

	keyA, _ := noiseutil.GenerateKey()
	sessA := connect(t, wsURL, keyA)
	fpA := fingerprint(keyA)
	register(t, sessA, fpA)

	ghostFP := strings.Repeat("ab", 32) // fingerprint inexistant

	payload, _ := json.Marshal("message fantôme")
	send(t, sessA, protocol.Envelope{
		Type:  protocol.TypeForward,
		MsgID: "msg-ghost",
		To:    ghostFP,
		Data:  json.RawMessage(payload),
	})

	// Le serveur doit répondre avec un TypePeerStatus online=false.
	resp := recv(t, sessA)
	if resp.Type != protocol.TypePeerStatus {
		t.Fatalf("expected TypePeerStatus, got %q", resp.Type)
	}
	if resp.Online {
		t.Error("expected online=false for ghost peer")
	}
}

func TestPeerStatus_Query(t *testing.T) {
	wsURL, _ := testServer(t)

	keyA, _ := noiseutil.GenerateKey()
	keyB, _ := noiseutil.GenerateKey()

	sessA := connect(t, wsURL, keyA)
	sessB := connect(t, wsURL, keyB)

	fpA := fingerprint(keyA)
	fpB := fingerprint(keyB)

	register(t, sessA, fpA)
	register(t, sessB, fpB)

	// A demande si B est en ligne.
	send(t, sessA, protocol.Envelope{
		Type:  protocol.TypePeerStatus,
		MsgID: "status-1",
		To:    fpB,
	})

	resp := recv(t, sessA)
	if resp.Type != protocol.TypePeerStatus {
		t.Fatalf("expected TypePeerStatus, got %q", resp.Type)
	}
	if !resp.Online {
		t.Error("expected B online=true")
	}
}

func TestPing_Pong(t *testing.T) {
	wsURL, _ := testServer(t)

	clientKey, _ := noiseutil.GenerateKey()
	session := connect(t, wsURL, clientKey)
	register(t, session, fingerprint(clientKey))

	send(t, session, protocol.Envelope{
		Type:  protocol.TypePing,
		MsgID: "ping-1",
	})

	resp := recv(t, session)
	if resp.Type != protocol.TypePong {
		t.Errorf("expected TypePong, got %q", resp.Type)
	}
	if resp.MsgID != "ping-1" {
		t.Errorf("MsgID = %q, want %q", resp.MsgID, "ping-1")
	}
}

func TestForward_MissingTo(t *testing.T) {
	wsURL, _ := testServer(t)

	clientKey, _ := noiseutil.GenerateKey()
	session := connect(t, wsURL, clientKey)
	register(t, session, fingerprint(clientKey))

	send(t, session, protocol.Envelope{
		Type:  protocol.TypeForward,
		MsgID: "msg-bad",
		// To intentionnellement absent
		Data: json.RawMessage(`"data"`),
	})

	resp := recv(t, session)
	if resp.Type != protocol.TypeAck {
		t.Fatalf("expected TypeAck, got %q", resp.Type)
	}
	if resp.Error == "" {
		t.Error("expected error for missing 'to' field")
	}
}

func TestDuplicateSession_Rejected(t *testing.T) {
	wsURL, _ := testServer(t)

	clientKey, _ := noiseutil.GenerateKey()
	fp := fingerprint(clientKey)

	// Première connexion.
	sess1 := connect(t, wsURL, clientKey)
	register(t, sess1, fp)

	// Deuxième connexion avec la même clé.
	sess2 := connect(t, wsURL, clientKey)

	payload, _ := json.Marshal(protocol.RegisterPayload{Fingerprint: fp})
	send(t, sess2, protocol.Envelope{
		Type:  protocol.TypeRegister,
		MsgID: "init",
		Data:  json.RawMessage(payload),
	})

	// Le serveur doit envoyer un ack avec erreur puis fermer.
	resp := recv(t, sess2)
	if resp.Error == "" {
		t.Error("expected error for duplicate session")
	}

	// La deuxième session doit être fermée.
	_, err := sess2.Recv()
	if err == nil {
		t.Error("expected connection close after duplicate registration")
	}
}

func TestForward_NoData(t *testing.T) {
	wsURL, _ := testServer(t)

	clientKey, _ := noiseutil.GenerateKey()
	session := connect(t, wsURL, clientKey)
	register(t, session, fingerprint(clientKey))

	ghostFP := strings.Repeat("cd", 32)
	send(t, session, protocol.Envelope{
		Type:  protocol.TypeForward,
		MsgID: "msg-nodata",
		To:    ghostFP,
		// Data absent
	})

	resp := recv(t, session)
	if resp.Type != protocol.TypeAck || resp.Error == "" {
		t.Errorf("expected error ack for missing data, got type=%q error=%q", resp.Type, resp.Error)
	}
}

// TestConnectionTimeout vérifie que le serveur ferme la connexion si le client
// ne s'enregistre pas dans les délais.
func TestConnectionTimeout_NoRegister(t *testing.T) {
	wsURL, _ := testServer(t)

	clientKey, _ := noiseutil.GenerateKey()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	session, err := noiseutil.InitiateXX(context.Background(), conn, clientKey)
	if err != nil {
		t.Fatalf("InitiateXX: %v", err)
	}

	// On n'envoie rien — le serveur doit fermer après registerTimeout (10 s).
	// Pour le test, on attend au maximum 15 secondes.
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err = session.Recv()
	if err == nil {
		t.Fatal("expected connection close after register timeout")
	}
}
