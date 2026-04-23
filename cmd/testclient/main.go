// testclient connects to the relay server, performs a Noise XX handshake,
// registers, and queries its own peer status.
//
// Usage:
//
//	go run ./cmd/testclient                          # connect to localhost:8080
//	go run ./cmd/testclient ws://host:8080/ws        # custom address
//	go run ./cmd/testclient ws://host:8080/ws <fp>   # also forward a message to <fp>
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/gorilla/websocket"
	noiseutil "github.com/yourname/p2p-relay/internal/noise"
	"github.com/yourname/p2p-relay/pkg/protocol"
)

func main() {
	addr := "ws://localhost:8080/ws"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	// Generate a fresh Curve25519 key pair for this client.
	key, err := noiseutil.GenerateKey()
	if err != nil {
		log.Fatal("generate key:", err)
	}
	sum := sha256.Sum256(key.Public)
	fingerprint := hex.EncodeToString(sum[:])

	// Connect WebSocket.
	conn, _, err := websocket.DefaultDialer.Dial(addr, nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer conn.Close()

	// Noise XX handshake (client = initiator).
	session, err := noiseutil.InitiateXX(context.Background(), conn, key)
	if err != nil {
		log.Fatal("noise handshake:", err)
	}

	serverSum := sha256.Sum256(session.RemoteStatic())
	fmt.Println("--- handshake ok ---")
	fmt.Println("client fingerprint :", fingerprint)
	fmt.Println("server fingerprint :", hex.EncodeToString(serverSum[:]))

	// Register.
	regData, _ := json.Marshal(protocol.RegisterPayload{Fingerprint: fingerprint})
	mustSend(session, protocol.Envelope{
		Type:  protocol.TypeRegister,
		MsgID: "1",
		Data:  json.RawMessage(regData),
	})
	ack := mustRecv(session)
	if ack.Error != "" {
		log.Fatal("register error:", ack.Error)
	}
	fmt.Println("registered         : ok")

	// Query own peer status — should be online.
	mustSend(session, protocol.Envelope{
		Type:  protocol.TypePeerStatus,
		MsgID: "2",
		To:    fingerprint,
	})
	status := mustRecv(session)
	fmt.Println("self online        :", status.Online)

	if len(os.Args) > 2 {
		// Forward a message to another peer, then exit.
		target := os.Args[2]
		payload, _ := json.Marshal("hello from " + fingerprint[:12])
		mustSend(session, protocol.Envelope{
			Type:  protocol.TypeForward,
			MsgID: "3",
			To:    target,
			Data:  json.RawMessage(payload),
		})
		resp := mustRecv(session)
		switch {
		case resp.Error != "":
			fmt.Println("forward error      :", resp.Error)
		case resp.Type == protocol.TypePeerStatus && !resp.Online:
			fmt.Println("forward            : target offline")
		default:
			fmt.Println("forward            : ack ok")
		}
		return
	}

	// No target specified: stay connected and print incoming messages.
	fmt.Println("listening for messages (Ctrl+C to quit)...")
	for {
		env := mustRecv(session)
		switch env.Type {
		case protocol.TypeDeliver:
			fmt.Printf("message from %s : %s\n", env.From[:12], env.Data)
		case protocol.TypePing:
			mustSend(session, protocol.Envelope{Type: protocol.TypePong, MsgID: env.MsgID})
		default:
			fmt.Printf("received type=%s\n", env.Type)
		}
	}
}

func mustSend(s *noiseutil.Session, env protocol.Envelope) {
	b, err := json.Marshal(env)
	if err != nil {
		log.Fatal("marshal:", err)
	}
	if err := s.Send(b); err != nil {
		log.Fatal("send:", err)
	}
}

func mustRecv(s *noiseutil.Session) protocol.Envelope {
	b, err := s.Recv()
	if err != nil {
		log.Fatal("recv:", err)
	}
	var env protocol.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		log.Fatal("unmarshal:", err)
	}
	return env
}
