package hub_test

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/yourname/p2p-relay/internal/hub"
)

func newHub(t *testing.T) *hub.Hub {
	t.Helper()
	h := hub.New(zap.NewNop())
	t.Cleanup(h.Shutdown)
	return h
}

func newClient(fp string) *hub.Client {
	return hub.NewClient(fp)
}

// ── Register ──────────────────────────────────────────────────────────────────

func TestRegister_OK(t *testing.T) {
	h := newHub(t)
	c := newClient("aabbcc")

	if err := h.Register(c); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
}

func TestRegister_Duplicate(t *testing.T) {
	h := newHub(t)
	c1 := newClient("aabbcc")
	c2 := newClient("aabbcc") // même fingerprint

	if err := h.Register(c1); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	if err := h.Register(c2); err == nil {
		t.Fatal("second Register() should return an error for duplicate fingerprint")
	}
}

// ── IsOnline ──────────────────────────────────────────────────────────────────

func TestIsOnline_AfterRegister(t *testing.T) {
	h := newHub(t)
	c := newClient("peer-1")

	if h.IsOnline("peer-1") {
		t.Fatal("peer should be offline before registration")
	}

	_ = h.Register(c)

	if !h.IsOnline("peer-1") {
		t.Fatal("peer should be online after registration")
	}
}

func TestIsOnline_AfterUnregister(t *testing.T) {
	h := newHub(t)
	c := newClient("peer-2")

	_ = h.Register(c)
	h.Unregister(c)

	// Le hub est asynchrone : on laisse la boucle traiter l'événement.
	time.Sleep(10 * time.Millisecond)

	if h.IsOnline("peer-2") {
		t.Fatal("peer should be offline after unregistration")
	}
}

// ── Route ─────────────────────────────────────────────────────────────────────

func TestRoute_DeliversToDest(t *testing.T) {
	h := newHub(t)

	src := newClient("src")
	dst := newClient("dst")

	_ = h.Register(src)
	_ = h.Register(dst)

	payload := []byte(`{"hello":"world"}`)
	online, err := h.Route(src, "dst", "msg-1", payload)
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if !online {
		t.Fatal("Route() reported peer offline, want online")
	}

	select {
	case msg := <-dst.Send:
		if string(msg.Payload) != string(payload) {
			t.Errorf("received payload = %q, want %q", msg.Payload, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message on destination channel")
	}
}

func TestRoute_PeerOffline(t *testing.T) {
	h := newHub(t)
	src := newClient("src")
	_ = h.Register(src)

	online, err := h.Route(src, "ghost", "msg-1", []byte("data"))
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if online {
		t.Fatal("Route() reported peer online, want offline")
	}
}

func TestRoute_SelfMessage(t *testing.T) {
	h := newHub(t)
	c := newClient("self")
	_ = h.Register(c)

	online, err := h.Route(c, "self", "msg-1", []byte("hi"))
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if !online {
		t.Fatal("Route() to self: want online=true")
	}

	select {
	case msg := <-c.Send:
		if string(msg.Payload) != "hi" {
			t.Errorf("payload = %q, want %q", msg.Payload, "hi")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for self-routed message")
	}
}

// ── Shutdown ──────────────────────────────────────────────────────────────────

func TestShutdown_ClosesSendChannels(t *testing.T) {
	h := hub.New(zap.NewNop())
	c := newClient("peer")
	_ = h.Register(c)

	h.Shutdown()

	select {
	case _, open := <-c.Send:
		if open {
			t.Fatal("Send channel should be closed after Shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Send channel to close")
	}
}
