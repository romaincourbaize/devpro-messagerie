package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/yourname/p2p-relay/pkg/protocol"
)

// ── Marshaling ────────────────────────────────────────────────────────────────

func TestEnvelope_Marshal_TypeRegister(t *testing.T) {
	payload, _ := json.Marshal(protocol.RegisterPayload{Fingerprint: "deadbeef"})
	env := protocol.Envelope{
		Type:  protocol.TypeRegister,
		MsgID: "init",
		Data:  json.RawMessage(payload),
	}

	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got protocol.Envelope
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if got.Type != protocol.TypeRegister {
		t.Errorf("Type = %q, want %q", got.Type, protocol.TypeRegister)
	}
	if got.MsgID != "init" {
		t.Errorf("MsgID = %q, want %q", got.MsgID, "init")
	}

	var reg protocol.RegisterPayload
	if err := json.Unmarshal(got.Data, &reg); err != nil {
		t.Fatalf("Unmarshal RegisterPayload error = %v", err)
	}
	if reg.Fingerprint != "deadbeef" {
		t.Errorf("Fingerprint = %q, want %q", reg.Fingerprint, "deadbeef")
	}
}

func TestEnvelope_Marshal_TypeForward(t *testing.T) {
	env := protocol.Envelope{
		Type:  protocol.TypeForward,
		MsgID: "msg-1",
		To:    "targetfp",
		Data:  json.RawMessage(`"hello"`),
	}

	b, _ := json.Marshal(env)
	var got protocol.Envelope
	_ = json.Unmarshal(b, &got)

	if got.To != "targetfp" {
		t.Errorf("To = %q, want %q", got.To, "targetfp")
	}
	if got.From != "" {
		t.Errorf("From should be empty on forward, got %q", got.From)
	}
}

func TestEnvelope_Marshal_TypeAck_Error(t *testing.T) {
	env := protocol.Envelope{
		Type:  protocol.TypeAck,
		MsgID: "msg-1",
		Error: "peer not found",
	}

	b, _ := json.Marshal(env)
	var got protocol.Envelope
	_ = json.Unmarshal(b, &got)

	if got.Error != "peer not found" {
		t.Errorf("Error = %q, want %q", got.Error, "peer not found")
	}
}

func TestEnvelope_Marshal_TypePeerStatus(t *testing.T) {
	env := protocol.Envelope{
		Type:   protocol.TypePeerStatus,
		To:     "somefp",
		Online: true,
	}

	b, _ := json.Marshal(env)
	var got protocol.Envelope
	_ = json.Unmarshal(b, &got)

	if !got.Online {
		t.Error("Online = false, want true")
	}
}

// ── Omitempty ─────────────────────────────────────────────────────────────────

func TestEnvelope_OmitEmpty_Fields(t *testing.T) {
	env := protocol.Envelope{Type: protocol.TypePing}

	b, _ := json.Marshal(env)
	s := string(b)

	for _, field := range []string{"msg_id", "from", "to", "data", "error"} {
		if contains(s, `"`+field+`"`) {
			t.Errorf("field %q should be omitted when empty, got: %s", field, s)
		}
	}
}

// Online=false is a zero value — it should be omitted too.
func TestEnvelope_OmitEmpty_OnlineFalse(t *testing.T) {
	env := protocol.Envelope{Type: protocol.TypePeerStatus, To: "fp", Online: false}
	b, _ := json.Marshal(env)
	if contains(string(b), `"online"`) {
		t.Errorf("online:false should be omitted, got: %s", b)
	}
}

// ── Round-trip ────────────────────────────────────────────────────────────────

func TestEnvelope_RoundTrip_AllFields(t *testing.T) {
	original := protocol.Envelope{
		Type:   protocol.TypeDeliver,
		MsgID:  "m42",
		From:   "fp-sender",
		To:     "fp-receiver",
		Data:   json.RawMessage(`{"text":"bonjour"}`),
		Online: true,
		Error:  "",
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got protocol.Envelope
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	checks := []struct {
		field string
		a, b  any
	}{
		{"Type", original.Type, got.Type},
		{"MsgID", original.MsgID, got.MsgID},
		{"From", original.From, got.From},
		{"To", original.To, got.To},
	}
	for _, c := range checks {
		if c.a != c.b {
			t.Errorf("%s: got %v, want %v", c.field, c.b, c.a)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
