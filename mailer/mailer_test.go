package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Faux serveur SMTP ─────────────────────────────────────────────────────────
//
// Implémente le protocole SMTP minimal pour intercepter les emails sans
// dépendance externe. Les messages reçus sont envoyés sur le canal retourné.

func fakeSMTP(t *testing.T) (host, port string, msgs <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeSMTP listen: %v", err)
	}

	ch := make(chan string, 8)

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(conn, ch)
		}
	}()

	t.Cleanup(func() { ln.Close() })

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p, ch
}

// serveConn répond aux commandes SMTP et envoie le corps du message sur ch.
func serveConn(conn net.Conn, ch chan<- string) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	reply := func(s string) { fmt.Fprint(conn, s+"\r\n") }

	reply("220 test SMTP ready")

	var body strings.Builder
	inData := false

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				ch <- body.String()
				body.Reset()
				inData = false
				reply("250 OK: message accepted")
			} else {
				// Dé-doubler le point d'échappement SMTP.
				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}
				body.WriteString(line + "\n")
			}
			continue
		}

		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			// AUTH annoncé mais pas STARTTLS → smtp.SendMail envoie les
			// credentials en clair, autorisé par PlainAuth sur localhost.
			fmt.Fprint(conn, "250-test\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
		case strings.HasPrefix(cmd, "AUTH"):
			reply("235 Authentication successful")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			reply("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			reply("250 OK")
		case cmd == "DATA":
			reply("354 Start input, end with <CRLF>.<CRLF>")
			inData = true
		case cmd == "QUIT":
			reply("221 Bye")
			return
		default:
			reply("502 Command not implemented")
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newTestConfig(smtpHost, smtpPort string) *config {
	return &config{
		smtpHost: smtpHost,
		smtpPort: smtpPort,
		smtpUser: "user@test.com",
		smtpPass: "secret",
		from:     "from@test.com",
	}
}

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(b)
}

// ── /healthz ──────────────────────────────────────────────────────────────────

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(handleHealthz))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if body := readBody(t, resp.Body); body != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

// ── /send — validation HTTP ───────────────────────────────────────────────────

func TestHandleSend_MethodNotAllowed(t *testing.T) {
	cfg := newTestConfig("127.0.0.1", "2525")
	srv := httptest.NewServer(http.HandlerFunc(cfg.handleSend))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/send")
	if err != nil {
		t.Fatalf("GET /send: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHandleSend_InvalidJSON(t *testing.T) {
	cfg := newTestConfig("127.0.0.1", "2525")
	srv := httptest.NewServer(http.HandlerFunc(cfg.handleSend))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/send", "application/json",
		strings.NewReader("{invalid json"))
	if err != nil {
		t.Fatalf("POST /send: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleSend_MissingTo(t *testing.T) {
	cfg := newTestConfig("127.0.0.1", "2525")
	srv := httptest.NewServer(http.HandlerFunc(cfg.handleSend))
	defer srv.Close()

	resp := postJSON(t, srv, "/send", SendRequest{Subject: "Test"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleSend_MissingSubject(t *testing.T) {
	cfg := newTestConfig("127.0.0.1", "2525")
	srv := httptest.NewServer(http.HandlerFunc(cfg.handleSend))
	defer srv.Close()

	resp := postJSON(t, srv, "/send", SendRequest{To: "a@b.fr"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// ── /send — envoi réel via faux SMTP ─────────────────────────────────────────

func TestHandleSend_Success(t *testing.T) {
	host, port, msgs := fakeSMTP(t)

	cfg := newTestConfig(host, port)
	srv := httptest.NewServer(http.HandlerFunc(cfg.handleSend))
	defer srv.Close()

	resp := postJSON(t, srv, "/send", SendRequest{
		To:      "dest@test.com",
		Subject: "Bonjour",
		Body:    "Corps du message",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — body: %s", resp.StatusCode, readBody(t, resp.Body))
		return
	}

	var result map[string]bool
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if !result["ok"] {
		t.Error(`response body: want {"ok":true}`)
	}

	// Vérifie que le faux serveur a bien reçu le message.
	select {
	case msg := <-msgs:
		if !strings.Contains(msg, "Bonjour") {
			t.Errorf("message subject absent — got:\n%s", msg)
		}
		if !strings.Contains(msg, "Corps du message") {
			t.Errorf("message body absent — got:\n%s", msg)
		}
	default:
		t.Error("fake SMTP: no message received")
	}
}

func TestHandleSend_SMTPUnavailable(t *testing.T) {
	// Port fermé → smtp.SendMail doit échouer.
	cfg := newTestConfig("127.0.0.1", "19999")
	srv := httptest.NewServer(http.HandlerFunc(cfg.handleSend))
	defer srv.Close()

	resp := postJSON(t, srv, "/send", SendRequest{
		To:      "x@y.fr",
		Subject: "Test",
		Body:    "...",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// ── Format du message SMTP ────────────────────────────────────────────────────

func TestSend_MessageHeaders(t *testing.T) {
	host, port, msgs := fakeSMTP(t)

	cfg := newTestConfig(host, port)
	err := cfg.send(SendRequest{
		To:      "dest@test.com",
		Subject: "Sujet de test",
		Body:    "Contenu",
	})
	if err != nil {
		t.Fatalf("send() error = %v", err)
	}

	select {
	case msg := <-msgs:
		checks := []string{
			"From: from@test.com",
			"To: dest@test.com",
			"Subject: Sujet de test",
			"Content-Type: text/plain; charset=UTF-8",
			"Contenu",
		}
		for _, want := range checks {
			if !strings.Contains(msg, want) {
				t.Errorf("message missing %q\ngot:\n%s", want, msg)
			}
		}
	default:
		t.Error("fake SMTP: no message received")
	}
}

func TestSend_NoAuth(t *testing.T) {
	host, port, msgs := fakeSMTP(t)

	// Sans identifiants → pas de commande AUTH envoyée.
	cfg := &config{
		smtpHost: host,
		smtpPort: port,
		from:     "noreply@test.com",
	}

	err := cfg.send(SendRequest{To: "a@b.fr", Subject: "Sans auth", Body: "ok"})
	if err != nil {
		t.Fatalf("send() error = %v", err)
	}

	select {
	case <-msgs: // message bien reçu
	default:
		t.Error("fake SMTP: no message received")
	}
}

func TestSend_MultipleRecipients_Sequential(t *testing.T) {
	host, port, msgs := fakeSMTP(t)
	cfg := newTestConfig(host, port)

	for i, to := range []string{"a@test.com", "b@test.com", "c@test.com"} {
		err := cfg.send(SendRequest{
			To:      to,
			Subject: fmt.Sprintf("Message %d", i+1),
			Body:    "corps",
		})
		if err != nil {
			t.Errorf("send to %s: %v", to, err)
		}
	}

	count := 0
	for count < 3 {
		select {
		case <-msgs:
			count++
		default:
			if count < 3 {
				t.Errorf("got %d messages, want 3", count)
			}
			return
		}
	}
}

// ── envOrDefault ──────────────────────────────────────────────────────────────

func TestEnvOrDefault_ReturnsDefault(t *testing.T) {
	got := envOrDefault("__VAR_INEXISTANTE__", "defaut")
	if got != "defaut" {
		t.Errorf("got %q, want %q", got, "defaut")
	}
}

func TestEnvOrDefault_ReturnsEnv(t *testing.T) {
	t.Setenv("__VAR_TEST__", "valeur")
	got := envOrDefault("__VAR_TEST__", "defaut")
	if got != "valeur" {
		t.Errorf("got %q, want %q", got, "valeur")
	}
}
