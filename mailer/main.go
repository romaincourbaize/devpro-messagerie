// mailer is a tiny HTTP microservice that sends transactional emails.
//
// API:
//
//	POST /send   {"to":"…","subject":"…","body":"…"}
//	GET  /healthz
//
// Configuration via environment variables:
//
//	MAILER_ADDR       — listen address (default: :8025)
//	MAILER_SMTP_HOST  — SMTP server hostname (required)
//	MAILER_SMTP_PORT  — SMTP server port (default: 587)
//	MAILER_SMTP_USER  — SMTP login
//	MAILER_SMTP_PASS  — SMTP password / app-password
//	MAILER_FROM       — sender address (defaults to MAILER_SMTP_USER)
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"time"
)

// SendRequest is the JSON body expected by POST /send.
type SendRequest struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func main() {
	cfg := loadConfig()
	log.Printf("mailer started — addr=%s smtp=%s:%s from=%s",
		cfg.addr, cfg.smtpHost, cfg.smtpPort, cfg.from)

	mux := http.NewServeMux()
	mux.HandleFunc("/send", cfg.handleSend)
	mux.HandleFunc("/healthz", handleHealthz)

	srv := &http.Server{
		Addr:         cfg.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// ─── Config ───────────────────────────────────────────────────────────────────

type config struct {
	addr     string
	smtpHost string
	smtpPort string
	smtpUser string
	smtpPass string
	from     string
}

func loadConfig() *config {
	smtpHost := os.Getenv("MAILER_SMTP_HOST")
	if smtpHost == "" {
		log.Fatal("MAILER_SMTP_HOST is required")
	}
	smtpUser := os.Getenv("MAILER_SMTP_USER")
	from := os.Getenv("MAILER_FROM")
	if from == "" {
		from = smtpUser
	}
	return &config{
		addr:     envOrDefault("MAILER_ADDR", ":8025"),
		smtpHost: smtpHost,
		smtpPort: envOrDefault("MAILER_SMTP_PORT", "587"),
		smtpUser: smtpUser,
		smtpPass: os.Getenv("MAILER_SMTP_PASS"),
		from:     from,
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (c *config) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.To == "" || req.Subject == "" {
		http.Error(w, "to and subject are required", http.StatusBadRequest)
		return
	}

	if err := c.send(req); err != nil {
		log.Printf("[ERROR] send to=%s subject=%q err=%v", req.To, req.Subject, err)
		http.Error(w, "failed to send email: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[SENT] to=%s subject=%q", req.To, req.Subject)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ─── SMTP ─────────────────────────────────────────────────────────────────────

func (c *config) send(req SendRequest) error {
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		c.from, req.To, req.Subject, req.Body,
	)

	addr := net.JoinHostPort(c.smtpHost, c.smtpPort)

	var auth smtp.Auth
	if c.smtpUser != "" {
		auth = smtp.PlainAuth("", c.smtpUser, c.smtpPass, c.smtpHost)
	}

	if c.smtpPort == "465" {
		return c.sendTLS(addr, auth, req.To, msg)
	}
	return smtp.SendMail(addr, auth, c.from, []string{req.To}, []byte(msg))
}

// sendTLS uses implicit TLS (port 465).
func (c *config) sendTLS(addr string, auth smtp.Auth, to, msg string) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: c.smtpHost})
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, c.smtpHost)
	if err != nil {
		return err
	}
	defer client.Quit() //nolint:errcheck

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(c.from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, msg); err != nil {
		return err
	}
	return w.Close()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
