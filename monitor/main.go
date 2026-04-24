// monitor polls a health endpoint and notifies the mailer service on state changes.
//
// Configuration via environment variables:
//
//	MONITOR_TARGET      — URL to poll (default: http://server:8080/healthz)
//	MONITOR_INTERVAL    — polling interval in seconds (default: 10)
//	MONITOR_TIMEOUT     — HTTP request timeout in seconds (default: 5)
//	MONITOR_MAILER_URL  — mailer service base URL (default: http://mailer:8025)
//	MONITOR_EMAIL_TO    — alert recipient address
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	target    := envOrDefault("MONITOR_TARGET",     "http://server:8080/healthz")
	mailerURL := envOrDefault("MONITOR_MAILER_URL", "http://mailer:8025")
	emailTo   := os.Getenv("MONITOR_EMAIL_TO")
	interval  := parseDuration("MONITOR_INTERVAL", 10)
	timeout   := parseDuration("MONITOR_TIMEOUT",  5)

	if emailTo == "" {
		log.Printf("MONITOR_EMAIL_TO not set — email alerts disabled")
	} else {
		log.Printf("email alerts → %s via %s", emailTo, mailerURL)
	}

	client := &http.Client{Timeout: timeout}
	log.Printf("monitor started — target=%s interval=%s", target, interval)

	var wasUp *bool

	for {
		up := check(client, target)

		switch {
		case wasUp == nil:
			if up {
				log.Printf("[UP] %s is reachable", target)
			} else {
				log.Printf("[DOWN] %s is unreachable on first check", target)
				notify(mailerURL, emailTo, target, false)
			}
		case up && !*wasUp:
			log.Printf("[RECOVERED] %s is back up", target)
			notify(mailerURL, emailTo, target, true)
		case !up && *wasUp:
			log.Printf("[DOWN] %s stopped responding", target)
			notify(mailerURL, emailTo, target, false)
		}

		wasUp = &up
		time.Sleep(interval)
	}
}

// ─── Health check ─────────────────────────────────────────────────────────────

func check(client *http.Client, url string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ─── Notification via mailer service ─────────────────────────────────────────

func notify(mailerURL, to, target string, recovered bool) {
	if to == "" {
		return
	}

	subject, body := alertContent(target, recovered)

	payload, _ := json.Marshal(map[string]string{
		"to":      to,
		"subject": subject,
		"body":    body,
	})

	resp, err := http.Post(mailerURL+"/send", "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[NOTIFY ERROR] could not reach mailer: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[NOTIFY ERROR] mailer returned %d", resp.StatusCode)
		return
	}
	log.Printf("[NOTIFIED] alert sent to %s", to)
}

func alertContent(target string, recovered bool) (subject, body string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	if recovered {
		subject = fmt.Sprintf("[RECOVERED] %s est de nouveau accessible", target)
		body = fmt.Sprintf("Le serveur %s est revenu en ligne.\n\nDate : %s", target, now)
	} else {
		subject = fmt.Sprintf("[ALERTE] %s ne répond plus", target)
		body = fmt.Sprintf("Le serveur %s ne répond plus au healthcheck.\n\nDate : %s", target, now)
	}
	return
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDuration(key string, defaultSeconds int) time.Duration {
	s := os.Getenv(key)
	if s == "" {
		return time.Duration(defaultSeconds) * time.Second
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		log.Printf("invalid %s=%q, using default %ds", key, s, defaultSeconds)
		return time.Duration(defaultSeconds) * time.Second
	}
	return time.Duration(n) * time.Second
}
