// Command server starts the P2P relay / signalling server.
//
// Configuration is read from environment variables:
//
//	RELAY_ADDR          — listen address (default: :8080)
//	RELAY_KEY_FILE      — path to the server's Noise static private key
//	                      (raw 32-byte file).  If absent, a new key is
//	                      generated and written to this path.
//	RELAY_LOG_LEVEL     — zap log level: debug | info | warn | error
//	                      (default: info)
package main

import (
	"context"
	"crypto/ecdh"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/yourname/p2p-relay/internal/handler"
	"github.com/yourname/p2p-relay/internal/hub"
	noiseutil "github.com/yourname/p2p-relay/internal/noise"
)

//go:embed web
var webFS embed.FS

func main() {
	logger := buildLogger()
	defer func() { _ = logger.Sync() }()

	// ── Load or generate the server's Noise static key ───────────────────────
	noiseCfg, err := loadOrGenerateKey(logger)
	if err != nil {
		logger.Fatal("noise key setup", zap.Error(err))
	}

	// ── Build the dependency graph ───────────────────────────────────────────
	h := hub.New(logger)
	defer h.Shutdown()

	hand := handler.New(h, noiseCfg, logger)

	// ── HTTP router ──────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// / — interface web
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// /ws — peer connections (Noise XX + message routing)
	mux.HandleFunc("/ws", hand.ServeWS)

	// /healthz — liveness probe for load-balancers
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := envOrDefault("RELAY_ADDR", ":8080")
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("server listening", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("listen", zap.Error(err))
		}
	}()

	<-quit
	logger.Info("shutting down…")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("http shutdown", zap.Error(err))
	}

	logger.Info("bye")
}

// ─── Key management ──────────────────────────────────────────────────────────

func loadOrGenerateKey(logger *zap.Logger) (noiseutil.Config, error) {
	path := envOrDefault("RELAY_KEY_FILE", "server.key")

	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != 32 {
			return noiseutil.Config{}, errors.New("key file must be exactly 32 bytes")
		}
		// Derive the matching public key from the stored private key bytes.
		ecPriv, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return noiseutil.Config{}, err
		}
		key := noiseutil.DHKey{
			Private: ecPriv.Bytes(),
			Public:  ecPriv.PublicKey().Bytes(),
		}
		logger.Info("loaded noise key", zap.String("path", path))
		return noiseutil.NewServerConfig(key), nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return noiseutil.Config{}, err
	}

	key, err := noiseutil.GenerateKey()
	if err != nil {
		return noiseutil.Config{}, err
	}

	if err := os.WriteFile(path, key.Private, 0600); err != nil {
		return noiseutil.Config{}, err
	}

	logger.Info("generated new noise key",
		zap.String("path", path),
		zap.String("public_hex", hex.EncodeToString(key.Public)),
	)

	return noiseutil.NewServerConfig(key), nil
}

// ─── Logger ──────────────────────────────────────────────────────────────────

func buildLogger() *zap.Logger {
	level := zap.NewAtomicLevel()
	switch envOrDefault("RELAY_LOG_LEVEL", "info") {
	case "debug":
		level.SetLevel(zapcore.DebugLevel)
	case "warn":
		level.SetLevel(zapcore.WarnLevel)
	case "error":
		level.SetLevel(zapcore.ErrorLevel)
	default:
		level.SetLevel(zapcore.InfoLevel)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = level
	logger, _ := cfg.Build()
	return logger
}

// ─── Utility ─────────────────────────────────────────────────────────────────

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
