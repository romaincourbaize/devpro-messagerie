## ─── p2p-relay Makefile ──────────────────────────────────────────────────────

BINARY  := bin/server
CMD     := ./cmd/server
GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: build run test lint deps clean up up-detach down logs reset docker-build

## ── Local build (Go 1.22+ requis) ───────────────────────────────────────────

build:
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

run: build
	RELAY_LOG_LEVEL=debug ./$(BINARY)

test:
	go test -race -count=1 ./...

test-verbose:
	go test -race -count=1 -v ./...

lint:
	golangci-lint run ./...

deps:
	go mod tidy

clean:
	rm -rf bin/

## ── Docker ───────────────────────────────────────────────────────────────────

# Build the image (télécharge les dépendances Go dans le builder)
docker-build:
	docker build -t p2p-relay:latest .

# Lance le stack — aucune dépendance locale requise, tout se passe dans Docker
up:
	docker compose up --build

# Même chose, en arrière-plan
up-detach:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

# Repart de zéro : supprime le volume (nouvelle clé Noise générée au redémarrage)
reset:
	docker compose down -v
