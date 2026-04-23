# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# git is required by go mod download for some VCS dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy everything first — go mod tidy needs the source files to resolve deps.
COPY . .

# Download and verify all dependencies (generates go.sum inside the builder).
# No go.sum is required in the source tree.
RUN go mod tidy && go mod download && go mod verify

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /bin/server \
      .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/server /server

# The Noise static key is stored in a named volume (see docker-compose.yml).
# It is generated automatically on first start if absent.
VOLUME ["/data"]

ENV RELAY_ADDR=:8080
ENV RELAY_KEY_FILE=/data/server.key
ENV RELAY_LOG_LEVEL=info

EXPOSE 8080

ENTRYPOINT ["/server"]