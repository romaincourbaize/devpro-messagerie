# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /bin/monitor \
      .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/monitor /monitor

ENV MONITOR_TARGET=http://server:8080/healthz
ENV MONITOR_INTERVAL=10
ENV MONITOR_TIMEOUT=5

ENTRYPOINT ["/monitor"]
