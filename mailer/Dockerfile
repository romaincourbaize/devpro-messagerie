# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /bin/mailer \
      .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/mailer /mailer

ENV MAILER_ADDR=:8025
ENV MAILER_SMTP_PORT=587

EXPOSE 8025

ENTRYPOINT ["/mailer"]
