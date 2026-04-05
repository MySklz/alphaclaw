# Dockerfile — AlphaClaw + Kumo ("Secure OpenClaw")
# Multi-stage build: Go binary (Kumo) + Node.js app (AlphaClaw) in one image.
# Kumo intercepts all outbound HTTP/HTTPS for observability and security.

# ---------------------------------------------------------------------------
# Stage 1: Build Kumo from vendored Go source
# ---------------------------------------------------------------------------
FROM golang:1.26-alpine AS kumo-builder
WORKDIR /src
COPY kumo/go.mod kumo/go.sum ./
RUN go mod download
COPY kumo/ .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /kumo ./cmd/kumo

# ---------------------------------------------------------------------------
# Stage 2: Runtime — node:22-slim with AlphaClaw + Kumo
# ---------------------------------------------------------------------------
FROM node:22-slim

RUN apt-get update && \
    apt-get install -y git curl procps cron ca-certificates wget openssl && \
    rm -rf /var/lib/apt/lists/*

# Kumo binary + policy templates
COPY --from=kumo-builder /kumo /usr/local/bin/kumo
COPY kumo/templates/ /etc/kumo/templates/

# AlphaClaw
WORKDIR /app
COPY . .
RUN npm install
RUN npm run build:ui
RUN npm prune --omit=dev
ENV PATH="/app/node_modules/.bin:$PATH"
ENV ALPHACLAW_ROOT_DIR=/data

# Entrypoint + proxy bootstrap + diagnostics
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
COPY proxy-bootstrap.js /app/proxy-bootstrap.js
COPY kumo-doctor.sh /usr/local/bin/kumo-doctor
RUN chmod +x /usr/local/bin/kumo-doctor

EXPOSE 3000 9091
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["alphaclaw", "start"]
