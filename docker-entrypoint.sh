#!/bin/sh
set -e

# docker-entrypoint.sh — Orchestrates Kumo (AI firewall proxy) + AlphaClaw startup.
# Kumo intercepts all outbound HTTP/HTTPS traffic for observability and security.
# All log lines prefixed with [semarang] for easy filtering.

log() { echo "[semarang] $*"; }
err() { echo "[semarang] ERROR: $*" >&2; }
hint() { echo "[semarang] HINT: $*" >&2; }

# ---------------------------------------------------------------------------
# Bypass Kumo entirely if disabled
# ---------------------------------------------------------------------------
if [ "${KUMO_ENABLED}" = "false" ]; then
  log "Kumo disabled (KUMO_ENABLED=false), starting AlphaClaw directly"
  exec "$@"
fi

KUMO_DATA_DIR="${KUMO_DATA_DIR:-/data/kumo}"
KUMO_MODE="${KUMO_MODE:-observe}"

log "Starting Kumo integration..."
log "  KUMO_MODE=$KUMO_MODE"
log "  KUMO_DATA_DIR=$KUMO_DATA_DIR"

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
case "$KUMO_MODE" in
  observe|enforce) ;;
  *) err "KUMO_MODE must be 'observe' or 'enforce', got '$KUMO_MODE'"; exit 1 ;;
esac

KUMO_POLICY_FLAG=""
if [ -n "$KUMO_POLICY_PATH" ]; then
  log "  KUMO_POLICY_PATH=$KUMO_POLICY_PATH"
  if echo "$KUMO_POLICY_PATH" | grep -q ' '; then
    err "KUMO_POLICY_PATH must not contain spaces"; exit 1
  fi
  if [ ! -f "$KUMO_POLICY_PATH" ]; then
    err "Policy file not found: $KUMO_POLICY_PATH"; exit 1
  fi
  KUMO_POLICY_FLAG="--policy $KUMO_POLICY_PATH"
fi

mkdir -p "$KUMO_DATA_DIR"

# ---------------------------------------------------------------------------
# 1. Initialize CA certificate (idempotent)
# ---------------------------------------------------------------------------
log "Initializing CA certificate..."
kumo init --data-dir "$KUMO_DATA_DIR"
chmod 0600 "$KUMO_DATA_DIR/ca-key.pem" 2>/dev/null || true

if [ -f "$KUMO_DATA_DIR/ca.pem" ]; then
  EXPIRY=$(openssl x509 -enddate -noout -in "$KUMO_DATA_DIR/ca.pem" 2>/dev/null | cut -d= -f2 || echo "unknown")
  log "CA certificate: $KUMO_DATA_DIR/ca.pem (expires $EXPIRY)"
else
  err "CA certificate was not generated"
  hint "Check disk space and permissions on $KUMO_DATA_DIR"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Trust CA in system store (for Go processes like OpenClaw gateway)
# ---------------------------------------------------------------------------
log "Trusting CA in system store..."
cp "$KUMO_DATA_DIR/ca.pem" /usr/local/share/ca-certificates/kumo.crt
update-ca-certificates 2>/dev/null || log "WARN: update-ca-certificates failed (non-fatal)"

# ---------------------------------------------------------------------------
# 3. Set proxy environment variables for all child processes
# ---------------------------------------------------------------------------
# NODE_EXTRA_CA_CERTS adds Kumo's CA to Node.js built-in roots (does not replace them).
# Do NOT set SSL_CERT_FILE — it replaces the entire system CA bundle, breaking
# upstream TLS validation for Go processes (they'd reject real certs like DigiCert).
export NODE_EXTRA_CA_CERTS="$KUMO_DATA_DIR/ca.pem"
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
# NO_PROXY excludes ALL 127.0.0.1 traffic including OpenClaw gateway on :18789
export NO_PROXY="127.0.0.1,localhost,::1"
# Append to NODE_OPTIONS (don't replace) to preserve operator settings
export NODE_OPTIONS="${NODE_OPTIONS:-} --require /app/proxy-bootstrap.js"
log "Proxy configured: HTTP_PROXY=$HTTP_PROXY"

# ---------------------------------------------------------------------------
# 4. Start Kumo in background
# ---------------------------------------------------------------------------
log "Starting Kumo proxy on :8080 (health: :9091)..."
KUMO_STDERR=$(mktemp /tmp/kumo-stderr-XXXXXX)

if [ "$KUMO_MODE" = "enforce" ] && [ -n "$KUMO_POLICY_FLAG" ]; then
  kumo serve --mode "$KUMO_MODE" --data-dir "$KUMO_DATA_DIR" $KUMO_POLICY_FLAG 2>"$KUMO_STDERR" &
else
  kumo serve --mode "$KUMO_MODE" --data-dir "$KUMO_DATA_DIR" 2>"$KUMO_STDERR" &
fi
KUMO_PID=$!

# ---------------------------------------------------------------------------
# 5. Wait for Kumo to become healthy
# ---------------------------------------------------------------------------
for i in $(seq 1 30); do
  # Check if Kumo process is still alive
  if ! kill -0 "$KUMO_PID" 2>/dev/null; then
    err "Kumo process exited unexpectedly (PID $KUMO_PID)"
    err "Kumo stderr:"
    cat "$KUMO_STDERR" >&2 2>/dev/null
    hint "Check if port 8080 is already in use"
    hint "Run with KUMO_ENABLED=false to bypass Kumo"
    rm -f "$KUMO_STDERR"
    exit 1
  fi
  # Check health endpoint
  if wget -q --spider http://localhost:9091/healthz 2>/dev/null; then
    log "Kumo healthy after ${i}s"
    break
  fi
  if [ "$i" -eq 30 ]; then
    err "Kumo health check timed out after 30s"
    err "Kumo stderr:"
    cat "$KUMO_STDERR" >&2 2>/dev/null
    hint "Kumo may be starting slowly. Check container resources."
    hint "Run with KUMO_ENABLED=false to bypass Kumo"
    rm -f "$KUMO_STDERR"
    exit 1
  fi
  sleep 1
done
rm -f "$KUMO_STDERR"

log "Kumo ready (PID $KUMO_PID, mode=$KUMO_MODE)"
log "Traffic logs: $KUMO_DATA_DIR/logs/"
log "Run 'kumo-doctor' inside the container to diagnose issues"

# ---------------------------------------------------------------------------
# 6. Forward signals to Kumo on shutdown
# ---------------------------------------------------------------------------
trap "log 'Shutting down Kumo...'; kill $KUMO_PID 2>/dev/null; wait $KUMO_PID 2>/dev/null" EXIT TERM INT

# ---------------------------------------------------------------------------
# 7. Start AlphaClaw
# ---------------------------------------------------------------------------
log "Starting AlphaClaw..."
exec "$@"
