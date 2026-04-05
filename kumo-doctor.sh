#!/bin/sh
# kumo-doctor.sh — Diagnose Kumo integration health inside the container.
# Usage: kumo-doctor (run inside the AlphaClaw+Kumo container)
#
# Checks: Kumo process, health endpoint, CA certificate, system trust,
# Node trust, proxy env vars, proxy-bootstrap.js, traffic logs, outbound test.

set -e

echo "=== Kumo Doctor ==="
echo ""

PASS=0
FAIL=0
WARN=0

pass() { echo "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $*"; FAIL=$((FAIL + 1)); }
warn() { echo "[WARN] $*"; WARN=$((WARN + 1)); }
info() { echo "[INFO] $*"; }

KUMO_DATA_DIR="${KUMO_DATA_DIR:-/data/kumo}"

# ---------------------------------------------------------------------------
# 1. Process check
# ---------------------------------------------------------------------------
KUMO_PID=$(pgrep -x kumo 2>/dev/null || true)
if [ -n "$KUMO_PID" ]; then
  pass "Kumo process: running (PID $KUMO_PID)"
else
  fail "Kumo process: NOT RUNNING"
  echo "  HINT: Check container logs for [semarang] errors"
  echo "  HINT: Restart container, or run: kumo serve --mode observe --data-dir $KUMO_DATA_DIR &"
fi

# ---------------------------------------------------------------------------
# 2. Health endpoint
# ---------------------------------------------------------------------------
if wget -q --spider http://localhost:9091/healthz 2>/dev/null; then
  pass "Kumo health: ok (http://localhost:9091/healthz)"
else
  fail "Kumo health: unreachable (port 9091)"
  echo "  HINT: Kumo may not be running or may have crashed"
fi

# ---------------------------------------------------------------------------
# 3. CA certificate
# ---------------------------------------------------------------------------
if [ -f "$KUMO_DATA_DIR/ca.pem" ]; then
  EXPIRY=$(openssl x509 -enddate -noout -in "$KUMO_DATA_DIR/ca.pem" 2>/dev/null | cut -d= -f2 || echo "unknown")
  pass "CA certificate: valid (expires $EXPIRY)"
else
  fail "CA certificate: missing at $KUMO_DATA_DIR/ca.pem"
  echo "  HINT: Run: kumo init --data-dir $KUMO_DATA_DIR"
fi

# ---------------------------------------------------------------------------
# 4. CA key permissions
# ---------------------------------------------------------------------------
if [ -f "$KUMO_DATA_DIR/ca-key.pem" ]; then
  PERMS=$(stat -c '%a' "$KUMO_DATA_DIR/ca-key.pem" 2>/dev/null || stat -f '%Lp' "$KUMO_DATA_DIR/ca-key.pem" 2>/dev/null || echo "unknown")
  if [ "$PERMS" = "600" ]; then
    pass "CA key permissions: 0600 (restricted)"
  else
    warn "CA key permissions: $PERMS (should be 0600)"
    echo "  HINT: Run: chmod 0600 $KUMO_DATA_DIR/ca-key.pem"
  fi
fi

# ---------------------------------------------------------------------------
# 5. System trust store
# ---------------------------------------------------------------------------
if [ -f /usr/local/share/ca-certificates/kumo.crt ]; then
  pass "CA trusted (system): installed at /usr/local/share/ca-certificates/kumo.crt"
else
  warn "CA trusted (system): not installed"
  echo "  HINT: Run: cp $KUMO_DATA_DIR/ca.pem /usr/local/share/ca-certificates/kumo.crt && update-ca-certificates"
fi

# ---------------------------------------------------------------------------
# 6. Node.js trust
# ---------------------------------------------------------------------------
if [ -n "$NODE_EXTRA_CA_CERTS" ] && [ -f "$NODE_EXTRA_CA_CERTS" ]; then
  pass "CA trusted (Node): NODE_EXTRA_CA_CERTS=$NODE_EXTRA_CA_CERTS"
else
  warn "CA trusted (Node): NODE_EXTRA_CA_CERTS not set or file missing"
  echo "  HINT: Set NODE_EXTRA_CA_CERTS=$KUMO_DATA_DIR/ca.pem"
fi

# ---------------------------------------------------------------------------
# 7. SSL_CERT_FILE check (should NOT be set)
# ---------------------------------------------------------------------------
if [ -n "$SSL_CERT_FILE" ]; then
  warn "SSL_CERT_FILE is set ($SSL_CERT_FILE) — this may break upstream TLS"
  echo "  HINT: Unset SSL_CERT_FILE. Use update-ca-certificates instead."
else
  pass "SSL_CERT_FILE: not set (correct — using system trust store)"
fi

# ---------------------------------------------------------------------------
# 8. Proxy environment variables
# ---------------------------------------------------------------------------
if [ -n "$HTTP_PROXY" ]; then
  pass "Proxy: HTTP_PROXY=$HTTP_PROXY"
else
  fail "Proxy: HTTP_PROXY not set"
  echo "  HINT: Kumo is not intercepting traffic. Set HTTP_PROXY=http://127.0.0.1:8080"
fi

if [ -n "$HTTPS_PROXY" ]; then
  pass "Proxy: HTTPS_PROXY=$HTTPS_PROXY"
else
  fail "Proxy: HTTPS_PROXY not set"
fi

if [ -n "$NO_PROXY" ]; then
  pass "No-proxy: NO_PROXY=$NO_PROXY"
else
  warn "NO_PROXY not set — localhost traffic may route through Kumo (breaks internal gateway)"
fi

# ---------------------------------------------------------------------------
# 9. proxy-bootstrap.js
# ---------------------------------------------------------------------------
if echo "$NODE_OPTIONS" | grep -q "proxy-bootstrap" 2>/dev/null; then
  pass "proxy-bootstrap.js: loaded via NODE_OPTIONS"
else
  warn "proxy-bootstrap.js: not in NODE_OPTIONS (Node fetch may bypass proxy)"
  echo "  HINT: Set NODE_OPTIONS=\"--require /app/proxy-bootstrap.js\""
fi

# ---------------------------------------------------------------------------
# 10. Traffic logs
# ---------------------------------------------------------------------------
LOG_DIR="$KUMO_DATA_DIR/logs"
TODAY=$(date +%Y-%m-%d)
LOG_FILE="$LOG_DIR/traffic-$TODAY.jsonl"
if [ -f "$LOG_FILE" ]; then
  COUNT=$(wc -l < "$LOG_FILE" 2>/dev/null | tr -d ' ')
  LAST_TS=$(tail -1 "$LOG_FILE" 2>/dev/null | grep -o '"ts":"[^"]*"' | head -1 || echo "")
  pass "Traffic logs: $COUNT entries today ${LAST_TS}"
else
  warn "Traffic logs: no entries today ($LOG_FILE)"
  echo "  HINT: Traffic may not be routing through Kumo yet"
  echo "  HINT: Check HTTP_PROXY and proxy-bootstrap.js"
fi

# ---------------------------------------------------------------------------
# 11. Test outbound HTTPS request
# ---------------------------------------------------------------------------
if [ -n "$KUMO_PID" ]; then
  if wget -q -O /dev/null --timeout=10 https://httpbin.org/get 2>/dev/null; then
    pass "Outbound test: HTTPS request through proxy succeeded"
  else
    fail "Outbound test: HTTPS request failed"
    echo "  HINT: Check CA trust chain and proxy configuration"
    echo "  HINT: Try: wget --no-check-certificate https://httpbin.org/get"
  fi
else
  info "Outbound test: skipped (Kumo not running)"
fi

# ---------------------------------------------------------------------------
# 12. Mode and policy info
# ---------------------------------------------------------------------------
echo ""
info "KUMO_MODE=${KUMO_MODE:-observe}"
info "KUMO_ENABLED=${KUMO_ENABLED:-true}"
[ -n "$KUMO_POLICY_PATH" ] && info "KUMO_POLICY_PATH=$KUMO_POLICY_PATH"
info "KUMO_DATA_DIR=$KUMO_DATA_DIR"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Summary ==="
echo "  PASS: $PASS  FAIL: $FAIL  WARN: $WARN"
if [ "$FAIL" -gt 0 ]; then
  echo "  STATUS: UNHEALTHY — fix FAIL items above"
  exit 1
elif [ "$WARN" -gt 0 ]; then
  echo "  STATUS: DEGRADED — check WARN items above"
  exit 0
else
  echo "  STATUS: HEALTHY"
  exit 0
fi
