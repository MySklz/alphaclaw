#!/bin/sh
# smoke-test.sh — Integration test for the AlphaClaw + Kumo Docker image.
# Run inside the built container: docker run --rm semarang /smoke-test.sh
# Or during CI: docker run --rm -e SETUP_PASSWORD=test semarang /smoke-test.sh

set -e

PASS=0
FAIL=0

pass() { echo "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $*"; FAIL=$((FAIL + 1)); }

echo "=== Smoke Test: AlphaClaw + Kumo ==="
echo ""

# 1. Kumo binary exists
if [ -x /usr/local/bin/kumo ]; then
  pass "Kumo binary exists and is executable"
else
  fail "Kumo binary missing at /usr/local/bin/kumo"
fi

# 2. Kumo version
KUMO_VER=$(kumo version 2>/dev/null || echo "unknown")
pass "Kumo version: $KUMO_VER"

# 3. proxy-bootstrap.js exists
if [ -f /app/proxy-bootstrap.js ]; then
  pass "proxy-bootstrap.js exists at /app/proxy-bootstrap.js"
else
  fail "proxy-bootstrap.js missing"
fi

# 4. proxy-bootstrap.js loads without error
if node -e "require('/app/proxy-bootstrap.js')" 2>/dev/null; then
  pass "proxy-bootstrap.js loads without error"
else
  fail "proxy-bootstrap.js fails to load"
fi

# 5. kumo-doctor exists
if [ -x /usr/local/bin/kumo-doctor ]; then
  pass "kumo-doctor script exists and is executable"
else
  fail "kumo-doctor missing at /usr/local/bin/kumo-doctor"
fi

# 6. AlphaClaw CLI exists
if command -v alphaclaw >/dev/null 2>&1; then
  pass "alphaclaw CLI available in PATH"
else
  fail "alphaclaw CLI not found"
fi

# 7. Policy template exists
if [ -f /etc/kumo/templates/alphaclaw.yaml ]; then
  pass "AlphaClaw policy template exists"
else
  fail "AlphaClaw policy template missing"
fi

# 8. Kumo templates exist
TEMPLATE_COUNT=$(ls /etc/kumo/templates/*.yaml 2>/dev/null | wc -l | tr -d ' ')
if [ "$TEMPLATE_COUNT" -gt 0 ]; then
  pass "Kumo templates: $TEMPLATE_COUNT policy files"
else
  fail "No Kumo templates found"
fi

# 9. kumo init works (idempotent)
TMPDIR=$(mktemp -d)
if kumo init --data-dir "$TMPDIR" >/dev/null 2>&1; then
  if [ -f "$TMPDIR/ca.pem" ] && [ -f "$TMPDIR/ca-key.pem" ]; then
    pass "kumo init generates CA cert and key"
  else
    fail "kumo init ran but CA files missing"
  fi
  # Test idempotency
  if kumo init --data-dir "$TMPDIR" >/dev/null 2>&1; then
    pass "kumo init is idempotent (second run succeeds)"
  else
    fail "kumo init is NOT idempotent"
  fi
else
  fail "kumo init failed"
fi
rm -rf "$TMPDIR"

# 10. KUMO_MODE validation
ENTRYPOINT_OUT=$(KUMO_ENABLED=true KUMO_MODE=invalid /docker-entrypoint.sh echo test 2>&1 || true)
if echo "$ENTRYPOINT_OUT" | grep -q "must be 'observe' or 'enforce'"; then
  pass "KUMO_MODE validation rejects invalid values"
else
  fail "KUMO_MODE validation did not catch invalid value"
fi

# 11. KUMO_ENABLED=false bypass
BYPASS_OUT=$(KUMO_ENABLED=false /docker-entrypoint.sh echo "bypass-test" 2>&1)
if echo "$BYPASS_OUT" | grep -q "bypass-test"; then
  pass "KUMO_ENABLED=false bypasses Kumo correctly"
else
  fail "KUMO_ENABLED=false bypass failed"
fi

# 12. Docker entrypoint exists and is executable
if [ -x /docker-entrypoint.sh ]; then
  pass "docker-entrypoint.sh exists and is executable"
else
  fail "docker-entrypoint.sh missing or not executable"
fi

echo ""
echo "=== Results ==="
echo "  PASS: $PASS  FAIL: $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "  STATUS: FAILED"
  exit 1
else
  echo "  STATUS: ALL PASSED"
  exit 0
fi
