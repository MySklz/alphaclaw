# Kumo Doctor — Troubleshooting skill for AlphaClaw + Kumo

Diagnose and fix issues with the Kumo AI firewall proxy in AlphaClaw deployments.
Automates the debugging that would otherwise require SSH access and Linux knowledge.

Use when: "kumo doctor", "kumo not working", "proxy broken", "agents failing",
"TLS errors", "can't reach API", "outbound requests failing", "kumo health"

## Workflow

### Step 1: Detect deployment platform

```bash
# Check for platform indicators
[ -f fly.toml ] && echo "PLATFORM: fly.io"
[ -n "$RENDER_EXTERNAL_URL" ] && echo "PLATFORM: render"
[ -n "$RAILWAY_PROJECT_ID" ] && echo "PLATFORM: railway"
[ -z "$PLATFORM" ] && echo "PLATFORM: docker (generic)"
```

### Step 2: Read container logs

Look for `[semarang]` prefixed lines in the container logs. These are Kumo integration messages from the entrypoint.

**Fly.io:**
```bash
fly logs --app <app-name> | grep '\[semarang\]'
```

**Render:** Use GStack browser to navigate to the Render dashboard:
1. Navigate to https://dashboard.render.com
2. Find the AlphaClaw service
3. Click into Logs
4. Search for `[semarang]` entries
5. Screenshot the log output

**Railway:** Use GStack browser to navigate to the Railway dashboard:
1. Navigate to https://railway.app/dashboard
2. Find the AlphaClaw project
3. Click into Deployments → latest deployment → Logs
4. Search for `[semarang]` entries

**Docker:**
```bash
docker logs <container> 2>&1 | grep '\[semarang\]'
```

### Step 3: Check Kumo health

If the deployment URL is known:
```bash
curl -s <deploy-url>:9091/healthz
```

Note: Port 9091 may not be exposed externally on all platforms. Check the deployment config.

### Step 4: Run kumo-doctor inside the container

**Fly.io:**
```bash
fly ssh console --app <app-name> -C kumo-doctor
```

**Docker:**
```bash
docker exec <container> kumo-doctor
```

Parse the output. Focus on [FAIL] and [WARN] entries.

### Step 5: Read recent traffic logs

```bash
# Inside the container:
tail -20 /data/kumo/logs/traffic-$(date +%Y-%m-%d).jsonl | jq .
```

Look for:
- Blocked requests (decision: "block") that shouldn't be blocked
- Error patterns in responses
- Unusual hosts that might indicate proxy bypass

### Step 6: Common failure patterns

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `[FAIL] Kumo process: NOT RUNNING` | Kumo crashed or port 8080 in use | Check startup logs, restart container |
| `[FAIL] CA certificate: missing` | kumo init failed, disk full | Check disk space, run `kumo init --data-dir /data/kumo` |
| `[FAIL] Outbound test: HTTPS failed` | CA trust chain broken | Check `NODE_EXTRA_CA_CERTS`, re-run `update-ca-certificates` |
| `[WARN] Traffic logs: no entries` | Proxy not intercepting | Check `HTTP_PROXY` env var, verify `proxy-bootstrap.js` loaded |
| All API calls return 403 | Policy blocking in enforce mode | Set `KUMO_MODE=observe` and restart, or fix the policy |
| TLS certificate errors in Node | `SSL_CERT_FILE` set incorrectly | Unset `SSL_CERT_FILE`, use `NODE_EXTRA_CA_CERTS` instead |
| TLS certificate errors in Go | System CA store missing Kumo cert | Run `update-ca-certificates` |
| Agent tasks fail silently | Kumo dead = fail closed | Check Kumo process status, restart container |
| `ECONNREFUSED` on outbound calls | Kumo crashed after startup | Restart container (Kumo watcher is a future feature) |
| Container starts but UI unreachable | AlphaClaw port not exposed | Check docker-compose.yml / fly.toml port config |

### Step 7: Platform-specific admin checks

Use GStack browser (`/gstack-open-gstack-browser`) to log into the deployment platform:

**Render:**
1. Navigate to https://dashboard.render.com
2. Check service health status (green/yellow/red)
3. Check Environment tab for: KUMO_ENABLED, KUMO_MODE, SETUP_PASSWORD, API keys
4. Check recent deploy logs for build errors
5. Verify the Docker image built successfully

**Fly.io:**
```bash
fly status --app <app-name>
fly secrets list --app <app-name>
fly volumes list --app <app-name>
```
Check that the volume is mounted and has sufficient space.

**Railway:**
1. Navigate to https://railway.app/dashboard
2. Check deployment status
3. Verify environment variables are set
4. Check resource usage (memory, CPU)

### Step 8: Output diagnosis

Present findings as a structured report:

```
=== Kumo Doctor Report ===

Platform: [detected platform]
Kumo Status: [HEALTHY / DEGRADED / UNHEALTHY]

Checks:
  [PASS/FAIL] Kumo process
  [PASS/FAIL] Health endpoint
  [PASS/FAIL] CA certificate
  [PASS/FAIL] Proxy configuration
  [PASS/FAIL] Traffic interception
  [PASS/FAIL] Outbound connectivity

Issues Found:
  1. [description + fix]
  2. [description + fix]

Recommended Actions:
  1. [specific action]
  2. [specific action]
```

### Quick fixes reference

**Disable Kumo temporarily:**
Set `KUMO_ENABLED=false` in environment variables and restart.

**Reset CA certificate:**
```bash
rm -f /data/kumo/ca.pem /data/kumo/ca-key.pem
# Restart container — kumo init will regenerate
```

**Switch to observe mode:**
Set `KUMO_MODE=observe` in environment variables and restart.

**Check proxy bypass:**
```bash
# Inside container — should route through Kumo:
wget -O /dev/null https://httpbin.org/get
# Check traffic log:
tail -1 /data/kumo/logs/traffic-$(date +%Y-%m-%d).jsonl | jq .
```
