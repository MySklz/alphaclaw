// proxy-bootstrap.js — Patches Node 22's built-in fetch (undici) to respect HTTP_PROXY/HTTPS_PROXY.
// Without this, fetch() calls bypass the proxy entirely.
// Loaded via NODE_OPTIONS=--require in docker-entrypoint.sh.
//
// Why: Node 22's fetch uses undici, which does NOT honor proxy env vars by default.
// AlphaClaw uses fetch() in 15+ files (telegram-api.js, discord-api.js, slack-api.js,
// routes/google.js, onboarding/github.js, etc.). The OpenClaw gateway (Go binary)
// respects HTTP_PROXY natively via net/http — this file is only needed for Node.js.

'use strict';

const { EnvHttpProxyAgent, setGlobalDispatcher } = require('undici');
setGlobalDispatcher(new EnvHttpProxyAgent());
