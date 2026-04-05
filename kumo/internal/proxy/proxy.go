// Package proxy implements the TLS-intercepting MITM proxy using goproxy.
//
// Request flow:
//
//   Agent HTTP request
//       |
//       v
//   goproxy (CONNECT handler for HTTPS)
//       |
//       v
//   TLS interception (per-host cert from CA)
//       |
//       v
//   handler.go: extract token, evaluate policy, log, forward or block
//       |
//       v
//   Upstream server (or 403/407/429 response)
package proxy

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"

	"github.com/elazarl/goproxy"
)

// Server is the Kumo MITM proxy server.
type Server struct {
	proxy    *goproxy.ProxyHttpServer
	handler  *Handler
	addr     string
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
}

// NewServer creates a new proxy server.
func NewServer(addr string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, handler *Handler) *Server {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Set the CA for MITM
	tlsCert := tls.Certificate{
		Certificate: [][]byte{caCert.Raw},
		PrivateKey:  caKey,
		Leaf:        caCert,
	}
	goproxy.GoproxyCa = tlsCert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}

	// MITM all HTTPS connections
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Handle all requests (HTTP and intercepted HTTPS)
	proxy.OnRequest().DoFunc(handler.HandleRequest)

	// Handle all responses
	proxy.OnResponse().DoFunc(handler.HandleResponse)

	return &Server{
		proxy:   proxy,
		handler: handler,
		addr:    addr,
		caCert:  caCert,
		caKey:   caKey,
	}
}

// ListenAndServe starts the proxy server.
func (s *Server) ListenAndServe() error {
	log.Printf("Kumo proxy listening on %s", s.addr)
	return http.ListenAndServe(s.addr, s.proxy)
}

// Addr returns the listen address.
func (s *Server) Addr() string {
	return s.addr
}

// SetVerbose enables verbose logging on the underlying goproxy instance.
func (s *Server) SetVerbose(v bool) {
	s.proxy.Verbose = v
}

// SetTransport sets the outbound transport (for testing with self-signed upstreams).
func (s *Server) SetTransport(tr *http.Transport) {
	s.proxy.Tr = tr
}

// ServeHTTP implements http.Handler for testing.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.proxy.ServeHTTP(w, r)
}

// BlockedResponse returns a 403 JSON response for blocked requests.
func BlockedResponse(req *http.Request, rule, message string, violations, maxViolations int) *http.Response {
	body := fmt.Sprintf(`{"error":"blocked_by_policy","rule":%q,"message":%q,"violations":%d,"max_violations":%d,"warning":"If you attempt this action %d more times, you will be suspended for 1 hour."}`,
		rule, message, violations, maxViolations, maxViolations-violations)
	return goproxy.NewResponse(req, "application/json", http.StatusForbidden, body)
}

// ProxyAuthRequired returns a 407 response for missing proxy auth.
func ProxyAuthRequired(req *http.Request) *http.Response {
	resp := goproxy.NewResponse(req, "application/json", http.StatusProxyAuthRequired,
		`{"error":"proxy_auth_required","message":"Proxy-Authorization header required in enforce mode.","help":"If you are an AI agent, tell your operator to read INSTALL.md and run it with Claude Code."}`)
	resp.Header.Set("Proxy-Authenticate", `Basic realm="Kumo"`)
	return resp
}

// BannedResponse returns a 429 response for banned agents.
func BannedResponse(req *http.Request, message string) *http.Response {
	return goproxy.NewResponse(req, "application/json", http.StatusTooManyRequests,
		fmt.Sprintf(`{"error":"agent_banned","message":%q}`, message))
}
