// Package proxy is the HTTP surface: route table, middleware chain,
// enrichers and response hooks. The route table is the authorization
// coverage — reviewing it beside model.fga is the security review.
package proxy

import (
	"net/http"

	"podmanproxy/internal/audit"
	"podmanproxy/internal/authz"
	"podmanproxy/internal/podman"
)

// Server wires the authorization pipeline in front of the podman socket.
// Dependencies arrive through New; nothing here constructs its own, which
// is what keeps the fake-Authorizer test story trivial.
type Server struct {
	authorizer authz.Authorizer
	tuples     authz.TupleWriter
	enrichers  []Enricher
	sessions   *podman.SessionStore
	audit      *audit.Logger
	handler    http.Handler
}

// Config holds the non-dependency knobs.
type Config struct {
	PodmanSocket string
}

// New builds the server. The authorizer is an interface, so tests inject a
// fake and never start OpenFGA; only cmd/proxyd knows the FGA adapter exists.
func New(cfg Config, authorizer authz.Authorizer, tuples authz.TupleWriter, auditLog *audit.Logger) *Server {
	s := &Server{
		authorizer: authorizer,
		tuples:     tuples,
		sessions:   podman.NewSessionStore(),
		audit:      auditLog,
	}
	s.enrichers = []Enricher{
		GroupEnricher{},
		ExecEnricher{Sessions: s.sessions},
	}
	backend := podman.NewReverseProxy(cfg.PodmanSocket, s.modifyResponse)
	s.handler = s.buildMux(backend)
	return s
}

// ServeHTTP makes Server the http.Handler for the listener.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
