package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"podmanproxy/internal/authz"
	"podmanproxy/internal/identity"
)

// middleware is the standard net/http decorator shape.
type middleware func(http.Handler) http.Handler

// chain composes middlewares so they execute in the order listed:
//
//	chain(h, a, b, c) == a(b(c(h)))
func chain(h http.Handler, mws ...middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// buildMux wires the pipeline. Two scopes, visible at a glance:
//
//	global (wraps the mux, so even the deny-all catch-all is covered):
//	    requestID -> authenticate
//	per route (wraps the backend, after routing so {id} is bound):
//	    authorize -> listScope -> annotate -> backend
func (s *Server) buildMux(backend http.Handler) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.Handle(rt.pattern, chain(backend,
			s.authorize(rt),
			s.listScope(rt),
			annotate(rt),
		))
	}
	// Deny by default: unknown paths, including the entire docker-compat
	// surface, never reach podman.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	return chain(mux,
		requestID(),
		authenticate(),
	)
}

// ---- global middlewares ----

// requestID tags every request for audit correlation and echoes it, so a
// user report maps to an audit line.
func requestID() middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := newRequestID()
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), id)))
		})
	}
}

// authenticate requires a subject, placed in the connection context by
// identity.ConnContext from SO_PEERCRED.
func authenticate() middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := identity.FromContext(r.Context()); !ok {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---- per-route middlewares ----

// authorize is the choke point: derive facts, evaluate the route's
// requirements, audit the outcome, then deny or stamp the decision into
// context for the guarded transport.
//
// The steps are one middleware rather than three because they form a single
// atomic security operation: splitting them would let a later edit reorder
// or drop one. Chain granularity follows invariant boundaries.
func (s *Server) authorize(rt route) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			sub, _ := identity.FromContext(ctx) // guaranteed by authenticate
			reqID := requestIDFrom(ctx)

			reqs, err := rt.require(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			facts, err := RunEnrichers(s.enrichers, r, sub)
			if err != nil { // fail closed: fewer facts = different inputs
				slog.Error("enrichment failed", "request_id", reqID, "err", err)
				http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
				return
			}

			start := time.Now()
			d, err := s.authorizer.Authorize(ctx, sub, reqs, facts)
			if err != nil {
				// Infrastructure failure is not denial: distinguish it for
				// operators, but fail closed either way.
				level := slog.LevelError
				if !errors.Is(err, authz.ErrUnavailable) {
					level = slog.LevelWarn
				}
				slog.Log(ctx, level, "authorization failed", "request_id", reqID, "err", err)
				http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
				return
			}

			s.audit.Decision(ctx, reqID, r.Method, r.URL.Path, d, time.Since(start))
			if !d.Allowed {
				// Uniform 403 before forwarding: deny and not-exist must not
				// diverge, or low-entropy container names become an
				// existence oracle.
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			ctx = authz.WithDecision(ctx, d)
			ctx = withFacts(ctx, facts)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// listScope resolves the subject's visible object set for list endpoints,
// using the same facts the decision was evaluated with.
func (s *Server) listScope(rt route) middleware {
	return func(next http.Handler) http.Handler {
		if rt.list == nil {
			return next // resolved once at wiring time, not per request
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			sub, _ := identity.FromContext(ctx)
			ids, err := s.authorizer.ListIDs(ctx, sub, *rt.list, factsFrom(ctx))
			if err != nil {
				slog.Error("list scope failed", "request_id", requestIDFrom(ctx), "err", err)
				http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r.WithContext(withVisibleIDs(ctx, ids)))
		})
	}
}

// annotate sets markers consumed by the response hooks. Pure bookkeeping.
func annotate(rt route) middleware {
	return func(next http.Handler) http.Handler {
		if rt.owned == "" && !rt.execSession {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if rt.owned != "" {
				sub, _ := identity.FromContext(ctx)
				ctx = withOwnership(ctx, ownership{objType: rt.owned, subject: sub})
			}
			if rt.execSession {
				ctx = withExecParent(ctx, r.PathValue("id"))
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ---- context plumbing: unexported keys, typed accessors ----

type (
	requestIDKey  struct{}
	factsKey      struct{}
	visibleIDsKey struct{}
	ownershipKey  struct{}
	execParentKey struct{}
)

type ownership struct {
	objType string
	subject authz.Subject
}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func withFacts(ctx context.Context, f []authz.Tuple) context.Context {
	return context.WithValue(ctx, factsKey{}, f)
}

func factsFrom(ctx context.Context) []authz.Tuple {
	f, _ := ctx.Value(factsKey{}).([]authz.Tuple)
	return f
}

func withVisibleIDs(ctx context.Context, ids map[string]bool) context.Context {
	return context.WithValue(ctx, visibleIDsKey{}, ids)
}

func visibleIDsFrom(ctx context.Context) (map[string]bool, bool) {
	ids, ok := ctx.Value(visibleIDsKey{}).(map[string]bool)
	return ids, ok
}

func withOwnership(ctx context.Context, o ownership) context.Context {
	return context.WithValue(ctx, ownershipKey{}, o)
}

func ownershipFrom(ctx context.Context) (ownership, bool) {
	o, ok := ctx.Value(ownershipKey{}).(ownership)
	return o, ok
}

func withExecParent(ctx context.Context, containerID string) context.Context {
	return context.WithValue(ctx, execParentKey{}, containerID)
}

func execParentFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(execParentKey{}).(string)
	return id, ok
}
