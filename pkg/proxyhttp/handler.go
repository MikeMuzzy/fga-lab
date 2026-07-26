// Package proxyhttp is the HTTP front door for the container-create proxy.
// It holds no authorization policy itself: it authenticates the caller,
// asks pkg/authz whether the request's mounts are permitted, and forwards
// (or rejects) based on the resulting Decision.
package proxyhttp

import (
	"context"
	"log/slog"
	"net/http"

	"fga-lib/pkg/authn"
	"fga-lib/pkg/authz"
)

type allowedKey struct{}
type ownedKey struct{}

type owned struct {
	objType string
	sub     authz.Subject
}

func authorize(a *authz.FGA, rt route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, ok := authn.SubjectFrom(r.Context())
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		checks, err := rt.checks(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d, err := a.BatchCheck(r.Context(), sub, checks)
		if err != nil { // infrastructure failure: fail closed
			slog.Error("authz unavailable", "err", err)
			http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
			return
		}
		audit(r, d) // every decision, allow AND deny, with model version
		if !d.Allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		ctx := authz.WithDecision(r.Context(), d)
		if rt.list != nil {
			ids, err := a.ListIDs(ctx, sub, *rt.list)
			if err != nil {
				http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
				return
			}
			ctx = context.WithValue(ctx, allowedKey{}, ids)
		}
		if rt.owned != "" {
			ctx = context.WithValue(ctx, ownedKey{}, owned{objType: rt.owned, sub: sub})
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func audit(r *http.Request, d authz.Decision) {
	slog.Info("authz.decision",
		"subject", d.Subject,
		"allowed", d.Allowed,
		"method", r.Method,
		"path", r.URL.Path,
		"model_id", d.ModelID,
		"checks", len(d.Checks),
	)
}

func BuildMux(a *authz.FGA, backend http.Handler) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.Handle(rt.pattern, authorize(a, rt, backend))
	}
	// Deny by default: unknown paths, including the entire docker-compat
	// surface, never reach podman. Coverage is structural, not discipline.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	return mux
}
