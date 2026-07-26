// Package proxyhttp is the HTTP front door for the container-create proxy.
// It holds no authorization policy itself: it authenticates the caller,
// asks pkg/authz whether the request's mounts are permitted, and forwards
// (or rejects) based on the resulting Decision.
package proxyhttp

import (
	"context"
	"log/slog"
	"net/http"

	"fga-lib/pkg/authz"
)

// // DefaultFilesystemID is the filesystem object checked against when Handler
// // is not given one explicitly. The model currently protects a single
// // filesystem, "host".
// const DefaultFilesystemID = "host"
//
// // Mount mirrors the subset of a container mount spec (as used by the
// // docker/podman container-create API) that the mount policy inspects.
//
//	type Mount struct {
//		Type   string `json:"Type"`
//		Source string `json:"Source"`
//		Target string `json:"Target"`
//	}
//
// // ContainerRequest is the subset of a container-create request body this
// // proxy inspects before deciding whether to forward it.
//
//	type ContainerRequest struct {
//		Mounts []Mount `json:"Mounts"`
//	}
//
// Handler authorizes container-create requests by their Mounts and forwards
// permitted ones. Authn and Authz are required; FilesystemID defaults to
// DefaultFilesystemID when empty.
//type Handler struct {
//	Authn        authn.Authenticator
//	Authz        authz.Authorizer
//	FilesystemID string
//}

//
//func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
//	if r.Method != http.MethodPost {
//		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
//		return
//	}
//
//	sub, err := h.Authn.Authenticate(r)
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusUnauthorized)
//		return
//	}
//
//	var req ContainerRequest
//	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//		http.Error(w, "invalid json body", http.StatusBadRequest)
//		return
//	}
//
//	decision, err := h.authorize(r.Context(), sub, req)
//	if err != nil {
//		http.Error(w, "authorization check failed", http.StatusInternalServerError)
//		return
//	}
//
//	if err := h.forward(authz.WithDecision(r.Context(), decision), w); err != nil {
//		http.Error(w, err.Error(), http.StatusForbidden)
//		return
//	}
//}
//
//// authorize checks every mount source in req against the can_recursive_list
//// permission. A request with no mounts has nothing to authorize and is
//// allowed trivially; BatchCheck denies on an empty check set, which is the
//// right default for "no evidence of permission" but wrong here, where an
//// empty set means there was nothing to permit in the first place.
//func (h *Handler) authorize(ctx context.Context, sub authz.Subject, req ContainerRequest) (authz.Decision, error) {
//	if len(req.Mounts) == 0 {
//		return authz.Decision{Allowed: true, Subject: sub.String()}, nil
//	}
//
//	checks := make([]authz.Check, len(req.Mounts))
//	for i, m := range req.Mounts {
//		checks[i] = authz.CanRecursiveList.
//			On(h.filesystemID()).
//			WithContext(authz.Context{"requested_path": m.Source})
//	}
//
//	return h.Authz.BatchCheck(ctx, sub, checks)
//}
//
//// forward stands in for handing the request to the podman transport, which
//// does not exist yet. It enforces the same fail-closed invariant the real
//// transport will: no Decision in context, or a denied Decision, means the
//// request does not proceed.
//func (h *Handler) forward(ctx context.Context, w http.ResponseWriter) error {
//	decision, ok := authz.DecisionFrom(ctx)
//	if !ok {
//		return authz.ErrNoDecision
//	}
//	if !decision.Allowed {
//		return fmt.Errorf("forbidden")
//	}
//
//	w.WriteHeader(http.StatusOK)
//	return nil
//}
//
//func (h *Handler) filesystemID() string {
//	if h.FilesystemID == "" {
//		return DefaultFilesystemID
//	}
//	return h.FilesystemID
//}

type subjectKey struct{}
type allowedKey struct{}
type ownedKey struct{}

type owned struct {
	objType string
	sub     authz.Subject
}

func authorize(a *authz.FGA, rt route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, ok := r.Context().Value(subjectKey{}).(authz.Subject)
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
