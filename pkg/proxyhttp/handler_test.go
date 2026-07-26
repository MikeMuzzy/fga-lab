package proxyhttp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"fga-lib/pkg/authn"
	"fga-lib/pkg/authz"
)

// newTestHandler builds a Handler backed by a real (in-memory) FGA
// authorizer, seeded so uid 1000 may recursively list anything under
// /data, and nothing else.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()

	fga, err := authz.NewFGA()
	if err != nil {
		t.Fatalf("NewFGA: %v", err)
	}

	sub := authz.Subject{UID: 1000}
	err = fga.WriteGrants(context.Background(),
		authz.Grant{
			Object:   "path_grant:mnt1",
			Relation: "holder",
			User:     sub.String(),
		},
		authz.Grant{
			Object:           "filesystem:host",
			Relation:         "recursive_list_grant",
			User:             "path_grant:mnt1",
			Condition:        "path_matches",
			ConditionContext: authz.Context{"allowed_pattern": "^/data/.*"},
		},
	)
	if err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	return &Handler{Authn: authn.Stub{}, Authz: fga}
}

func doRequest(t *testing.T, h *Handler, uid, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))
	if uid != "" {
		req.Header.Set("X-Debug-Uid", uid)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_AllowsPermittedMount(t *testing.T) {
	h := newTestHandler(t)

	rec := doRequest(t, h, "1000", `{"Mounts":[{"Type":"bind","Source":"/data/app","Target":"/app"}]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestHandler_DeniesUnpermittedMount(t *testing.T) {
	h := newTestHandler(t)

	rec := doRequest(t, h, "1000", `{"Mounts":[{"Type":"bind","Source":"/etc/passwd","Target":"/etc/passwd"}]}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestHandler_DeniesWhenAnyMountUnpermitted(t *testing.T) {
	h := newTestHandler(t)

	rec := doRequest(t, h, "1000", `{"Mounts":[
		{"Type":"bind","Source":"/data/app","Target":"/app"},
		{"Type":"bind","Source":"/etc/passwd","Target":"/etc/passwd"}
	]}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestHandler_DeniesUnknownSubject(t *testing.T) {
	h := newTestHandler(t)

	rec := doRequest(t, h, "2000", `{"Mounts":[{"Type":"bind","Source":"/data/app","Target":"/app"}]}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestHandler_AllowsRequestWithNoMounts(t *testing.T) {
	h := newTestHandler(t)

	rec := doRequest(t, h, "1000", `{}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestHandler_RejectsUnauthenticatedRequest(t *testing.T) {
	h := newTestHandler(t)

	rec := doRequest(t, h, "", `{"Mounts":[{"Type":"bind","Source":"/data/app","Target":"/app"}]}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestHandler_RejectsInvalidJSON(t *testing.T) {
	h := newTestHandler(t)

	rec := doRequest(t, h, "1000", `not json`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
