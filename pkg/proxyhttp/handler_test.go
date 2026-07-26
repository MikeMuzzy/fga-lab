package proxyhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fga-lib/pkg/authn"
	"fga-lib/pkg/authz"
)

// newTestFGA builds a real (in-memory) FGA authorizer and seeds it with
// grants sufficient to exercise both routes.go's route table and the
// filesystem path_matches condition: uid 1000 may create containers using
// the "alpine" image, mount anything under /data, view host info, and view
// (as owner) container "a".
func newTestFGA(t *testing.T) *authz.FGA {
	t.Helper()

	fga, err := authz.NewFGA()
	if err != nil {
		t.Fatalf("NewFGA: %v", err)
	}

	sub := authz.Subject{UID: 1000}
	err = fga.WriteGrants(t.Context(),
		authz.Grant{Object: "host:local", Relation: "can_create", User: sub.String()},
		authz.Grant{Object: "host:local", Relation: "can_view_info", User: sub.String()},
		authz.Grant{Object: "image:alpine", Relation: "can_use", User: sub.String()},
		authz.Grant{Object: "container:a", Relation: "owner", User: sub.String()},
		authz.Grant{
			Object:   "path_grant:mnt1",
			Relation: "holder",
			User:     sub.String(),
		},
		authz.Grant{
			Object:           "filesystem:host",
			Relation:         "mount_grant",
			User:             "path_grant:mnt1",
			Condition:        "path_matches",
			ConditionContext: authz.Context{"allowed_pattern": "^/data/.*"},
		},
	)
	if err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	return fga
}

// recordingBackend is the stand-in "podman" target. It records whether it
// was reached and captures the request-scoped context BuildMux's authorize
// middleware attaches on success, so tests can assert on the plumbing
// without a real reverse proxy.
type recordingBackend struct {
	called  bool
	allowed map[string]bool
	owned   *owned
}

func (b *recordingBackend) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.called = true
		if ids, ok := r.Context().Value(allowedKey{}).(map[string]bool); ok {
			b.allowed = ids
		}
		if o, ok := r.Context().Value(ownedKey{}).(owned); ok {
			b.owned = &o
		}
		w.WriteHeader(http.StatusOK)
	})
}

func newRequest(t *testing.T, method, target string, body string, sub *authz.Subject) *http.Request {
	t.Helper()

	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	if sub != nil {
		r = r.WithContext(authn.WithSubject(r.Context(), *sub))
	}
	return r
}

func TestBuildMux_RejectsUnauthenticatedRequest(t *testing.T) {
	fga := newTestFGA(t)
	backend := &recordingBackend{}
	mux := BuildMux(fga, backend.Handler())

	req := newRequest(t, http.MethodGet, "/v5/libpod/info", "", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if backend.called {
		t.Error("backend was reached for an unauthenticated request")
	}
}

func TestBuildMux_DeniesUnmappedRouteByDefault(t *testing.T) {
	fga := newTestFGA(t)
	backend := &recordingBackend{}
	mux := BuildMux(fga, backend.Handler())

	sub := authz.Subject{UID: 1000}
	req := newRequest(t, http.MethodGet, "/some/unmapped/path", "", &sub)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if backend.called {
		t.Error("backend was reached for an unmapped route")
	}
}

func TestBuildMux_HostLevelRoute(t *testing.T) {
	fga := newTestFGA(t)

	tests := []struct {
		name string
		uid  uint32
		want int
	}{
		{"granted host_view_info", 1000, http.StatusOK},
		{"no grant for this user", 2000, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &recordingBackend{}
			mux := BuildMux(fga, backend.Handler())

			sub := authz.Subject{UID: tt.uid}
			req := newRequest(t, http.MethodGet, "/v5/libpod/info", "", &sub)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.want, rec.Body.String())
			}
			if backend.called != (tt.want == http.StatusOK) {
				t.Errorf("backend called = %v, want %v", backend.called, tt.want == http.StatusOK)
			}
		})
	}
}

func TestBuildMux_ContainerCreate(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{
			name: "mount within allowed pattern is forwarded",
			body: `{"image":"alpine","mounts":[{"source":"/data/app"}]}`,
			want: http.StatusOK,
		},
		{
			name: "mount outside allowed pattern is denied",
			body: `{"image":"alpine","mounts":[{"source":"/etc/passwd"}]}`,
			want: http.StatusForbidden,
		},
		{
			name: "no mounts, permitted image, is forwarded",
			body: `{"image":"alpine"}`,
			want: http.StatusOK,
		},
		{
			name: "permitted mount but unpermitted image is denied",
			body: `{"image":"not-granted","mounts":[{"source":"/data/app"}]}`,
			want: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fga := newTestFGA(t)
			backend := &recordingBackend{}
			mux := BuildMux(fga, backend.Handler())

			sub := authz.Subject{UID: 1000}
			req := newRequest(t, http.MethodPost, "/v5/libpod/containers/create", tt.body, &sub)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestBuildMux_ContainerCreate_SetsOwnershipContext(t *testing.T) {
	fga := newTestFGA(t)
	backend := &recordingBackend{}
	mux := BuildMux(fga, backend.Handler())

	sub := authz.Subject{UID: 1000}
	req := newRequest(t, http.MethodPost, "/v5/libpod/containers/create", `{"image":"alpine"}`, &sub)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if backend.owned == nil {
		t.Fatal("backend did not observe an ownedKey value in context")
	}
	if backend.owned.objType != "container" || backend.owned.sub != sub {
		t.Errorf("owned = %+v, want {objType: container, sub: %+v}", backend.owned, sub)
	}
}

func TestBuildMux_ListRoute_PopulatesAllowedIDs(t *testing.T) {
	fga := newTestFGA(t)
	backend := &recordingBackend{}
	mux := BuildMux(fga, backend.Handler())

	sub := authz.Subject{UID: 1000}
	req := newRequest(t, http.MethodGet, "/v5/libpod/containers/json", "", &sub)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !backend.allowed["a"] {
		t.Errorf("allowed IDs = %v, want to include owned container %q", backend.allowed, "a")
	}
}

func TestBuildMux_SingleResourceRoute(t *testing.T) {
	fga := newTestFGA(t)

	tests := []struct {
		name string
		uid  uint32
		want int
	}{
		{"owner can view", 1000, http.StatusOK},
		{"non-owner denied", 2000, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &recordingBackend{}
			mux := BuildMux(fga, backend.Handler())

			sub := authz.Subject{UID: tt.uid}
			req := newRequest(t, http.MethodGet, "/v5/libpod/containers/a/json", "", &sub)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}
