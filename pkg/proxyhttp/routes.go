package proxyhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"fga-lib/pkg/authz"
)

// checkBuilder turns a matched request into the set of FGA checks it
// requires. All checks must allow (BatchCheck) for the request to proceed.
type checkBuilder func(r *http.Request) ([]authz.Check, error)

// one covers the common case: a single permission on the {id} path segment.
func one(p authz.Permission, pathParam string) checkBuilder {
	return func(r *http.Request) ([]authz.Check, error) {
		id := r.PathValue(pathParam)
		if id == "" {
			return nil, fmt.Errorf("missing path parameter %q", pathParam)
		}
		return []authz.Check{p.On(id)}, nil
	}
}

// hostLevel covers endpoints with no resource object.
func hostLevel(p authz.Permission) checkBuilder {
	return func(*http.Request) ([]authz.Check, error) {
		return []authz.Check{p.On("local")}, nil
	}
}

type route struct {
	pattern string            // Go 1.22+ net/http pattern: "METHOD /path/{id}"
	checks  checkBuilder      // required checks (AND)
	list    *authz.Permission // non-nil: filter podman's JSON array response
	owned   string            // non-empty: write ownership tuples on 2xx create
}

// The route table IS the authz coverage: reviewing it next to the .fga file
// is the security review. Anything not listed 403s via the mux catch-all.
var routes = []route{
	// containers
	{pattern: "POST /v5/libpod/containers/create", checks: containerCreateChecks, owned: "container"},
	{pattern: "GET /v5/libpod/containers/json", checks: hostLevel(authz.HostViewInfo), list: &authz.ContainerView},
	{pattern: "GET /v5/libpod/containers/{id}/json", checks: one(authz.ContainerView, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/start", checks: one(authz.ContainerOperate, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/stop", checks: one(authz.ContainerOperate, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/restart", checks: one(authz.ContainerOperate, "id")},
	{pattern: "GET /v5/libpod/containers/{id}/logs", checks: one(authz.ContainerOperate, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/exec", checks: one(authz.ContainerExec, "id")},
	{pattern: "DELETE /v5/libpod/containers/{id}", checks: one(authz.ContainerDelete, "id")},

	// images
	{pattern: "GET /v5/libpod/images/{name}/json", checks: one(authz.ImageUse, "name")},
	{pattern: "DELETE /v5/libpod/images/{name}", checks: one(authz.ImageDelete, "name")},

	// host-scoped
	{pattern: "GET /v5/libpod/info", checks: hostLevel(authz.HostViewInfo)},
	{pattern: "GET /v5/libpod/events", checks: hostLevel(authz.HostViewEvents)},
	{pattern: "POST /v5/libpod/containers/prune", checks: hostLevel(authz.HostPrune)},

	// ... remaining endpoints follow the same pattern. NOTE: /exec/{sid}/start
	// needs the sid->container map discussed earlier, authorized as
	// authz.ContainerExec.On(containerID).
}

// containerCreateChecks is the composite check: host create right, can_use on
// the image, and a grant on every named volume and network in the spec.
func containerCreateChecks(r *http.Request) ([]authz.Check, error) {
	var spec struct {
		Image   string `json:"image"`
		Volumes []struct {
			Name string `json:"Name"`
		} `json:"volumes"`
		Networks map[string]json.RawMessage `json:"Networks"`
		Mounts   []json.RawMessage          `json:"mounts"`
	}
	if err := decodeAndRestore(r, &spec); err != nil {
		return nil, err
	}

	// Bind mounts are proxy-side policy, not tuples: this is what closes the
	// "mount / and exec in" escalation path.
	if len(spec.Mounts) > 0 {
		return nil, fmt.Errorf("bind mounts are not permitted")
	}

	// Production note: resolve the image reference to its digest/id first so
	// the check and the tuple key are canonical, not tag-dependent.
	checks := []authz.Check{
		authz.HostCreate.On("local"),
		authz.ImageUse.On(spec.Image),
	}
	for _, v := range spec.Volumes {
		checks = append(checks, authz.VolumeMount.On(v.Name))
	}
	for name := range spec.Networks {
		checks = append(checks, authz.NetworkConnect.On(name))
	}
	return checks, nil
}

// decodeAndRestore reads the body for inspection and puts it back so the
// reverse proxy can forward it unchanged.
func decodeAndRestore(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("decode container spec: %w", err)
	}
	return nil
}
