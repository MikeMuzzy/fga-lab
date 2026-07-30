package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"podmanproxy/internal/authz"
	"podmanproxy/internal/podman"
)

// requirementBuilder turns a matched request into the requirements it must
// satisfy: every requirement must hold, and a requirement holds if any of
// its alternatives allows.
type requirementBuilder func(r *http.Request) ([]authz.Requirement, error)

// route binds a URL pattern to its authorization requirements plus optional
// response-hook markers.
type route struct {
	pattern     string             // Go 1.22+ pattern: "METHOD /path/{id}"
	require     requirementBuilder // AND of ORs
	list        *authz.Permission  // non-nil: filter the JSON array response
	owned       string             // non-empty: write ownership tuples on 201
	execSession bool               // response creates an exec session for {id}
}

// routes is the complete authorized surface. Anything absent is denied by
// the mux catch-all, so coverage is structural rather than a matter of
// per-handler discipline.
var routes = []route{
	// containers
	{pattern: "POST /v5/libpod/containers/create", require: containerCreate, owned: "container"},
	{pattern: "GET /v5/libpod/containers/json", require: hostLevel(authz.HostViewInfo), list: &authz.ContainerView},
	{pattern: "GET /v5/libpod/containers/{id}/json", require: one(authz.ContainerView, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/start", require: one(authz.ContainerOperate, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/stop", require: one(authz.ContainerOperate, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/restart", require: one(authz.ContainerOperate, "id")},
	{pattern: "GET /v5/libpod/containers/{id}/logs", require: one(authz.ContainerOperate, "id")},
	{pattern: "POST /v5/libpod/containers/{id}/rename", require: one(authz.ContainerUpdate, "id")},
	{pattern: "DELETE /v5/libpod/containers/{id}", require: one(authz.ContainerDelete, "id")},

	// exec: creating a session checks the container; starting it checks the
	// session, joined to its container by a contextual tuple.
	{pattern: "POST /v5/libpod/containers/{id}/exec", require: one(authz.ContainerExec, "id"), execSession: true},
	{pattern: "POST /v5/libpod/exec/{sid}/start", require: one(authz.ExecSessionStart, "sid")},

	// pods
	{pattern: "GET /v5/libpod/pods/json", require: hostLevel(authz.HostViewInfo), list: &authz.PodView},
	{pattern: "POST /v5/libpod/pods/{id}/start", require: one(authz.PodOperate, "id")},
	{pattern: "DELETE /v5/libpod/pods/{id}", require: one(authz.PodDelete, "id")},

	// images
	{pattern: "GET /v5/libpod/images/{name}/json", require: imageUse("name")},
	{pattern: "DELETE /v5/libpod/images/{name}", require: one(authz.ImageDelete, "name")},

	// volumes and networks
	{pattern: "GET /v5/libpod/volumes/json", require: hostLevel(authz.HostViewInfo), list: &authz.VolumeView},
	{pattern: "DELETE /v5/libpod/volumes/{name}", require: one(authz.VolumeDelete, "name")},
	{pattern: "GET /v5/libpod/networks/json", require: hostLevel(authz.HostViewInfo), list: &authz.NetworkView},

	// host-scoped
	{pattern: "GET /v5/libpod/info", require: hostLevel(authz.HostViewInfo)},
	{pattern: "GET /v5/libpod/_ping", require: hostLevel(authz.HostViewInfo)},
	{pattern: "GET /v5/libpod/events", require: hostLevel(authz.HostViewEvents)},
	{pattern: "POST /v5/libpod/containers/prune", require: hostLevel(authz.HostPrune)},
}

// one covers the common case: a single permission on a path segment.
func one(p authz.Permission, pathParam string) requirementBuilder {
	return func(r *http.Request) ([]authz.Requirement, error) {
		id := r.PathValue(pathParam)
		if id == "" {
			return nil, fmt.Errorf("missing path parameter %q", pathParam)
		}
		return []authz.Requirement{authz.One(p.On(id))}, nil
	}
}

// hostLevel covers endpoints with no resource object.
func hostLevel(p authz.Permission) requirementBuilder {
	return func(*http.Request) ([]authz.Requirement, error) {
		return []authz.Requirement{authz.One(p.On(hostID))}, nil
	}
}

const hostID = "local" // single-host deployment

// imageUse supplies the image reference as condition context so pattern
// grants (image_ref_matches) can evaluate.
//
// Production note: resolve the reference to a digest before checking, so the
// check and the tuple key are canonical rather than tag-dependent.
func imageUse(pathParam string) requirementBuilder {
	return func(r *http.Request) ([]authz.Requirement, error) {
		ref := r.PathValue(pathParam)
		if ref == "" {
			return nil, fmt.Errorf("missing path parameter %q", pathParam)
		}
		return []authz.Requirement{imageRequirement(ref)}, nil
	}
}

func imageRequirement(ref string) authz.Requirement {
	return authz.Require("image:"+ref,
		authz.ImageUse.On(ref).WithContext(map[string]any{"image_ref": ref}))
}

// containerCreate is the composite: host create right, image use, a grant
// per named volume and network, and a host path grant per bind mount.
//
// The blanket-vs-pattern OR for bind sources lives in the model as
// can_mount_src, so each source remains a single check here — model-level
// unions stay visible to ListObjects and `fga model test`.
func containerCreate(r *http.Request) ([]authz.Requirement, error) {
	var spec podman.CreateSpec
	if err := decodeAndRestore(r, &spec); err != nil {
		return nil, err
	}
	if spec.Image == "" {
		return nil, fmt.Errorf("container spec has no image")
	}

	reqs := []authz.Requirement{
		authz.One(authz.HostCreate.On(hostID)),
		imageRequirement(spec.Image),
	}
	for _, v := range spec.Volumes {
		reqs = append(reqs, authz.One(authz.VolumeMount.On(v.Name)))
	}
	for name := range spec.Networks {
		reqs = append(reqs, authz.One(authz.NetworkConnect.On(name)))
	}
	for _, m := range spec.BindMounts() {
		src, err := normalizeSource(m.Source)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, authz.Require("bind:"+src,
			authz.HostMountSrc.On(hostID).WithContext(map[string]any{"src_path": src})))
	}
	return reqs, nil
}

// normalizeSource canonicalizes a bind-mount source before it becomes
// condition context. Without this, "/srv/team-a/../../etc" satisfies a
// "^/srv/team-a/" pattern grant while resolving elsewhere on disk: the
// pattern is matched against the string, not the path.
//
// Relative paths are rejected outright rather than resolved, since their
// meaning depends on podman's working directory rather than the request.
func normalizeSource(src string) (string, error) {
	if src == "" {
		return "", fmt.Errorf("bind mount has empty source")
	}
	if !filepath.IsAbs(src) {
		return "", fmt.Errorf("bind mount source %q is not absolute", src)
	}
	// Clean resolves . and .. lexically. Symlinks are not resolved here:
	// EvalSymlinks races with the mount (TOCTOU) and requires the path to
	// exist. Grant patterns must therefore cover symlink-free paths, and
	// the proxy should refuse sources under user-writable directories.
	return filepath.Clean(src), nil
}

// decodeAndRestore reads the body for inspection and restores it so the
// reverse proxy forwards the bytes unchanged.
func decodeAndRestore(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSpecBytes))
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

const maxSpecBytes = 1 << 20
