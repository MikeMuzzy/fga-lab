package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	fga "github.com/openfga/go-sdk/client"
)

// Request is the resolved OCI spec, not the CLI string. Compose files,
// Kube YAML and containers.conf defaults all inject these fields.
type Request struct {
	User   string // "user:alice.chen"
	Host   string // "host:hv-lon-01"
	Env    string // "prod" — capability object namespace

	ImageRepo   string // canonical registry/namespace/name, lowercased
	ImageTag    string
	ImageDigest string // resolved by the broker against the registry

	Mounts  []Mount
	Caps    []string // bare names, validated against the kernel set
	Sysctls []Sysctl
	Devices []Device

	Privileged, HostPID, HostIPC, HostUser, HostNet bool
	SeccompUnconfined, AppArmorUnconfined, SELinuxDisabled bool
}

type Mount struct{ Source string; RW bool } // Source is realpath-resolved
type Sysctl struct{ Key, Value string }
type Device struct{ Name string; Write bool }

type Decision struct {
	Allowed bool
	Denials []string // correlation IDs that returned false
	Errors  []string // correlation IDs that failed to evaluate
}

type PEP struct {
	fga     *fga.OpenFgaClient
	modelID string // pinned; a model write is otherwise a silent semantics change
	now     func() time.Time
}

// ── ambient context: built server-side, never from the caller ─────────────
func (p *PEP) ambient() map[string]any {
	return map[string]any{"request_time": p.now().UTC().Format(time.RFC3339)}
}

func (p *PEP) imageCtx() map[string]any {
	m := p.ambient()
	return m
}

// ── gate 1: coarse. Ambient only. Cacheable, session-scoped, tens of seconds.
// NEVER treat a pass here as authorisation — it is a fast reject only.
func (p *PEP) IsContainerEligible(ctx context.Context, user, host string) (bool, error) {
	c := p.ambient()
	r, err := p.fga.Check(ctx).Body(fga.ClientCheckRequest{
		User: user, Relation: "may_create_container", Object: host, Context: &c,
	}).Options(fga.ClientCheckOptions{AuthorizationModelId: &p.modelID}).Execute()
	if err != nil {
		return false, err
	}
	return r.GetAllowed(), nil
}

// ── gate 2: enforcing. Runs on every create, regardless of gate 1.
func (p *PEP) Authorize(ctx context.Context, req Request) (Decision, error) {
	if err := validateShape(req); err != nil { // before CEL ever sees it
		return Decision{}, err
	}

	items := []fga.ClientBatchCheckItem{{
		CorrelationId: "image",
		User: req.User, Relation: "can_create_container", Object: req.Host,
		Context: &map[string]any{
			"request_time": p.now().UTC().Format(time.RFC3339),
			"image_repo":   req.ImageRepo,
			"image_tag":    req.ImageTag,
			"image_digest": req.ImageDigest,
		},
	}}

	for i, m := range req.Mounts {
		rel := "can_mount_ro"
		if m.RW {
			rel = "can_mount_rw"
		}
		c := p.ambient()
		c["mount_source"] = m.Source
		items = append(items, fga.ClientBatchCheckItem{
			CorrelationId: fmt.Sprintf("mount.%d", i),
			User: req.User, Relation: rel, Object: req.Host, Context: &c,
		})
	}

	for _, s := range req.Sysctls {
		c := p.ambient()
		c["sysctl_key"], c["sysctl_value"] = s.Key, s.Value
		items = append(items, fga.ClientBatchCheckItem{
			CorrelationId: "sysctl." + s.Key,
			User: req.User, Relation: "can_set_sysctl", Object: req.Host, Context: &c,
		})
	}

	// --privileged is expanded, never checked as a single opaque flag.
	caps := req.Caps
	if req.Privileged {
		caps = union(caps, kernelBoundingSet())
	}
	for _, cp := range caps {
		c := p.ambient()
		items = append(items, fga.ClientBatchCheckItem{
			CorrelationId: "cap." + cp,
			User: req.User, Relation: "can_add",
			Object: "capability:" + req.Env + "/" + cp, Context: &c,
		})
	}

	for _, d := range req.Devices {
		rel := "can_use_ro"
		if d.Write {
			rel = "can_use_rw"
		}
		c := p.ambient()
		items = append(items, fga.ClientBatchCheckItem{
			CorrelationId: "device." + d.Name,
			User: req.User, Relation: rel,
			Object: strings.TrimPrefix(req.Host, "host:") + "/" + d.Name, Context: &c,
		})
	}

	for _, f := range []struct {
		on  bool
		id  string
		rel string
	}{
		{req.Privileged, "privileged", "can_use_privileged"},
		{req.HostPID, "host_pid", "can_use_host_pid_ns"},
		{req.HostIPC, "host_ipc", "can_use_host_ipc_ns"},
		{req.HostUser, "host_user", "can_use_host_user_ns"},
		{req.HostNet, "host_net", "can_use_host_network"},
		{req.SeccompUnconfined, "seccomp_off", "can_use_unconfined_seccomp"},
		{req.AppArmorUnconfined, "apparmor_off", "can_use_unconfined_apparmor"},
		{req.SELinuxDisabled, "selinux_off", "can_disable_selinux"},
	} {
		if !f.on {
			continue
		}
		c := p.ambient()
		items = append(items, fga.ClientBatchCheckItem{
			CorrelationId: "esc." + f.id,
			User: req.User, Relation: f.rel, Object: req.Host, Context: &c,
		})
	}

	res, err := p.fga.BatchCheck(ctx).
		Body(fga.ClientBatchCheckRequest{Checks: items}).
		Options(fga.ClientBatchCheckOptions{
			AuthorizationModelId: &p.modelID,
			Consistency:          &higherConsistency, // revocations must bite immediately
		}).Execute()
	if err != nil {
		return Decision{}, err
	}

	d := Decision{Allowed: true}
	seen := 0
	for id, r := range res.GetResult() {
		seen++
		switch {
		case r.Error != nil: // missing context param, CEL failure — fail closed
			d.Allowed, d.Errors = false, append(d.Errors, id)
		case !r.GetAllowed():
			d.Allowed, d.Denials = false, append(d.Denials, id)
		}
	}
	if seen != len(items) { // partial response — never infer allow
		return Decision{}, errors.New("authz: incomplete batch result")
	}
	if d.Allowed {
		if err := denyCombinations(req); err != nil { // not expressible in OpenFGA
			d.Allowed, d.Denials = false, append(d.Denials, "combo."+err.Error())
		}
	}
	return d, nil
}