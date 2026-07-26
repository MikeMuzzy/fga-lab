// Package authz is the single source of authorization policy for the proxy.
// Handlers and the podman transport contain no policy: they consume Checks
// and Decisions minted here.
package authz

import (
	"context"
	"errors"
	"fmt"
)

// Subject is the authenticated caller, derived from SO_PEERCRED.
type Subject struct {
	UID uint32
	GID uint32
}

// String renders the OpenFGA user identifier, e.g. "user:uid-1000".
func (s Subject) String() string { return fmt.Sprintf("user:uid-%d", s.UID) }

// Permission pairs an object type with a relation. Unexported fields mean
// only this package can mint them, so an invalid (type, relation) pair is
// unrepresentable outside the catalog in permissions.go.
type Permission struct {
	objType  string
	relation string
}

// On binds the permission to a concrete object id, producing a Check.
func (p Permission) On(id string) Check { return Check{perm: p, id: id} }

// Context carries check-time parameters for the FGA model's ABAC conditions,
// e.g. the concrete path a path_matches condition should test.
type Context map[string]any

// Check is a fully bound authorization question: (permission, object id),
// optionally parameterized with condition context.
type Check struct {
	perm Permission
	id   string
	ctx  Context
}

// WithContext attaches condition context to the check and returns it. It
// does not mutate the receiver.
func (c Check) WithContext(ctx Context) Check {
	c.ctx = ctx
	return c
}

func (c Check) Object() string   { return c.perm.objType + ":" + c.id }
func (c Check) Relation() string { return c.perm.relation }
func (c Check) Context() Context { return c.ctx }

// Decision is an answer, not an error. Deny is a normal value; error is
// reserved for infrastructure failure, which callers must treat as deny.
type Decision struct {
	Allowed bool
	Subject string
	Checks  []Check
	ModelID string // deployed FGA model version, for the audit trail
}

// ErrNoDecision is returned by the podman transport when a request reaches
// it without an authorization decision in context (fail-closed invariant).
var ErrNoDecision = errors.New("authz: request reached podman transport without an authorization decision")

// Authorizer is the one interface the rest of the binary depends on.
type Authorizer interface {
	Check(ctx context.Context, sub Subject, c Check) (Decision, error)
	// BatchCheck allows only if every check allows (AND semantics).
	BatchCheck(ctx context.Context, sub Subject, cs []Check) (Decision, error)
	// ListIDs returns the set of object ids of p's type the subject holds
	// p's relation on. Used to filter list-endpoint responses.
	ListIDs(ctx context.Context, sub Subject, p Permission) (map[string]bool, error)
}

// Context plumbing. The key type is unexported: only this package can set a
// Decision, so a handler cannot forge one.
type ctxKey struct{}

func WithDecision(ctx context.Context, d Decision) context.Context {
	return context.WithValue(ctx, ctxKey{}, d)
}

func DecisionFrom(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(ctxKey{}).(Decision)
	return d, ok
}
