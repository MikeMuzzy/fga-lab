// Package authz is the domain vocabulary and the single source of
// authorization policy. It deliberately imports no HTTP and no OpenFGA SDK:
// adapters depend on this package, never the reverse.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// Subject is the authenticated caller, derived from SO_PEERCRED.
type Subject struct {
	UID uint32
	GID uint32
}

// String renders the OpenFGA user identifier, e.g. "user:uid-1000".
func (s Subject) String() string { return fmt.Sprintf("user:uid-%d", s.UID) }

// Permission pairs an object type with a relation. Sealed: unexported fields
// mean only the generated catalog in this package can mint one, so an
// invalid (type, relation) pair is unrepresentable elsewhere.
type Permission struct {
	objType  string
	relation string
}

// On binds the permission to a concrete object id, producing a Check.
func (p Permission) On(id string) Check { return Check{perm: p, id: id} }

// Type reports the object type; adapters need it for ListObjects.
func (p Permission) Type() string { return p.objType }

// Relation reports the relation name.
func (p Permission) Relation() string { return p.relation }

// Check is a fully bound authorization question: (permission, object id),
// optionally carrying condition context for CEL-conditioned grants.
// Sealed like Permission; adapters read it through the accessors below.
type Check struct {
	perm    Permission
	id      string
	context map[string]any
}

// WithContext returns a copy carrying condition context (e.g. src_path for
// path_matches). The server merges this with the tuple's persisted context,
// tuple taking precedence, so a caller cannot loosen a stored grant.
func (c Check) WithContext(kv map[string]any) Check {
	c.context = kv
	return c
}

func (c Check) Object() string          { return c.perm.objType + ":" + c.id }
func (c Check) Relation() string        { return c.perm.relation }
func (c Check) Context() map[string]any { return c.context }
func (c Check) String() string          { return c.Object() + "#" + c.Relation() }

// Key identifies a check for deduplication within a batch. fmt prints maps
// in sorted key order, so identical contexts produce identical keys.
func (c Check) Key() string { return fmt.Sprintf("%s|%v", c.String(), c.context) }

func (c Check) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("object", c.Object()),
		slog.String("relation", c.Relation()),
	}
	if len(c.context) > 0 {
		attrs = append(attrs, slog.Any("context", c.context))
	}
	return slog.GroupValue(attrs...)
}

// Requirement is satisfied if at least one alternative allows (OR); a
// request is authorized if every Requirement is satisfied (AND).
//
// This OR is only for alternatives spanning *different objects*. An OR over
// relations on the same object belongs in the model as `or` in the relation
// definition, where ListObjects and `fga model test` can see it.
type Requirement struct {
	Name string // audit label, e.g. "image:alpine", "bind:/data/exports"
	Any  []Check
}

// Require builds a named requirement from alternatives.
func Require(name string, anyOf ...Check) Requirement {
	return Requirement{Name: name, Any: anyOf}
}

// One wraps the common single-alternative case with a derived name.
func One(c Check) Requirement { return Requirement{Name: c.String(), Any: []Check{c}} }

// CheckResult is the outcome of one alternative.
type CheckResult struct {
	Check   Check
	Allowed bool
}

// RequirementResult records how a requirement resolved, alternative by
// alternative — distinguishing "this alternative failed but didn't matter"
// from "this requirement sank the request".
type RequirementResult struct {
	Name    string
	Allowed bool
	Checks  []CheckResult
}

// Decision is an answer, not an error: deny is a normal value, and error is
// reserved for infrastructure failure that callers must treat as deny.
//
// Fields are exported because adapters outside this package must construct
// decisions; Check and Permission stay sealed because only the domain may
// mint those. Decision carries the complete evaluation input set so one
// audit line reproduces the outcome.
type Decision struct {
	Allowed      bool
	Subject      string
	ModelID      string
	Requirements []RequirementResult
	Facts        []Tuple
}

func (d Decision) LogValue() slog.Value {
	var denied []string
	for _, rr := range d.Requirements {
		if rr.Allowed {
			continue
		}
		alts := make([]string, len(rr.Checks))
		for i, cr := range rr.Checks {
			alts[i] = cr.Check.String()
		}
		denied = append(denied, rr.Name+": none of ["+strings.Join(alts, ", ")+"]")
	}
	facts := make([]string, len(d.Facts))
	for i, t := range d.Facts {
		facts[i] = t.String()
	}
	return slog.GroupValue(
		slog.Bool("allowed", d.Allowed),
		slog.String("subject", d.Subject),
		slog.String("model_id", d.ModelID),
		slog.Int("requirements", len(d.Requirements)),
		slog.Any("denied", denied),
		slog.Any("facts", facts),
	)
}

// Fold evaluates CNF semantics over per-check outcomes: a requirement is
// allowed if any alternative is, the decision if every requirement is.
//
// Living in the domain rather than in an adapter means the semantics are
// tested once, without a server, and every implementation shares them.
// Fail-closed by construction: a missing key in allowed counts as denied, a
// requirement with no alternatives is denied, and zero requirements deny.
func Fold(sub Subject, modelID string, reqs []Requirement, facts []Tuple, allowed map[string]bool) Decision {
	d := Decision{
		Subject: sub.String(),
		ModelID: modelID,
		Facts:   facts,
		Allowed: len(reqs) > 0,
	}
	for _, rq := range reqs {
		rr := RequirementResult{Name: rq.Name} // zero alternatives => denied
		for _, c := range rq.Any {
			ok := allowed[c.Key()]
			rr.Checks = append(rr.Checks, CheckResult{Check: c, Allowed: ok})
			rr.Allowed = rr.Allowed || ok
		}
		d.Requirements = append(d.Requirements, rr)
		d.Allowed = d.Allowed && rr.Allowed
	}
	return d
}

// Flatten returns the deduplicated set of checks across all requirements,
// so an adapter issues one batch per request.
func Flatten(reqs []Requirement) []Check {
	seen := make(map[string]bool)
	var out []Check
	for _, rq := range reqs {
		for _, c := range rq.Any {
			if !seen[c.Key()] {
				seen[c.Key()] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// ErrNoDecision is returned by the podman transport when a request reaches
// it without an authorization decision in context (fail-closed invariant).
var ErrNoDecision = errors.New("authz: request reached podman transport without an authorization decision")

// ErrUnavailable wraps infrastructure failures from an Authorizer. Callers
// distinguish it from policy denial with errors.Is and fail closed.
var ErrUnavailable = errors.New("authz: authorization service unavailable")

// Authorizer answers policy questions. Kept narrow on purpose: consumers
// depend only on what they call, so fakes stay small.
type Authorizer interface {
	// Authorize evaluates all requirements in one round trip. facts are
	// request-scoped contextual tuples.
	Authorize(ctx context.Context, sub Subject, reqs []Requirement, facts []Tuple) (Decision, error)
	// ListIDs returns the ids of p's object type the subject holds p's
	// relation on, evaluated with the same facts so lists and checks agree.
	ListIDs(ctx context.Context, sub Subject, p Permission, facts []Tuple) (map[string]bool, error)
}

// TupleWriter owns relationship lifecycle. Split from Authorizer so the
// read path's fakes need not stub write methods they never call.
type TupleWriter interface {
	WriteOwnership(ctx context.Context, sub Subject, objType, id string) error
	DeleteObjectTuples(ctx context.Context, objType, id string) error
}

// Context plumbing. The key type is unexported: only this package can place
// a Decision in a context, so no handler can forge one.
type ctxKey struct{}

func WithDecision(ctx context.Context, d Decision) context.Context {
	return context.WithValue(ctx, ctxKey{}, d)
}

func DecisionFrom(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(ctxKey{}).(Decision)
	return d, ok
}
