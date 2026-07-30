package authz

import "context"

// Fake is an in-memory Authorizer and TupleWriter for tests. Its existence
// is the payoff of keeping Authorizer narrow and the FGA client behind an
// interface: the entire deny path of the proxy is testable with no server.
//
// It lives in the domain package (not a _test.go file) so every consumer
// can use it.
type Fake struct {
	// Allow returns whether a check passes. nil denies everything, which
	// keeps the zero value fail-closed.
	Allow func(sub Subject, c Check, facts []Tuple) bool
	// Visible is the ListIDs result, keyed by "type#relation".
	Visible map[string]map[string]bool
	// Written records ownership writes for assertions.
	Written []string
	// Err, if set, is returned by every method to exercise failure paths.
	Err error
}

var (
	_ Authorizer  = (*Fake)(nil)
	_ TupleWriter = (*Fake)(nil)
)

func (f *Fake) Authorize(_ context.Context, sub Subject, reqs []Requirement, facts []Tuple) (Decision, error) {
	if f.Err != nil {
		return Decision{}, f.Err
	}
	allowed := make(map[string]bool)
	if f.Allow != nil {
		for _, c := range Flatten(reqs) {
			allowed[c.Key()] = f.Allow(sub, c, facts)
		}
	}
	// Reuses the real fold, so tests exercise production CNF semantics.
	return Fold(sub, "fake", reqs, facts, allowed), nil
}

func (f *Fake) ListIDs(_ context.Context, _ Subject, p Permission, _ []Tuple) (map[string]bool, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Visible[p.Type()+"#"+p.Relation()], nil
}

func (f *Fake) WriteOwnership(_ context.Context, sub Subject, objType, id string) error {
	if f.Err != nil {
		return f.Err
	}
	f.Written = append(f.Written, sub.String()+" owner "+objType+":"+id)
	return nil
}

func (f *Fake) DeleteObjectTuples(_ context.Context, objType, id string) error {
	if f.Err != nil {
		return f.Err
	}
	f.Written = append(f.Written, "delete "+objType+":"+id)
	return nil
}

// AllowAll is a convenience predicate for tests focused on non-authz paths.
func AllowAll(Subject, Check, []Tuple) bool { return true }
