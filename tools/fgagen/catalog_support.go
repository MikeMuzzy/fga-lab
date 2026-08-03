package authz

import "fmt"

// This file holds the hand-written declarations the generated catalog assumes.
// Merge it into the existing package; the only piece that needs adapting is
// newTuple, which must match the real Tuple definition.

// Role is an assignable (object type, relation) pair. Sealed like Permission:
// only the generated catalog can mint one, so a grant cannot name a relation
// the model does not define as assignable.
type Role struct {
	objType  string
	relation string
}

// Type reports the object type.
func (r Role) Type() string { return r.objType }

// Relation reports the relation name.
func (r Role) Relation() string { return r.relation }

// ConditionSpec describes a CEL condition and how its parameters are supplied.
//
// WriteParams are frozen into the tuple and take precedence over any value of
// the same name in a Check request. CheckParams are supplied per request. The
// two sets are disjoint and together cover every parameter of the condition;
// authzgen fails generation otherwise.
type ConditionSpec struct {
	Name        string
	WriteParams []string
	CheckParams []string
}

// newTuple adapts the generated grant constructors to the package's Tuple type.
//
// TODO: map these arguments onto the real field names of Tuple. condition is
// empty and ctx is nil for unconditioned grants.
func newTuple(user, relation, object, condition string, ctx map[string]any) Tuple {
	return Tuple{
		User:      user,
		Relation:  relation,
		Object:    object,
		Condition: condition,
		Context:   ctx,
	}
}

// ID renders the subject as a UserID, so the generated grant constructors can
// take it without a string detour.
func (s Subject) ID() UserID { return UserID(fmt.Sprintf("uid-%d", s.UID)) }

// CheckContexter is implemented by every generated condition Request type.
// Grant types deliberately do not implement it: they expose WriteContext, not
// CheckContext, so a value meant to be frozen into a tuple cannot be routed
// into a Check where the caller could influence it.
type CheckContexter interface {
	ConditionName() string
	CheckContext() map[string]any
}

// MergeCheckContexts combines request contexts for a hand-built Check, for the
// cases the generated builders do not cover -- notably a Check assembled
// dynamically rather than from a known permission.
//
// The generated builders do not call this: authzgen proves at generation time
// that no two conditions reachable from one permission share a check parameter
// name, so their merge cannot collide. This path has no such proof, hence the
// error return.
func MergeCheckContexts(ccs ...CheckContexter) (map[string]any, error) {
	out := make(map[string]any)
	owner := make(map[string]string)
	for _, cc := range ccs {
		name := cc.ConditionName()
		for k, v := range cc.CheckContext() {
			if prev, dup := owner[k]; dup {
				return nil, fmt.Errorf(
					"authz: check parameter %q supplied by both %s and %s", k, prev, name)
			}
			owner[k] = name
			out[k] = v
		}
	}
	return out, nil
}
