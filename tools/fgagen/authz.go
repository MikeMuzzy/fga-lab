// Package authz holds the generated authorization catalog and the hand-written
// types it references. Nothing here imports the OpenFGA SDK: the adapter that
// does lives one layer out, so an SDK upgrade never forces a regeneration.
package authz

// Permission is a checkable (object type, relation) pair.
type Permission struct {
	Type     string
	Relation string
}

// Role is an assignable (object type, relation) pair.
type Role struct {
	Type     string
	Relation string
}

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
