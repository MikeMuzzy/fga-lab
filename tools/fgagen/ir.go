package authzgen

// The intermediate representation is deliberately inert: plain structs, sorted
// slices, no maps and no funcs. Rendering must not be able to observe map
// iteration order, so regenerating an unchanged model produces a byte-identical
// file and `authzgen -verify` is meaningful in CI.

// File is everything the template needs.
type File struct {
	Package string
	Source  string
	Imports []string

	Permissions []Relation
	Roles       []Relation
	Conditions  []Condition
	Grants      []Grant

	// Helper functions are emitted only when a parameter needs them, since an
	// unused import would not compile and an unused helper is just noise.
	NeedsSliceHelper bool
	NeedsMapHelper   bool
}

// Relation is one (object type, relation) pair from the model.
type Relation struct {
	GoName   string
	Type     string
	Relation string
}

// Condition is one CEL condition, with its parameters partitioned by phase.
type Condition struct {
	Name       string
	GoName     string
	Expression string
	Write      []Param
	Check      []Param
}

// Param is a single condition parameter bound to one phase.
type Param struct {
	// Name is the wire name, which is also the key in the condition context and
	// the identifier the CEL expression sees.
	Name string
	// GoName is the exported struct field name.
	GoName string
	// GoType is the Go type expression for the field.
	GoType string
	// Encode is a complete Go expression, with the receiver already
	// substituted, producing a value that survives the round trip through
	// structpb. Integers become decimal strings rather than float64.
	Encode string
}

// Grant is a constructor for one directly-related user type of one relation.
// Each entry corresponds to a single RelationReference in the model's type
// restrictions, so the condition attached to a tuple cannot disagree with the
// condition the model requires for that edge.
type Grant struct {
	GoName   string
	Type     string
	Relation string

	// UserExpr is a Go expression producing the tuple's user field. It
	// references subjectID when NeedsSubject is set.
	UserExpr    string
	NeedsSubject bool

	// Condition is empty for unconditioned restrictions.
	Condition       string
	ConditionGoName string
}
