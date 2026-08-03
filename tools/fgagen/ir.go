package authzgen

// The intermediate representation is deliberately inert: plain structs, sorted
// slices, no maps and no funcs. Rendering must not be able to observe map
// iteration order, so regenerating an unchanged model produces a byte-identical
// file and `authzgen -verify` is meaningful in CI.

// ContextArgLimit is the number of condition arguments past which a builder
// takes a named parameter struct instead of positional arguments. Beyond three,
// same-shaped positional arguments reintroduce the ordering mistake the typed
// identifiers exist to prevent.
const ContextArgLimit = 3

// File is everything the template needs.
type File struct {
	Package string
	Source  string
	Imports []string

	ObjectTypes []ObjectType
	Permissions []Permission
	Roles       []Relation
	Conditions  []Condition
	Grants      []Grant

	// Helpers and imports are emitted only when something needs them: an
	// unused import does not compile and an unused helper is noise.
	NeedsSliceHelper bool
	NeedsMapHelper   bool
}

// ObjectType is a type in the model, which gets a distinct Go identifier type
// so object ids of different types cannot be transposed at a call site.
type ObjectType struct {
	Name   string // "folder"
	GoName string // "Folder"
	IDType string // "FolderID"
}

// Relation is one (object type, relation) pair.
type Relation struct {
	GoName   string
	Type     string
	Relation string
}

// Permission is a checkable relation plus the check-time context its evaluation
// can require.
type Permission struct {
	GoName   string // catalog variable, e.g. FolderCanRead
	Builder  string // constructor, e.g. CheckFolderCanRead
	Type     string
	Relation string
	IDType   string

	// Args are the condition requests the builder takes, sorted by condition
	// name. Conditions in the closure with no check-time parameters are
	// omitted: their Request type has no fields, so asking for one is noise.
	Args []ContextArg

	// ArgStruct is non-empty when len(Args) > ContextArgLimit, naming the
	// generated parameter struct the builder takes instead.
	ArgStruct string
}

// ContextArg is one condition's check-time input in a builder signature.
type ContextArg struct {
	Condition string // "path_match"
	ParamName string // "pathMatch"
	FieldName string // "PathMatch"
	TypeName  string // "PathMatchRequest"
}

// Condition is one CEL condition with its parameters partitioned by phase.
type Condition struct {
	Name       string
	GoName     string
	Expression string
	Write      []Param
	Check      []Param
}

// Param is a single condition parameter bound to one phase.
type Param struct {
	// Name is the wire name: the key in the condition context and the
	// identifier the CEL expression sees.
	Name string
	// GoName is the exported struct field name.
	GoName string
	// GoType is the Go type expression for the field.
	GoType string
	// Encode is a complete Go expression, receiver already substituted,
	// producing a value that survives the round trip through structpb.
	Encode string
}

// Grant is a constructor for one directly-related user type of one relation,
// so a tuple cannot carry a condition the model does not require on that edge.
type Grant struct {
	GoName   string
	Type     string
	Relation string

	// SubjectIDType is empty for wildcard restrictions, which take no subject.
	SubjectIDType string
	ObjectIDType  string
	UserExpr      string

	// Condition is empty for unconditioned restrictions.
	Condition       string
	ConditionGoName string
}
