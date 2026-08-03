package authzgen

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
)

// DefaultPermissionPrefix marks relations that are checked rather than granted.
const DefaultPermissionPrefix = "can_"

// Options configure a single generation run.
type Options struct {
	// Package is the package clause of the generated file.
	Package string
	// PermissionPrefix separates checkable relations from assignable ones.
	// Defaults to DefaultPermissionPrefix.
	PermissionPrefix string
}

// Load parses the model DSL and its annotations and returns the IR.
//
// Both halves must agree exactly: every condition parameter is classified
// exactly once, and every directive names a parameter that exists. Drift is a
// hard failure rather than a warning, because a silently unclassified parameter
// would produce a Go type missing a field, and the resulting Check would be
// evaluated against a missing CEL binding at runtime.
func Load(filename string, src []byte, opts Options) (*File, error) {
	if opts.PermissionPrefix == "" {
		opts.PermissionPrefix = DefaultPermissionPrefix
	}

	model, err := transformer.TransformDSLToProto(string(src))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	// Annotation errors are lexical and reported independently, so collect them
	// alongside the join errors below rather than returning early.
	annotations, annErr := ParseAnnotations(filename, src)

	f := &File{Package: opts.Package, Source: filename}
	var errs []error
	if annErr != nil {
		errs = append(errs, annErr)
	}

	imports := map[string]bool{}

	// --- conditions -------------------------------------------------------

	protoConds := model.GetConditions()
	byName := make(map[string]Condition, len(protoConds))
	for _, name := range sortedKeys(protoConds) {
		cond, err := buildCondition(filename, name, protoConds[name], annotations, imports, f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		byName[name] = cond
		f.Conditions = append(f.Conditions, cond)
	}
	for _, name := range sortedKeys(annotations) {
		if _, ok := protoConds[name]; !ok {
			errs = append(errs, fmt.Errorf("%s:%d: directives attached to %q, which is not a condition in the model",
				filename, annotations[name].Line, name))
		}
	}

	// --- types, relations, grants ----------------------------------------

	idx := newTypeIndex(model)
	idTypes := make(map[string]string, len(idx))
	for _, td := range model.GetTypeDefinitions() {
		t := td.GetType()
		ot := ObjectType{Name: t, GoName: exportedName(t), IDType: exportedName(t) + "ID"}
		idTypes[t] = ot.IDType
		f.ObjectTypes = append(f.ObjectTypes, ot)
	}
	sort.Slice(f.ObjectTypes, func(i, j int) bool { return f.ObjectTypes[i].Name < f.ObjectTypes[j].Name })

	for _, td := range model.GetTypeDefinitions() {
		objectType := td.GetType()
		relations := td.GetRelations()
		for _, rel := range sortedKeys(relations) {
			if strings.HasPrefix(rel, opts.PermissionPrefix) {
				p, err := buildPermission(filename, idx, objectType, rel, idTypes[objectType],
					opts.PermissionPrefix, byName)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				f.Permissions = append(f.Permissions, p)
				if len(p.Args) > 1 {
					imports["maps"] = true
				}
				continue
			}
			f.Roles = append(f.Roles, Relation{
				GoName:   exportedName(objectType) + exportedName(rel),
				Type:     objectType,
				Relation: rel,
			})

			for _, rr := range idx.restrictions(objectType, rel) {
				grant, err := buildGrant(objectType, rel, rr, protoConds, idTypes)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %s#%s: %w", filename, objectType, rel, err))
					continue
				}
				f.Grants = append(f.Grants, grant)
			}
		}
	}

	sort.Slice(f.Permissions, func(i, j int) bool { return f.Permissions[i].GoName < f.Permissions[j].GoName })
	sort.Slice(f.Roles, func(i, j int) bool { return f.Roles[i].GoName < f.Roles[j].GoName })
	sort.Slice(f.Grants, func(i, j int) bool { return f.Grants[i].GoName < f.Grants[j].GoName })

	for imp := range imports {
		f.Imports = append(f.Imports, imp)
	}
	sort.Strings(f.Imports)

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return f, nil
}

// buildPermission derives the builder signature from the relation's condition
// closure.
//
// It rejects models in which two conditions reachable from one permission share
// a check-time parameter name. A Check carries a single flat context map, so
// those two parameters would collide on one key: the caller would set both
// fields and one would be discarded silently. Enforcing uniqueness here keeps
// the builder total -- it returns a Check, never an error -- at the cost of
// requiring a rename in the model.
func buildPermission(
	filename string,
	idx typeIndex,
	objectType, relation, idType, prefix string,
	conditions map[string]Condition,
) (Permission, error) {
	base := exportedName(objectType) + exportedName(strings.TrimPrefix(relation, prefix))
	p := Permission{
		GoName:   base,
		Builder:  "Check" + base,
		Type:     objectType,
		Relation: relation,
		IDType:   idType,
	}

	owner := map[string]string{} // check param name -> condition that claims it
	var errs []error

	for _, name := range idx.conditionClosure(node{objType: objectType, relation: relation}) {
		cond, ok := conditions[name]
		if !ok {
			// Already reported while building conditions.
			continue
		}
		if len(cond.Check) == 0 {
			continue
		}
		for _, param := range cond.Check {
			if prev, dup := owner[param.Name]; dup {
				errs = append(errs, fmt.Errorf(
					"%s: %s#%s reaches conditions %q and %q, which both take a check parameter %q; "+
						"rename one so the Check context has a single meaning for that key",
					filename, objectType, relation, prev, name, param.Name))
				continue
			}
			owner[param.Name] = name
		}
		p.Args = append(p.Args, ContextArg{
			Condition: name,
			ParamName: unexportedName(name),
			FieldName: cond.GoName,
			TypeName:  cond.GoName + "Request",
		})
	}

	if len(p.Args) > ContextArgLimit {
		p.ArgStruct = base + "Context"
	}
	return p, errors.Join(errs...)
}

func buildCondition(
	filename, name string,
	cond *openfgav1.Condition,
	annotations Annotations,
	imports map[string]bool,
	f *File,
) (Condition, error) {
	out := Condition{
		Name:       name,
		GoName:     exportedName(name),
		Expression: strings.TrimSpace(cond.GetExpression()),
	}

	params := cond.GetParameters()
	ann, ok := annotations[name]
	if !ok {
		return out, fmt.Errorf("%s: condition %q has no fga:write/fga:check directives; "+
			"every parameter must be classified", filename, name)
	}

	var errs []error
	for _, p := range sortedKeys(ann.Params) {
		if _, ok := params[p]; !ok {
			errs = append(errs, fmt.Errorf("%s:%d: condition %q has no parameter %q",
				filename, ann.Line, name, p))
		}
	}

	for _, pname := range sortedKeys(params) {
		phase, ok := ann.Params[pname]
		if !ok {
			errs = append(errs, fmt.Errorf("%s:%d: parameter %q of condition %q is not classified "+
				"as fga:write or fga:check", filename, ann.Line, pname, name))
			continue
		}

		receiver := "g"
		if phase == PhaseCheck {
			receiver = "r"
		}
		goName := exportedName(pname)
		gt, encode, err := mapParamType(params[pname], receiver+"."+goName, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s:%d: condition %q parameter %q: %w",
				filename, ann.Line, name, pname, err))
			continue
		}
		for _, imp := range gt.Imports {
			imports[imp] = true
		}
		f.NeedsSliceHelper = f.NeedsSliceHelper || gt.Slice
		f.NeedsMapHelper = f.NeedsMapHelper || gt.Map

		param := Param{Name: pname, GoName: goName, GoType: gt.Name, Encode: encode}
		if phase == PhaseCheck {
			out.Check = append(out.Check, param)
		} else {
			out.Write = append(out.Write, param)
		}
	}

	return out, errors.Join(errs...)
}

func buildGrant(
	objectType, relation string,
	rr *openfgav1.RelationReference,
	conditions map[string]*openfgav1.Condition,
	idTypes map[string]string,
) (Grant, error) {
	g := Grant{
		Type:         objectType,
		Relation:     relation,
		ObjectIDType: idTypes[objectType],
		Condition:    rr.GetCondition(),
	}

	subjectType := rr.GetType()
	if _, ok := idTypes[subjectType]; !ok {
		return Grant{}, fmt.Errorf("restriction references unknown type %q", subjectType)
	}

	var suffix string
	switch {
	case rr.GetWildcard() != nil:
		g.UserExpr = strconv.Quote(subjectType + ":*")
		suffix = exportedName(subjectType) + "Wildcard"
	case rr.GetRelation() != "":
		g.SubjectIDType = idTypes[subjectType]
		g.UserExpr = fmt.Sprintf("%s + string(subjectID) + %s",
			strconv.Quote(subjectType+":"), strconv.Quote("#"+rr.GetRelation()))
		suffix = exportedName(subjectType) + exportedName(rr.GetRelation())
	default:
		g.SubjectIDType = idTypes[subjectType]
		g.UserExpr = fmt.Sprintf("%s + string(subjectID)", strconv.Quote(subjectType+":"))
		suffix = exportedName(subjectType)
	}

	if g.Condition != "" {
		if cond, ok := conditions[g.Condition]; !ok || cond == nil {
			return Grant{}, fmt.Errorf("restriction references undefined condition %q", g.Condition)
		}
		g.ConditionGoName = exportedName(g.Condition)
		suffix += g.ConditionGoName
	}

	g.GoName = "Grant" + exportedName(objectType) + exportedName(relation) + suffix
	return g, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
