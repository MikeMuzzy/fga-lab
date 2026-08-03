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

	// Annotation errors are lexical and reported independently, so surface them
	// alongside the join errors below rather than returning early.
	annotations, annErr := ParseAnnotations(filename, src)

	f := &File{Package: opts.Package, Source: filename}
	var errs []error
	if annErr != nil {
		errs = append(errs, annErr)
	}

	imports := map[string]bool{}

	conditions := model.GetConditions()
	for _, name := range sortedKeys(conditions) {
		cond, err := buildCondition(filename, name, conditions[name], annotations, imports, f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f.Conditions = append(f.Conditions, cond)
	}
	for _, name := range sortedKeys(annotations) {
		if _, ok := conditions[name]; !ok {
			errs = append(errs, fmt.Errorf("%s:%d: directives attached to %q, which is not a condition in the model",
				filename, annotations[name].Line, name))
		}
	}

	for _, td := range model.GetTypeDefinitions() {
		objectType := td.GetType()
		relations := td.GetRelations()
		for _, rel := range sortedKeys(relations) {
			entry := Relation{Type: objectType, Relation: rel}
			switch {
			case strings.HasPrefix(rel, opts.PermissionPrefix):
				entry.GoName = exportedName(objectType) + exportedName(strings.TrimPrefix(rel, opts.PermissionPrefix))
				f.Permissions = append(f.Permissions, entry)
			default:
				entry.GoName = exportedName(objectType) + exportedName(rel)
				f.Roles = append(f.Roles, entry)
			}

			meta := td.GetMetadata().GetRelations()[rel]
			for _, rr := range meta.GetDirectlyRelatedUserTypes() {
				grant, err := buildGrant(objectType, rel, rr, conditions)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %s#%s: %w", filename, objectType, rel, err))
					continue
				}
				f.Grants = append(f.Grants, grant)
			}
		}
	}

	sortByGoName(f.Permissions)
	sortByGoName(f.Roles)
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
	for p := range ann.Params {
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
) (Grant, error) {
	g := Grant{
		Type:      objectType,
		Relation:  relation,
		Condition: rr.GetCondition(),
	}

	var suffix string
	switch {
	case rr.GetWildcard() != nil:
		g.UserExpr = strconv.Quote(rr.GetType() + ":*")
		suffix = exportedName(rr.GetType()) + "Wildcard"
	case rr.GetRelation() != "":
		g.UserExpr = fmt.Sprintf("%s + subjectID + %s",
			strconv.Quote(rr.GetType()+":"), strconv.Quote("#"+rr.GetRelation()))
		g.NeedsSubject = true
		suffix = exportedName(rr.GetType()) + exportedName(rr.GetRelation())
	default:
		g.UserExpr = fmt.Sprintf("%s + subjectID", strconv.Quote(rr.GetType()+":"))
		g.NeedsSubject = true
		suffix = exportedName(rr.GetType())
	}

	if g.Condition != "" {
		cond, ok := conditions[g.Condition]
		if !ok || cond == nil {
			return Grant{}, fmt.Errorf("restriction references undefined condition %q", g.Condition)
		}
		g.ConditionGoName = exportedName(g.Condition)
		suffix += g.ConditionGoName
	}

	g.GoName = "Grant" + exportedName(objectType) + exportedName(relation) + suffix
	return g, nil
}

func sortByGoName(s []Relation) {
	sort.Slice(s, func(i, j int) bool { return s[i].GoName < s[j].GoName })
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
