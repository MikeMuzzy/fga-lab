package authzgen

import (
	"sort"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

// node identifies a relation on an object type.
type node struct {
	objType  string
	relation string
}

// typeIndex is the model's type definitions keyed by type name.
type typeIndex map[string]*openfgav1.TypeDefinition

func newTypeIndex(model *openfgav1.AuthorizationModel) typeIndex {
	idx := make(typeIndex, len(model.GetTypeDefinitions()))
	for _, td := range model.GetTypeDefinitions() {
		idx[td.GetType()] = td
	}
	return idx
}

func (idx typeIndex) restrictions(objType, relation string) []*openfgav1.RelationReference {
	return idx[objType].GetMetadata().GetRelations()[relation].GetDirectlyRelatedUserTypes()
}

// conditionClosure returns every condition that evaluating start may traverse,
// sorted by name.
//
// This is an over-approximation: a given Check may match a tuple on an edge
// that carries no condition, in which case context for the others goes unread.
// Unknown keys in a Check context are ignored by the server, so the cost is a
// slightly wider builder signature, not a failed request.
//
// The traversal marks nodes rather than memoizing partial results, because a
// cycle -- folder#parent: [folder] is the common one -- would otherwise let an
// incomplete set be cached and reused. Models are small enough that walking
// afresh per permission is not worth optimizing.
func (idx typeIndex) conditionClosure(start node) []string {
	found := map[string]bool{}
	visited := map[node]bool{}

	var walk func(n node)
	walk = func(n node) {
		if visited[n] {
			return
		}
		visited[n] = true
		td, ok := idx[n.objType]
		if !ok {
			return
		}
		us, ok := td.GetRelations()[n.relation]
		if !ok {
			return
		}
		idx.walkUserset(n, us, found, walk)
	}
	walk(start)

	out := make([]string, 0, len(found))
	for c := range found {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// walkUserset descends the rewrite tree of a single relation. Union,
// intersection and difference arms are all traversed: a condition in a "but
// not" arm is still evaluated, so its parameters are still required.
func (idx typeIndex) walkUserset(n node, us *openfgav1.Userset, found map[string]bool, walk func(node)) {
	switch {
	case us.GetThis() != nil:
		// Direct assignment. The allowed user types, and the conditions
		// attached to them, live in the relation's metadata rather than in the
		// userset itself.
		for _, rr := range idx.restrictions(n.objType, n.relation) {
			if c := rr.GetCondition(); c != "" {
				found[c] = true
			}
			if rr.GetWildcard() != nil {
				continue
			}
			if rel := rr.GetRelation(); rel != "" {
				// A userset such as group#member: resolving it evaluates that
				// relation, including any conditions it reaches.
				walk(node{objType: rr.GetType(), relation: rel})
			}
		}

	case us.GetComputedUserset() != nil:
		walk(node{objType: n.objType, relation: us.GetComputedUserset().GetRelation()})

	case us.GetTupleToUserset() != nil:
		ttu := us.GetTupleToUserset()
		tupleset := ttu.GetTupleset().GetRelation()
		target := ttu.GetComputedUserset().GetRelation()
		// Conditions on the tupleset relation itself are evaluated while
		// resolving the parent edge, so they count too.
		for _, rr := range idx.restrictions(n.objType, tupleset) {
			if c := rr.GetCondition(); c != "" {
				found[c] = true
			}
			if rr.GetWildcard() != nil {
				continue
			}
			walk(node{objType: rr.GetType(), relation: target})
		}

	case us.GetUnion() != nil:
		for _, child := range us.GetUnion().GetChild() {
			idx.walkUserset(n, child, found, walk)
		}

	case us.GetIntersection() != nil:
		for _, child := range us.GetIntersection().GetChild() {
			idx.walkUserset(n, child, found, walk)
		}

	case us.GetDifference() != nil:
		idx.walkUserset(n, us.GetDifference().GetBase(), found, walk)
		idx.walkUserset(n, us.GetDifference().GetSubtract(), found, walk)
	}
}
