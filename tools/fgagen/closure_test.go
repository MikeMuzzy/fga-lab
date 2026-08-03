package authzgen

import (
	"reflect"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

func this() *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_This{This: &openfgav1.DirectUserset{}}}
}

func computed(rel string) *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_ComputedUserset{
		ComputedUserset: &openfgav1.ObjectRelation{Relation: rel},
	}}
}

func ttu(tupleset, target string) *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_TupleToUserset{
		TupleToUserset: &openfgav1.TupleToUserset{
			Tupleset:        &openfgav1.ObjectRelation{Relation: tupleset},
			ComputedUserset: &openfgav1.ObjectRelation{Relation: target},
		},
	}}
}

func union(children ...*openfgav1.Userset) *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_Union{
		Union: &openfgav1.Usersets{Child: children},
	}}
}

func directRef(t, condition string) *openfgav1.RelationReference {
	return &openfgav1.RelationReference{Type: t, Condition: condition}
}

func usersetRef(t, rel, condition string) *openfgav1.RelationReference {
	return &openfgav1.RelationReference{
		Type:               t,
		RelationOrWildcard: &openfgav1.RelationReference_Relation{Relation: rel},
		Condition:          condition,
	}
}

func relMeta(refs ...*openfgav1.RelationReference) *openfgav1.RelationMetadata {
	return &openfgav1.RelationMetadata{DirectlyRelatedUserTypes: refs}
}

// testModel mirrors the shape of model.fga: a self-referential parent edge, a
// tuple-to-userset that recurses through it, and a userset that reaches a
// condition on another type.
func testModel() typeIndex {
	return newTypeIndex(&openfgav1.AuthorizationModel{
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "user"},
			{
				Type:      "group",
				Relations: map[string]*openfgav1.Userset{"member": this()},
				Metadata: &openfgav1.Metadata{Relations: map[string]*openfgav1.RelationMetadata{
					"member": relMeta(directRef("user", "")),
				}},
			},
			{
				Type: "bind",
				Relations: map[string]*openfgav1.Userset{
					"parent":  this(),
					"owner":   this(),
					"mounter": this(),
					"can_mount": union(
						computed("mounter"),
						computed("owner"),
						ttu("parent", "can_mount"),
					),
				},
				Metadata: &openfgav1.Metadata{Relations: map[string]*openfgav1.RelationMetadata{
					// Self-referential: the walk must terminate.
					"parent":  relMeta(directRef("bind", "")),
					"owner":   relMeta(directRef("user", "")),
					"mounter": relMeta(directRef("user", "path_within"), usersetRef("group", "member", "path_within")),
				}},
			},
		},
	})
}

func TestConditionClosure(t *testing.T) {
	idx := testModel()

	tests := []struct {
		node node
		want []string
	}{
		{node{"bind", "owner"}, nil},
		{node{"bind", "mounter"}, []string{"path_within"}},
		// Reached through the union, and again through the recursive TTU.
		{node{"bind", "can_mount"}, []string{"path_within"}},
		{node{"group", "member"}, nil},
		{node{"bind", "nonexistent"}, nil},
	}

	for _, tt := range tests {
		got := idx.conditionClosure(tt.node)
		if len(got) == 0 && len(tt.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("closure(%s#%s) = %v, want %v", tt.node.objType, tt.node.relation, got, tt.want)
		}
	}
}

// TestConditionClosureTerminates guards the cycle protection directly: without
// the visited set, parent -> can_mount -> parent would not return.
func TestConditionClosureTerminates(t *testing.T) {
	done := make(chan []string, 1)
	go func() { done <- testModel().conditionClosure(node{"bind", "can_mount"}) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("conditionClosure did not terminate on a self-referential model")
	}
}
