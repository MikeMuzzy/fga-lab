package authz

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

// grantMount seeds a policy under which uid is granted can_mount on
// filesystem:host for any path matching pattern: a user:uid-<uid> holds
// path_grant:mnt1, and path_grant:mnt1 is attached to filesystem:host's
// mount_grant with a path_matches condition bound to pattern.
func grantMount(t *testing.T, f *FGA, uid uint32, pattern string) {
	t.Helper()

	sub := Subject{UID: uid}
	err := f.WriteGrants(context.Background(),
		Grant{
			Object:   "path_grant:mnt1",
			Relation: "holder",
			User:     sub.String(),
		},
		Grant{
			Object:           "filesystem:host",
			Relation:         "mount_grant",
			User:             "path_grant:mnt1",
			Condition:        "path_matches",
			ConditionContext: Context{"allowed_pattern": pattern},
		},
	)
	if err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
}

func TestFGACheck_PathMatchesCondition(t *testing.T) {
	f, err := NewFGA()
	if err != nil {
		t.Fatalf("NewFGA: %v", err)
	}

	grantMount(t, f, 1000, "^/data/.*")

	tests := []struct {
		name          string
		uid           uint32
		requestedPath string
		wantAllowed   bool
	}{
		{"path under allowed pattern", 1000, "/data/foo/bar", true},
		{"path outside allowed pattern", 1000, "/etc/passwd", false},
		{"no grant for this user", 2000, "/data/foo/bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub := Subject{UID: tt.uid}
			check := CanMount.On("host").WithContext(Context{"requested_path": tt.requestedPath})

			decision, err := f.Check(context.Background(), sub, check)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
		})
	}
}

func TestFGABatchCheck_AndSemantics(t *testing.T) {
	f, err := NewFGA()
	if err != nil {
		t.Fatalf("NewFGA: %v", err)
	}

	grantMount(t, f, 1000, "^/data/.*")
	sub := Subject{UID: 1000}

	allowed := CanMount.On("host").WithContext(Context{"requested_path": "/data/a"})
	denied := CanMount.On("host").WithContext(Context{"requested_path": "/etc/passwd"})

	decision, err := f.BatchCheck(context.Background(), sub, []Check{allowed, denied})
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if decision.Allowed {
		t.Errorf("BatchCheck with one denied check should deny, got Allowed = true")
	}

	decision, err = f.BatchCheck(context.Background(), sub, []Check{allowed})
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("BatchCheck with only allowed checks should allow, got Allowed = false")
	}
}

func TestFGAListIDs(t *testing.T) {
	f, err := NewFGA()
	if err != nil {
		t.Fatalf("NewFGA: %v", err)
	}

	sub := Subject{UID: 1000}
	err = f.WriteGrants(context.Background(),
		Grant{Object: "container:a", Relation: "owner", User: sub.String()},
		Grant{Object: "container:b", Relation: "owner", User: sub.String()},
	)
	if err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	ids, err := f.ListIDs(context.Background(), sub, ContainerView)
	if err != nil {
		t.Fatalf("ListIDs: %v", err)
	}

	want := map[string]bool{"a": true, "b": true}
	if len(ids) != len(want) || !ids["a"] || !ids["b"] {
		t.Errorf("ListIDs = %v, want %v", ids, want)
	}
}

func TestFGANewFGA_ValidatesCatalogAgainstModel(t *testing.T) {
	// Every catalog entry in permissions.go must resolve against model.fga;
	// NewFGA calls ValidateModel while loading it, so a passing NewFGA is
	// itself the drift check.
	if _, err := NewFGA(); err != nil {
		t.Fatalf("NewFGA: %v", err)
	}
}

func TestValidateModel_ReportsMissingPermissions(t *testing.T) {
	// A model with none of the catalog's types defined should fail closed
	// with every missing (type, relation) pair named, not boot silently.
	err := ValidateModel(nil)
	if err == nil {
		t.Fatal("ValidateModel(nil) = nil, want error naming every catalog permission as missing")
	}
}

func TestValidateModel_AcceptsCompleteModel(t *testing.T) {
	// One TypeDefinition per type carrying every relation catalogued for it,
	// mirroring how OpenFGA actually shapes a model (a type appears once,
	// with all its relations in a single map).
	relationsByType := make(map[string]map[string]*openfgav1.Userset)
	for _, p := range all {
		if relationsByType[p.objType] == nil {
			relationsByType[p.objType] = make(map[string]*openfgav1.Userset)
		}
		relationsByType[p.objType][p.relation] = &openfgav1.Userset{}
	}

	defs := make([]*openfgav1.TypeDefinition, 0, len(relationsByType))
	for objType, relations := range relationsByType {
		defs = append(defs, &openfgav1.TypeDefinition{Type: objType, Relations: relations})
	}

	if err := ValidateModel(defs); err != nil {
		t.Fatalf("ValidateModel with every catalog permission defined: %v", err)
	}
}
