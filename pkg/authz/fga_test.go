package authz

import (
	"context"
	"testing"
)

// setupHostGrant seeds a policy under which uid is granted
// can_recursive_list on filesystem:host for any path matching pattern: a
// user:uid-<uid> holds path_grant:mnt1, and path_grant:mnt1 is attached to
// filesystem:host's recursive_list_grant with a path_matches condition
// bound to pattern.
func setupHostGrant(t *testing.T, f *FGA, uid uint32, pattern string) {
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
			Relation:         "recursive_list_grant",
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

	setupHostGrant(t, f, 1000, "^/data/.*")

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
			check := CanRecursiveList.On("host").WithContext(Context{"requested_path": tt.requestedPath})

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

	setupHostGrant(t, f, 1000, "^/data/.*")
	sub := Subject{UID: 1000}

	allowed := CanRecursiveList.On("host").WithContext(Context{"requested_path": "/data/a"})
	denied := CanRecursiveList.On("host").WithContext(Context{"requested_path": "/etc/passwd"})

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
