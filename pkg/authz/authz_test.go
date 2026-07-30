package authz

import "testing"

// The CNF semantics live in the domain, so they are tested once, here,
// without a server — and every Authorizer implementation inherits them.
func TestFold(t *testing.T) {
	sub := Subject{UID: 1000}
	a := ContainerView.On("a")
	b := ContainerOperate.On("b")

	tests := []struct {
		name    string
		reqs    []Requirement
		allowed map[string]bool
		want    bool
	}{
		{
			name: "all requirements satisfied",
			reqs: []Requirement{One(a), One(b)},
			allowed: map[string]bool{
				a.Key(): true, b.Key(): true,
			},
			want: true,
		},
		{
			name:    "one requirement denied sinks the request",
			reqs:    []Requirement{One(a), One(b)},
			allowed: map[string]bool{a.Key(): true},
			want:    false,
		},
		{
			name:    "any alternative satisfies a requirement",
			reqs:    []Requirement{Require("either", a, b)},
			allowed: map[string]bool{b.Key(): true},
			want:    true,
		},
		{
			name:    "unanswered check counts as denied",
			reqs:    []Requirement{One(a)},
			allowed: nil,
			want:    false,
		},
		{
			name:    "requirement with no alternatives denies",
			reqs:    []Requirement{{Name: "empty"}},
			allowed: map[string]bool{a.Key(): true},
			want:    false,
		},
		{
			name:    "zero requirements deny, never vacuously allow",
			reqs:    nil,
			allowed: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Fold(sub, "test", tt.reqs, nil, tt.allowed)
			if got.Allowed != tt.want {
				t.Fatalf("Allowed = %v, want %v", got.Allowed, tt.want)
			}
			if len(got.Requirements) != len(tt.reqs) {
				t.Fatalf("Requirements = %d, want %d", len(got.Requirements), len(tt.reqs))
			}
		})
	}
}

// Dedup keeps one batch item per distinct (object, relation, context).
func TestFlattenDedupes(t *testing.T) {
	same := ContainerView.On("a")
	withCtx := ContainerView.On("a").WithContext(map[string]any{"k": "v"})

	got := Flatten([]Requirement{One(same), One(same), One(withCtx)})
	if len(got) != 2 {
		t.Fatalf("Flatten returned %d checks, want 2 (context differentiates)", len(got))
	}
}
