package authzgen

import (
	"strings"
	"testing"
)

func TestParseAnnotations(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		want    map[string]map[string]Phase
		wantErr string
	}{
		{
			name: "write and check",
			src: `
# fga:write allowed_pattern
# fga:check requested_path
condition path_match(allowed_pattern: string, requested_path: string) {
  requested_path.startsWith(allowed_pattern)
}`,
			want: map[string]map[string]Phase{
				"path_match": {"allowed_pattern": PhaseWrite, "requested_path": PhaseCheck},
			},
		},
		{
			name: "multiple params per directive and interleaved prose",
			src: `
# fga:write grant_time, grant_duration
# the caller supplies the clock
# fga:check current_time
condition non_expired_grant(grant_time: timestamp, grant_duration: duration, current_time: timestamp) {
  current_time < grant_time + grant_duration
}`,
			want: map[string]map[string]Phase{
				"non_expired_grant": {
					"grant_time":     PhaseWrite,
					"grant_duration": PhaseWrite,
					"current_time":   PhaseCheck,
				},
			},
		},
		{
			name: "write only is allowed",
			src: `
# fga:write allowed_pattern
condition always(allowed_pattern: string) {
  allowed_pattern == allowed_pattern
}`,
			want: map[string]map[string]Phase{
				"always": {"allowed_pattern": PhaseWrite},
			},
		},
		{
			name: "directive not attached to a condition",
			src: `
# fga:write allowed_pattern
type document
  relations
    define viewer: [user]`,
			wantErr: "not attached to a condition",
		},
		{
			name: "same parameter in both phases",
			src: `
# fga:write p
# fga:check p
condition c(p: string) { p == p }`,
			wantErr: "declared write and check",
		},
		{
			name: "empty directive",
			src: `
# fga:check
condition c(p: string) { p == p }`,
			wantErr: "lists no parameters",
		},
		{
			name: "trailing directives at end of file",
			src:  "# fga:write p\n",
			wantErr: "not attached to a condition",
		},
		{
			name: "userset syntax is not mistaken for a comment",
			src: `
type document
  relations
    define viewer: [user, group#member]`,
			want: map[string]map[string]Phase{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAnnotations("model.fga", []byte(tt.src))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("got nil error, want one containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d conditions, want %d", len(got), len(tt.want))
			}
			for name, wantParams := range tt.want {
				ann, ok := got[name]
				if !ok {
					t.Fatalf("condition %q missing", name)
				}
				if len(ann.Params) != len(wantParams) {
					t.Fatalf("condition %q: got %v, want %v", name, ann.Params, wantParams)
				}
				for p, phase := range wantParams {
					if ann.Params[p] != phase {
						t.Errorf("condition %q param %q: got %v, want %v", name, p, ann.Params[p], phase)
					}
				}
			}
		})
	}
}

func TestExportedName(t *testing.T) {
	for in, want := range map[string]string{
		"path_match":   "PathMatch",
		"can_read":     "CanRead",
		"user_id":      "UserID",
		"ip_allowlist": "IPAllowlist",
		"viewer":       "Viewer",
	} {
		if got := exportedName(in); got != want {
			t.Errorf("exportedName(%q) = %q, want %q", in, got, want)
		}
	}
}
