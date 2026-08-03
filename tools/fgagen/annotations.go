package authzgen

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Phase is the lifecycle stage at which a condition parameter is supplied.
//
// The distinction is load-bearing: OpenFGA gives values persisted in a
// relationship tuple precedence over values supplied in the Check request, so a
// parameter classified as PhaseWrite can never be influenced by the caller of a
// Check. Splitting the two into unrelated Go types turns a misuse that would
// otherwise be silently ignored at runtime into a compile error.
type Phase int

const (
	// PhaseWrite parameters are frozen into the tuple's condition context when
	// the grant is written.
	PhaseWrite Phase = iota
	// PhaseCheck parameters are supplied per request, in the Check context.
	PhaseCheck
)

func (p Phase) String() string {
	switch p {
	case PhaseWrite:
		return "write"
	case PhaseCheck:
		return "check"
	default:
		return fmt.Sprintf("Phase(%d)", int(p))
	}
}

// ConditionAnnotation records the declared phase of every parameter of a single
// condition, along with the source line of the condition declaration it was
// attached to.
type ConditionAnnotation struct {
	Line   int
	Params map[string]Phase
}

// Annotations maps condition name to its parsed directives.
type Annotations map[string]ConditionAnnotation

var (
	// "# fga:write allowed_pattern, max_bytes"
	directiveRE = regexp.MustCompile(`^[\t ]*#[\t ]*fga:(write|check)\b(.*)$`)
	// "condition path_match(allowed_pattern: string, ...)"
	conditionRE = regexp.MustCompile(`^[\t ]*condition[\t ]+([A-Za-z_][A-Za-z0-9_]*)[\t ]*\(`)
	commentRE   = regexp.MustCompile(`^[\t ]*#`)
	identRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type pendingDirective struct {
	phase Phase
	param string
	line  int
}

// ParseAnnotations scans the raw DSL for fga:write and fga:check directives and
// attaches each run of them to the condition declaration that follows.
//
// It deliberately does not parse the DSL. Semantics come from
// transformer.TransformDSLToProto; this pass only harvests comments, which the
// ANTLR lexer discards. Everything it reports is therefore a lexical error:
// cross-checking the directives against the real parameter list happens in
// Load, where the parsed model is available.
func ParseAnnotations(filename string, src []byte) (Annotations, error) {
	out := Annotations{}
	var (
		pending []pendingDirective
		errs    []error
	)

	fail := func(line int, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s:%d: %s", filename, line, fmt.Sprintf(format, args...)))
	}

	for i, raw := range strings.Split(string(src), "\n") {
		line := i + 1

		if m := directiveRE.FindStringSubmatch(raw); m != nil {
			phase := PhaseWrite
			if m[1] == "check" {
				phase = PhaseCheck
			}
			params := splitParams(m[2])
			if len(params) == 0 {
				fail(line, "fga:%s directive lists no parameters", m[1])
				continue
			}
			for _, p := range params {
				if !identRE.MatchString(p) {
					fail(line, "invalid parameter name %q in fga:%s directive", p, m[1])
					continue
				}
				pending = append(pending, pendingDirective{phase: phase, param: p, line: line})
			}
			continue
		}

		if m := conditionRE.FindStringSubmatch(raw); m != nil {
			name := m[1]
			if _, dup := out[name]; dup {
				// The transformer rejects duplicate conditions too, but
				// reporting it here keeps the join in Load unambiguous.
				fail(line, "condition %q declared more than once", name)
			}
			ann := ConditionAnnotation{Line: line, Params: make(map[string]Phase, len(pending))}
			for _, d := range pending {
				if prev, ok := ann.Params[d.param]; ok {
					fail(d.line, "parameter %q of condition %q is declared %s and %s",
						d.param, name, prev, d.phase)
					continue
				}
				ann.Params[d.param] = d.phase
			}
			out[name] = ann
			pending = pending[:0]
			continue
		}

		// Blank lines and unrelated comments may separate the directive block
		// from its condition; anything else ends it.
		if strings.TrimSpace(raw) == "" || commentRE.MatchString(raw) {
			continue
		}
		for _, d := range pending {
			fail(d.line, "fga:%s directive is not attached to a condition declaration", d.phase)
		}
		pending = pending[:0]
	}

	for _, d := range pending {
		fail(d.line, "fga:%s directive is not attached to a condition declaration", d.phase)
	}

	return out, errors.Join(errs...)
}

func splitParams(s string) []string {
	// Trailing prose after the parameter list is not supported: a comma or space
	// separated list is the whole of the directive.
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}
