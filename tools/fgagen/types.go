package authzgen

import (
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

// goType is the result of mapping one condition parameter type.
type goType struct {
	Name    string   // Go type expression
	Imports []string // import paths the type or its encoding requires
	Slice   bool     // fgaSlice helper is required
	Map     bool     // fgaMap helper is required
}

// mapParamType returns the Go type for ref and a Go expression that encodes
// accessor into a value safe to place in a condition context.
//
// Encoding is explicit rather than reflective for one reason: everything
// crosses the wire inside a structpb.Struct, whose only numeric kind is
// float64. Handing structpb an int64 above 2^53 loses precision silently, so
// integers are encoded as decimal strings, which the server coerces back to the
// declared parameter type. Durations and timestamps are likewise encoded in the
// string forms the server parses ("10m", RFC 3339) instead of being flattened
// into numbers.
func mapParamType(ref *openfgav1.ConditionParamTypeRef, accessor string, depth int) (goType, string, error) {
	switch ref.GetTypeName() {
	case openfgav1.ConditionParamTypeRef_TYPE_NAME_STRING:
		return goType{Name: "string"}, accessor, nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_BOOL:
		return goType{Name: "bool"}, accessor, nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_DOUBLE:
		return goType{Name: "float64"}, accessor, nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_INT:
		return goType{Name: "int64", Imports: []string{"strconv"}},
			fmt.Sprintf("strconv.FormatInt(%s, 10)", accessor), nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_UINT:
		return goType{Name: "uint64", Imports: []string{"strconv"}},
			fmt.Sprintf("strconv.FormatUint(%s, 10)", accessor), nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_DURATION:
		return goType{Name: "time.Duration", Imports: []string{"time"}},
			fmt.Sprintf("%s.String()", accessor), nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_TIMESTAMP:
		return goType{Name: "time.Time", Imports: []string{"time"}},
			fmt.Sprintf("%s.UTC().Format(time.RFC3339Nano)", accessor), nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_IPADDRESS:
		return goType{Name: "netip.Addr", Imports: []string{"net/netip"}},
			fmt.Sprintf("%s.String()", accessor), nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_ANY:
		return goType{Name: "any"}, accessor, nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_LIST:
		elem, err := generic(ref)
		if err != nil {
			return goType{}, "", err
		}
		v := fmt.Sprintf("v%d", depth)
		et, enc, err := mapParamType(elem, v, depth+1)
		if err != nil {
			return goType{}, "", err
		}
		t := goType{Name: "[]" + et.Name, Imports: et.Imports, Slice: true, Map: et.Map}
		return t, fmt.Sprintf("fgaSlice(%s, func(%s %s) any { return %s })", accessor, v, et.Name, enc), nil

	case openfgav1.ConditionParamTypeRef_TYPE_NAME_MAP:
		elem, err := generic(ref)
		if err != nil {
			return goType{}, "", err
		}
		v := fmt.Sprintf("v%d", depth)
		et, enc, err := mapParamType(elem, v, depth+1)
		if err != nil {
			return goType{}, "", err
		}
		t := goType{Name: "map[string]" + et.Name, Imports: et.Imports, Slice: et.Slice, Map: true}
		return t, fmt.Sprintf("fgaMap(%s, func(%s %s) any { return %s })", accessor, v, et.Name, enc), nil

	default:
		return goType{}, "", fmt.Errorf("unsupported parameter type %s", ref.GetTypeName())
	}
}

func generic(ref *openfgav1.ConditionParamTypeRef) (*openfgav1.ConditionParamTypeRef, error) {
	gt := ref.GetGenericTypes()
	if len(gt) != 1 {
		return nil, fmt.Errorf("%s expects exactly one generic type, got %d", ref.GetTypeName(), len(gt))
	}
	return gt[0], nil
}
