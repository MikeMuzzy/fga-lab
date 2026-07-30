package fga

import (
	"encoding/json"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/encoding/protojson"
)

// transformDSL converts the embedded DSL into the SDK's write request.
func transformDSL(dsl string) (fgaclient.ClientWriteAuthorizationModelRequest, error) {
	var req fgaclient.ClientWriteAuthorizationModelRequest

	proto, err := transformer.TransformDSLToProto(dsl)
	if err != nil {
		return req, fmt.Errorf("%w: %v", ErrModelTransform, err)
	}
	// Round-trip through protojson: the SDK request type mirrors the API
	// JSON shape, so this avoids hand-mapping every type definition.
	buf, err := protojson.Marshal(proto)
	if err != nil {
		return req, fmt.Errorf("%w: marshal: %v", ErrModelTransform, err)
	}
	if err := json.Unmarshal(buf, &req); err != nil {
		return req, fmt.Errorf("%w: unmarshal: %v", ErrModelTransform, err)
	}
	return req, nil
}

// sameModel compares a deployed model against the desired write request on
// their canonical structures — type definitions and conditions — rather than
// DSL text, so comments and formatting never trigger a needless write.
// Ids and schema metadata are excluded: the id differs by construction.
func sameModel(deployed *openfgav1.AuthorizationModel, want fgaclient.ClientWriteAuthorizationModelRequest) (bool, error) {
	type shape struct {
		TypeDefinitions json.RawMessage `json:"type_definitions"`
		Conditions      json.RawMessage `json:"conditions"`
		SchemaVersion   string          `json:"schema_version"`
	}

	canon := func(v any) (string, error) {
		buf, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		var s shape
		if err := json.Unmarshal(buf, &s); err != nil {
			return "", err
		}
		// Re-marshal through map[string]any so key order is normalized.
		var norm any
		if err := json.Unmarshal(buf, &norm); err != nil {
			return "", err
		}
		out, err := json.Marshal(struct {
			T json.RawMessage `json:"t"`
			C json.RawMessage `json:"c"`
			S string          `json:"s"`
		}{s.TypeDefinitions, s.Conditions, s.SchemaVersion})
		return string(out), err
	}

	deployedJSON, err := protojson.Marshal(deployed)
	if err != nil {
		return false, fmt.Errorf("marshal deployed model: %w", err)
	}
	var deployedAny any
	if err := json.Unmarshal(deployedJSON, &deployedAny); err != nil {
		return false, err
	}

	a, err := canon(deployedAny)
	if err != nil {
		return false, err
	}
	b, err := canon(want)
	if err != nil {
		return false, err
	}
	return a == b, nil
}
