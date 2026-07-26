package authz

import (
	"context"
	"fmt"
	"io"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	openfga_transformer "github.com/openfga/language/pkg/go/transformer"
	openfga_server "github.com/openfga/openfga/pkg/server"
	openfga_storage_memory "github.com/openfga/openfga/pkg/storage/memory"
	openfga_tuple "github.com/openfga/openfga/pkg/tuple"
	"google.golang.org/protobuf/types/known/structpb"
)

type FGA struct {
	srv     *openfga_server.Server
	storeId string
	modelId string
}

func NewFGA() (*FGA, error) {
	ds := openfga_storage_memory.New()

	srv, err := openfga_server.NewServerWithOpts(
		openfga_server.WithDatastore(ds),
	)
	if err != nil {
		return nil, err
	}

	store, err := srv.CreateStore(context.Background(), &openfgav1.CreateStoreRequest{Name: "fga-lib"})
	if err != nil {
		return nil, fmt.Errorf("fga: create store: %w", err)
	}

	s := &FGA{
		srv:     srv,
		storeId: store.GetId(),
	}

	r, err := fgaModules.Open("model.fga")
	if err != nil {
		return nil, fmt.Errorf("fga: open embedded model: %w", err)
	}
	defer r.Close()

	if _, err := s.loadModel(context.Background(), r); err != nil {
		return nil, fmt.Errorf("fga: load authorization model: %w", err)
	}

	return s, nil
}

func (f *FGA) loadModel(ctx context.Context, r io.Reader) (string, error) {
	modelData, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	proto, err := openfga_transformer.TransformDSLToProto(string(modelData))
	if err != nil {
		return "", err
	}

	if err := ValidateModel(proto.TypeDefinitions); err != nil {
		return "", err
	}

	resp, err := f.srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         f.storeId,
		TypeDefinitions: proto.TypeDefinitions,
		SchemaVersion:   proto.SchemaVersion,
		Conditions:      proto.Conditions,
	})
	if err != nil {
		return "", err
	}

	modelId := resp.GetAuthorizationModelId()
	f.modelId = modelId

	return modelId, nil
}

func (f *FGA) Check(ctx context.Context, sub Subject, c Check) (Decision, error) {
	condCtx, err := contextToStruct(c.Context())
	if err != nil {
		return Decision{}, fmt.Errorf("fga check: %w", err)
	}

	resp, err := f.srv.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              f.storeId,
		AuthorizationModelId: f.modelId,
		TupleKey:             openfga_tuple.NewCheckRequestTupleKey(c.Object(), c.Relation(), sub.String()),
		Context:              condCtx,
	})
	if err != nil {
		return Decision{}, fmt.Errorf("fga check: %w", err) // caller fails closed
	}

	return Decision{
		Allowed: resp.GetAllowed(),
		Subject: sub.String(),
		Checks:  []Check{c},
		ModelID: f.modelId,
	}, nil
}

// BatchCheck has AND semantics: container create needs host.can_create AND
// image.can_use AND a grant on every volume/network in the spec.
func (f *FGA) BatchCheck(ctx context.Context, sub Subject, cs []Check) (Decision, error) {
	items := make([]*openfgav1.BatchCheckItem, len(cs))
	for i, c := range cs {
		condCtx, err := contextToStruct(c.Context())
		if err != nil {
			return Decision{}, fmt.Errorf("fga batch check: %w", err)
		}

		items[i] = &openfgav1.BatchCheckItem{
			TupleKey:      openfga_tuple.NewCheckRequestTupleKey(c.Object(), c.Relation(), sub.String()),
			Context:       condCtx,
			CorrelationId: fmt.Sprintf("c%d", i),
		}
	}

	resp, err := f.srv.BatchCheck(ctx, &openfgav1.BatchCheckRequest{
		StoreId:              f.storeId,
		AuthorizationModelId: f.modelId,
		Checks:               items,
	})
	if err != nil {
		return Decision{}, fmt.Errorf("fga batch check: %w", err)
	}

	allowed := len(cs) > 0
	for _, r := range resp.GetResult() {
		if !r.GetAllowed() {
			allowed = false
			break
		}
	}

	return Decision{Allowed: allowed, Subject: sub.String(), Checks: cs, ModelID: f.modelId}, nil
}

func (f *FGA) ListIDs(ctx context.Context, sub Subject, p Permission) (map[string]bool, error) {
	resp, err := f.srv.ListObjects(ctx, &openfgav1.ListObjectsRequest{
		StoreId:              f.storeId,
		AuthorizationModelId: f.modelId,
		User:                 sub.String(),
		Relation:             p.relation,
		Type:                 p.objType,
	})
	if err != nil {
		return nil, fmt.Errorf("fga list objects: %w", err)
	}

	ids := make(map[string]bool, len(resp.GetObjects()))
	for _, obj := range resp.GetObjects() { // "container:abc" -> "abc"
		if _, id, ok := strings.Cut(obj, ":"); ok {
			ids[id] = true
		}
	}

	return ids, nil
}

// Grant seeds a relationship tuple in the store, e.g. attaching a user to a
// path_grant's holder relation, or attaching a path_grant to a filesystem's
// mount_grant relation with a path_matches condition. It is used to
// bootstrap policy data and in tests, not to answer authorization questions,
// so it lives on FGA rather than the Authorizer interface.
type Grant struct {
	Object   string // "type:id", e.g. "filesystem:host"
	Relation string
	User     string // "type:id" or "type:id#relation", e.g. "user:uid-1000"

	// Condition and ConditionContext are optional. Condition names an FGA
	// model condition (e.g. "path_matches"); ConditionContext supplies the
	// parameters bound to this tuple at write time (e.g. allowed_pattern).
	Condition        string
	ConditionContext Context
}

// WriteGrants writes grants as relationship tuples.
func (f *FGA) WriteGrants(ctx context.Context, grants ...Grant) error {
	tupleKeys := make([]*openfgav1.TupleKey, len(grants))
	for i, g := range grants {
		if g.Condition == "" {
			tupleKeys[i] = openfga_tuple.NewTupleKey(g.Object, g.Relation, g.User)
			continue
		}

		condCtx, err := contextToStruct(g.ConditionContext)
		if err != nil {
			return fmt.Errorf("fga write grants: %w", err)
		}
		tupleKeys[i] = openfga_tuple.NewTupleKeyWithCondition(g.Object, g.Relation, g.User, g.Condition, condCtx)
	}

	_, err := f.srv.Write(ctx, &openfgav1.WriteRequest{
		StoreId:              f.storeId,
		AuthorizationModelId: f.modelId,
		Writes:               &openfgav1.WriteRequestWrites{TupleKeys: tupleKeys},
	})
	if err != nil {
		return fmt.Errorf("fga write grants: %w", err)
	}

	return nil
}

// ValidateModel checks that every permission in the catalog (permissions.go)
// names a (type, relation) pair the deployed model actually defines. It is
// called while loading the model so that permissions.go/model.fga drift
// fails the boot with a precise error instead of surfacing later as a
// runtime "unknown relation" error on whichever request hits it first.
func ValidateModel(defs []*openfgav1.TypeDefinition) error {
	relations := make(map[string]map[string]bool, len(defs))
	for _, td := range defs {
		rs := make(map[string]bool, len(td.GetRelations()))
		for rel := range td.GetRelations() {
			rs[rel] = true
		}
		relations[td.GetType()] = rs
	}

	var missing []string
	for _, p := range all {
		if !relations[p.objType][p.relation] {
			missing = append(missing, p.objType+"#"+p.relation)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("authz: model missing permissions declared in catalog: %s", strings.Join(missing, ", "))
	}

	return nil
}

// contextToStruct converts condition context to the structpb.Struct the
// OpenFGA API expects, returning nil for empty context rather than an empty
// struct.
func contextToStruct(c Context) (*structpb.Struct, error) {
	if len(c) == 0 {
		return nil, nil
	}

	s, err := structpb.NewStruct(c)
	if err != nil {
		return nil, fmt.Errorf("condition context: %w", err)
	}

	return s, nil
}
