package authz

import (
	"context"
	"fmt"
	"io"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	openfga_transformer "github.com/openfga/language/pkg/go/transformer"
	openfga_server "github.com/openfga/openfga/pkg/server"
	openfga_storage_memory "github.com/openfga/openfga/pkg/storage/memory"
	openfga_tuple "github.com/openfga/openfga/pkg/tuple"
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

	s := &FGA{
		srv:     srv,
		storeId: "test",
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
	resp, err := f.srv.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              f.storeId,
		AuthorizationModelId: f.modelId,
		TupleKey:             openfga_tuple.NewCheckRequestTupleKey(c.Object(), c.Relation(), sub.String()),
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
		items[i] = &openfgav1.BatchCheckItem{
			TupleKey:      openfga_tuple.NewCheckRequestTupleKey(c.Object(), c.Relation(), sub.String()),
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
