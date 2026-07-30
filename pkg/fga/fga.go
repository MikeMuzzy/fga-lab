// Package fga adapts OpenFGA to the authz domain. It is the only package
// that imports the OpenFGA SDK, and no SDK type crosses its boundary: it
// consumes authz vocabulary types and returns authz.Decision.
package fga

import (
	"context"
	"errors"
	"fmt"
	"strings"

	fgaclient "github.com/openfga/go-sdk/client"

	"podmanproxy/internal/authz"
)

// Client implements authz.Authorizer and authz.TupleWriter.
//
// Requires go-sdk >= v0.6 and OpenFGA >= v1.8 for server-side BatchCheck;
// verify field shapes against your pinned SDK version.
type Client struct {
	api     *fgaclient.OpenFgaClient
	modelID string
}

var (
	_ authz.Authorizer  = (*Client)(nil)
	_ authz.TupleWriter = (*Client)(nil)
)

// New connects to the store and provisions the embedded model, returning a
// client pinned to the resulting model id. Provisioning at startup means the
// deployed model is definitionally the embedded one, so a separate
// code-vs-deployed drift check is unnecessary for relations we generate —
// validate() still covers hand-maintained fact shapes.
func New(ctx context.Context, apiURL, storeID string) (*Client, error) {
	api, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:  apiURL,
		StoreId: storeID,
	})
	if err != nil {
		return nil, fmt.Errorf("fga client: %w", err)
	}
	c := &Client{api: api}
	if c.modelID, err = c.ensureModel(ctx); err != nil {
		return nil, err
	}
	// Pin: every check evaluates against exactly the model we provisioned,
	// and the audit log's model_id is meaningful.
	c.api.SetAuthorizationModelId(c.modelID)
	if err := c.validate(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// ModelID reports the pinned model version, recorded in every decision.
func (c *Client) ModelID() string { return c.modelID }

// Authorize flattens and dedupes all alternatives into one BatchCheck, then
// delegates CNF folding to the domain. Fail-closed properties live in
// authz.Fold; here, an unanswered batch item simply stays absent from the
// results map and therefore counts as denied.
func (c *Client) Authorize(ctx context.Context, sub authz.Subject, reqs []authz.Requirement, facts []authz.Tuple) (authz.Decision, error) {
	checks := authz.Flatten(reqs)
	if len(checks) == 0 {
		return authz.Fold(sub, c.modelID, reqs, facts, nil), nil
	}

	contextual := toContextualTuples(facts)
	items := make([]fgaclient.ClientBatchCheckItem, len(checks))
	for i, ch := range checks {
		items[i] = fgaclient.ClientBatchCheckItem{
			User:             sub.String(),
			Relation:         ch.Relation(),
			Object:           ch.Object(),
			CorrelationId:    fmt.Sprintf("c%d", i),
			Context:          contextPtr(ch.Context()),
			ContextualTuples: contextual,
		}
	}
	resp, err := c.api.BatchCheck(ctx).Body(fgaclient.ClientBatchCheckBody{Checks: items}).Execute()
	if err != nil {
		// Wrapped in a domain sentinel: callers fail closed via errors.Is
		// without type-asserting on SDK errors.
		return authz.Decision{}, fmt.Errorf("%w: batch check: %v", authz.ErrUnavailable, err)
	}

	allowed := make(map[string]bool, len(checks))
	for id, r := range resp.GetResult() {
		var i int
		if _, err := fmt.Sscanf(id, "c%d", &i); err == nil && i >= 0 && i < len(checks) {
			allowed[checks[i].Key()] = r.GetAllowed()
		}
	}
	return authz.Fold(sub, c.modelID, reqs, facts, allowed), nil
}

// ListIDs evaluates with the same facts as Authorize so list filtering and
// checks see the same world.
//
// Caveat: grants conditioned on per-object context (e.g. image_ref) cannot
// be evaluated here, since request context is single-valued per query.
// Permissions relying on such conditions need proxy-side filtering.
func (c *Client) ListIDs(ctx context.Context, sub authz.Subject, p authz.Permission, facts []authz.Tuple) (map[string]bool, error) {
	resp, err := c.api.ListObjects(ctx).Body(fgaclient.ClientListObjectsRequest{
		User:             sub.String(),
		Relation:         p.Relation(),
		Type:             p.Type(),
		ContextualTuples: toContextualTuples(facts),
	}).Execute()
	if err != nil {
		return nil, fmt.Errorf("%w: list objects: %v", authz.ErrUnavailable, err)
	}
	ids := make(map[string]bool, len(resp.GetObjects()))
	for _, obj := range resp.GetObjects() { // "container:abc" -> "abc"
		if _, id, ok := strings.Cut(obj, ":"); ok {
			ids[id] = true
		}
	}
	return ids, nil
}

// WriteOwnership runs after a successful create. The proxy is the only tuple
// writer, and tuples are attributed to the acting subject.
func (c *Client) WriteOwnership(ctx context.Context, sub authz.Subject, objType, id string) error {
	_, err := c.api.Write(ctx).Body(fgaclient.ClientWriteRequest{
		Writes: []fgaclient.ClientTupleKey{
			{User: sub.String(), Relation: "owner", Object: objType + ":" + id},
			{User: "host:local", Relation: "host", Object: objType + ":" + id},
		},
	}).Execute()
	if err != nil {
		return fmt.Errorf("write ownership %s:%s: %w", objType, id, err)
	}
	return nil
}

// DeleteObjectTuples removes every tuple for an object after a successful
// delete, so orphaned grants cannot resurrect on id reuse.
func (c *Client) DeleteObjectTuples(ctx context.Context, objType, id string) error {
	object := objType + ":" + id
	resp, err := c.api.Read(ctx).Body(fgaclient.ClientReadRequest{Object: &object}).Execute()
	if err != nil {
		return fmt.Errorf("read tuples for %s: %w", object, err)
	}
	tuples := resp.GetTuples()
	if len(tuples) == 0 {
		return nil
	}
	deletes := make([]fgaclient.ClientTupleKeyWithoutCondition, len(tuples))
	for i, t := range tuples {
		k := t.GetKey()
		deletes[i] = fgaclient.ClientTupleKeyWithoutCondition{
			User: k.GetUser(), Relation: k.GetRelation(), Object: k.GetObject(),
		}
	}
	if _, err := c.api.Write(ctx).Body(fgaclient.ClientWriteRequest{Deletes: deletes}).Execute(); err != nil {
		return fmt.Errorf("delete tuples for %s: %w", object, err)
	}
	return nil
}

// ---- model provisioning ----

// ensureModel makes the store's latest model equal the embedded DSL,
// idempotently. Models are immutable in OpenFGA — every write mints a new id
// — so compare before writing, or every restart stacks a duplicate version.
func (c *Client) ensureModel(ctx context.Context) (string, error) {
	want, err := transformDSL(authz.ModelDSL)
	if err != nil {
		return "", fmt.Errorf("transform embedded model: %w", err)
	}
	latest, err := c.api.ReadLatestAuthorizationModel(ctx).Execute()
	if err == nil && latest.AuthorizationModel != nil {
		same, err := sameModel(latest.AuthorizationModel, want)
		if err != nil {
			return "", err
		}
		if same {
			return latest.AuthorizationModel.GetId(), nil
		}
	}
	resp, err := c.api.WriteAuthorizationModel(ctx).Body(want).Execute()
	if err != nil {
		return "", fmt.Errorf("write authorization model: %w", err)
	}
	return resp.GetAuthorizationModelId(), nil
}

// validate fails startup if a hand-maintained contextual fact shape is
// absent from the deployed model — otherwise drift surfaces as per-request
// 400s from the server instead of a failed deploy.
func (c *Client) validate(ctx context.Context) error {
	resp, err := c.api.ReadAuthorizationModel(ctx).Execute()
	if err != nil {
		return fmt.Errorf("read model: %w", err)
	}
	have := map[string]bool{}
	for _, td := range resp.AuthorizationModel.GetTypeDefinitions() {
		for rel := range td.GetRelations() {
			have[td.GetType()+"#"+rel] = true
		}
	}
	var missing []string
	for _, p := range authz.Permissions() {
		if !have[p.Type()+"#"+p.Relation()] {
			missing = append(missing, "permission "+p.Type()+"#"+p.Relation())
		}
	}
	for _, s := range authz.FactShapes() {
		if !have[s.ObjType+"#"+s.Relation] {
			missing = append(missing, "fact "+s.ObjType+"#"+s.Relation)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("definitions absent from deployed model: %s", strings.Join(missing, ", "))
	}
	return nil
}

// ErrModelTransform indicates the embedded DSL could not be parsed.
var ErrModelTransform = errors.New("fga: model transform failed")

// ---- SDK adapters: no SDK type escapes this package ----

func toContextualTuples(facts []authz.Tuple) []fgaclient.ClientContextualTupleKey {
	if len(facts) == 0 {
		return nil
	}
	out := make([]fgaclient.ClientContextualTupleKey, len(facts))
	for i, t := range facts {
		out[i] = fgaclient.ClientContextualTupleKey{
			User: t.User(), Relation: t.Relation(), Object: t.Object(),
		}
	}
	return out
}

func contextPtr(kv map[string]any) *map[string]any {
	if len(kv) == 0 {
		return nil
	}
	return &kv
}
