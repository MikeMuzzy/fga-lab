# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`fga-lib` is a Go module providing an authorization layer for an "api-proxy" binary that fronts a podman transport. It embeds OpenFGA (Fine-Grained Authorization) as an in-process library — there is no external OpenFGA server; a full `openfga` server (`github.com/openfga/openfga/pkg/server`) is constructed in-memory (`openfga_storage_memory`) and driven directly via its Go API, not over gRPC/HTTP.

The project is very early-stage: `cmd/api-proxy/main.go` is currently just a stub that constructs the `FGA` authorizer, and `pkg/authz/permissions.go` is an empty placeholder for the permission catalog described below.

## Commands

Standard Go tooling applies (module root is `fga-lib`, Go 1.26):

- Build: `go build ./...`
- Run the proxy binary: `go run ./cmd/api-proxy`
- Test all packages: `go test ./...`
- Test a single package: `go test ./pkg/authz`
- Vet: `go vet ./...`

There are no test files yet, no Makefile, and no CI config in this repo.

## Architecture

### `pkg/authz` is the single source of authorization policy

Per the package doc comment in `authz.go`: handlers and the podman transport are expected to contain **no** policy logic themselves — they only consume `Check`s and `Decision`s minted by this package. When adding new authorization logic, it belongs in `pkg/authz`, not in caller code.

Core types (`pkg/authz/authz.go`):

- `Subject` — the authenticated caller, derived from `SO_PEERCRED` (uid/gid), rendered as an OpenFGA user id via `String()` (e.g. `user:uid-1000`).
- `Permission` — pairs an object type + relation. Fields are unexported by design: only this package can construct a `Permission`, so any valid permission must come from the catalog in `permissions.go` (currently unpopulated). Do not add exported fields or a public constructor that bypasses this — the whole point is that invalid (type, relation) pairs are unrepresentable outside the catalog.
- `Check` = a `Permission` bound to a concrete object id via `Permission.On(id)`.
- `Decision` — the result of a check. Deny is a normal, expected value; `error` is reserved for infrastructure failures, which callers must treat as deny (fail-closed).
- `Authorizer` interface — the only authorization surface the rest of the binary should depend on. Has three methods: `Check` (single), `BatchCheck` (AND semantics — all checks must pass), and `ListIDs` (returns the set of object ids a subject holds a given permission on, for filtering list-endpoint responses).
- Context plumbing (`WithDecision`/`DecisionFrom`) uses an unexported `ctxKey` so only this package can attach a `Decision` to a context — handlers cannot forge one.
- `ErrNoDecision` enforces the fail-closed invariant: if the podman transport receives a request with no `Decision` in context, that's an error, not an implicit allow.

### `FGA` — the OpenFGA-backed `Authorizer` implementation (`pkg/authz/fga.go`)

- Constructed via `NewFGA()`, which spins up an in-memory OpenFGA server and loads the authorization model from `model.fga` (embedded via `go:embed` in `model.go`) by transforming the DSL to proto (`openfga_transformer.TransformDSLToProto`) and writing it with `WriteAuthorizationModel`.
- `Check` and `BatchCheck` translate `authz.Check` values into OpenFGA `CheckRequest`/`BatchCheckRequest` calls using `openfga_tuple.NewCheckRequestTupleKey(object, relation, subject)`, scoped to the loaded `storeId`/`modelId`.
- `BatchCheck` is AND-only: e.g. a container-create request needs `host.can_create` AND `image.can_use` AND a grant on every volume/network in the spec — any single deny fails the whole batch.
- `Decision.ModelID` carries the deployed FGA model version through to the audit trail.

### Authorization model (`pkg/authz/model.fga`)

OpenFGA DSL, schema 1.1:

- `user`, `group` (with `member: [user]`) — identity types.
- `path_grant` — a `holder` relation (`[user, group#member]`) representing "who this filesystem grant applies to."
- `filesystem` — `recursive_list_grant: [path_grant with path_matches]` and a computed `can_recursive_list: holder from recursive_list_grant`.
- `path_matches(requested_path, allowed_pattern)` — an OpenFGA condition using `requested_path.matches(allowed_pattern)`, i.e. grants are scoped to a path pattern rather than an exact path.

When extending the model, remember relations/conditions are data (the DSL file), while the Go-side `Permission` catalog in `permissions.go` is what maps that data model into type-safe values the rest of the code is allowed to use.
