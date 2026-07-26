// Package authn resolves the identity of the caller making a request. It is
// deliberately separate from pkg/authz: authn answers "who is this", authz
// answers "what may they do".
package authn

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"fga-lib/pkg/authz"
)

// Authenticator resolves the authz.Subject for an inbound request.
type Authenticator interface {
	Authenticate(r *http.Request) (authz.Subject, error)
}

// debugUIDHeader carries the caller's uid for the Stub Authenticator. It has
// no place past development: the real transport derives Subject from
// SO_PEERCRED, which this stub exists only to stand in for until that
// transport lands.
const debugUIDHeader = "X-Debug-Uid"

// Stub is a placeholder Authenticator that trusts a client-supplied header
// instead of verifying SO_PEERCRED. It must not be used outside development
// and tests.
type Stub struct{}

func (Stub) Authenticate(r *http.Request) (authz.Subject, error) {
	v := r.Header.Get(debugUIDHeader)
	if v == "" {
		return authz.Subject{}, fmt.Errorf("authn: missing %s header", debugUIDHeader)
	}

	uid, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return authz.Subject{}, fmt.Errorf("authn: invalid %s header: %w", debugUIDHeader, err)
	}

	return authz.Subject{UID: uint32(uid)}, nil
}

// subjectKey is unexported so only this package can set the Subject that
// SubjectFrom reads back; a request handler cannot forge one.
type subjectKey struct{}

// WithSubject attaches sub to ctx, e.g. from http.Server.ConnContext once
// SO_PEERCRED is verified for the connection.
func WithSubject(ctx context.Context, sub authz.Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, sub)
}

// SubjectFrom reads back the Subject WithSubject attached, if any.
func SubjectFrom(ctx context.Context) (authz.Subject, bool) {
	sub, ok := ctx.Value(subjectKey{}).(authz.Subject)
	return sub, ok
}
