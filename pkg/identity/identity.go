// Package identity derives the authenticated subject from Unix socket peer
// credentials. It is the proxy's only authentication mechanism: the kernel
// vouches for the uid, so there is nothing to forge.
package identity

import (
	"context"
	"net"

	"golang.org/x/sys/unix"

	"podmanproxy/internal/authz"
)

type ctxKey struct{}

// ConnContext is installed as http.Server.ConnContext. Peer credentials are
// a property of the socket, so extracting them once per connection covers
// every request multiplexed over it — podman clients reuse connections.
//
// On failure it returns ctx unchanged: no subject means the authenticate
// middleware rejects with 401, so failure is closed by construction.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return ctx
	}
	return WithSubject(ctx, authz.Subject{UID: cred.Uid, GID: cred.Gid})
}

// WithSubject attaches a subject; exported for tests and alternative
// front ends.
func WithSubject(ctx context.Context, s authz.Subject) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// FromContext reports the authenticated subject, if any.
func FromContext(ctx context.Context) (authz.Subject, bool) {
	s, ok := ctx.Value(ctxKey{}).(authz.Subject)
	return s, ok
}
