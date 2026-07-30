package podman

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"podmanproxy/internal/authz"
)

// guardTransport is the fail-closed invariant: nothing reaches the podman
// socket without a positive decision in context. It is not a second policy
// evaluation — it catches the "new route forgot the authorize middleware"
// bug class structurally.
type guardTransport struct{ next http.RoundTripper }

func (t guardTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if d, ok := authz.DecisionFrom(r.Context()); !ok || !d.Allowed {
		return nil, authz.ErrNoDecision
	}
	return t.next.RoundTrip(r)
}

// NewReverseProxy dials the podman socket through the guarded transport.
// modifyResponse is supplied by the proxy package, which owns the response
// hooks (list filtering, ownership recording).
func NewReverseProxy(socket string, modifyResponse func(*http.Response) error) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: "podman"})
	rp.Transport = guardTransport{next: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
	rp.ModifyResponse = modifyResponse
	return rp
}
