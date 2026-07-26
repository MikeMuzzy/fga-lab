package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"

	"fga-lib/pkg/authn"
	"fga-lib/pkg/authz"
	"fga-lib/pkg/proxyhttp"
)

// connContext runs once per accepted connection. Peer credentials are a
// property of the socket, so every request multiplexed on the connection
// inherits the subject for free.
func connContext(ctx context.Context, c net.Conn) context.Context {
	//uc, ok := c.(*net.UnixConn)
	//if !ok {
	//	return ctx
	//}
	//raw, err := uc.SyscallConn()
	//if err != nil {
	//	return ctx
	//}
	//var cred *unix.Ucred
	//var serr error
	//if err := raw.Control(func(fd uintptr) {
	//	cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	//}); err != nil || serr != nil || cred == nil {
	//	return ctx // no subject in ctx -> middleware returns 401
	//}
	// stub for the moment
	return authn.WithSubject(ctx, authz.Subject{UID: 1001, GID: 1001})
}

func main() {
	fga, err := authz.NewFGA()
	if err != nil {
		log.Fatal(err)
	}

	addr := os.Getenv("API_PROXY_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	srv := &http.Server{
		Addr: addr,
		Handler: proxyhttp.BuildMux(fga, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})),
		ConnContext: connContext,
	}

	log.Printf("api-proxy listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
