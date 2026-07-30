// Command proxyd is the authorizing proxy in front of the Podman socket.
//
// This file is wiring only: read configuration, construct dependencies,
// serve. It is the single place that knows the FGA adapter exists — every
// other package depends on the authz interfaces, which is what makes the
// read path testable without a server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"podmanproxy/internal/audit"
	"podmanproxy/internal/fga"
	"podmanproxy/internal/identity"
	"podmanproxy/internal/proxy"
)

// version is set at build time: -ldflags "-X main.version=$(git rev-parse HEAD)".
// It ties every audit record to a commit, and with the embedded model, to a
// reviewed policy version.
var version = "dev"

type config struct {
	listenSocket string
	podmanSocket string
	fgaURL       string
	fgaStore     string
	auditPath    string
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	auditFile, err := openAuditSink(cfg.auditPath)
	if err != nil {
		return err
	}
	defer auditFile.Close()
	auditLog := audit.New(auditFile)

	// Provisions the embedded model and pins its id; fails startup on any
	// drift between the catalog, the fact shapes and the deployed model.
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	authorizer, err := fga.New(initCtx, cfg.fgaURL, cfg.fgaStore)
	if err != nil {
		return fmt.Errorf("authorization backend: %w", err)
	}
	auditLog.Startup(ctx, authorizer.ModelID(), version)

	srv := &http.Server{
		Handler: proxy.New(
			proxy.Config{PodmanSocket: cfg.podmanSocket},
			authorizer, // authz.Authorizer
			authorizer, // authz.TupleWriter
			auditLog,
		),
		ConnContext:       identity.ConnContext,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := listen(cfg.listenSocket)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info("listening", "socket", cfg.listenSocket, "model_id", authorizer.ModelID(), "build", version)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.listenSocket, "listen", "/run/podman-proxy.sock", "path of the socket to serve")
	flag.StringVar(&cfg.podmanSocket, "podman", "/run/podman/podman.sock", "path of the podman API socket")
	flag.StringVar(&cfg.fgaURL, "fga-url", envOr("FGA_API_URL", "http://localhost:8080"), "OpenFGA API URL")
	flag.StringVar(&cfg.fgaStore, "fga-store", os.Getenv("FGA_STORE_ID"), "OpenFGA store id")
	flag.StringVar(&cfg.auditPath, "audit-log", os.Getenv("AUDIT_LOG"), "audit log path (default stderr)")
	flag.Parse()
	return cfg
}

// listen binds the proxy socket. Mode 0660 with a dedicated group is the
// access boundary: membership decides who may reach the proxy at all, while
// OpenFGA decides what they may do once connected.
func listen(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}

// openAuditSink opens the audit destination append-only. Falling back to
// stderr is deliberate: never start without an audit trail, but never fail
// to start because a path is misconfigured — the startup log records which.
func openAuditSink(path string) (*os.File, error) {
	if path == "" {
		return os.Stderr, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return f, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
