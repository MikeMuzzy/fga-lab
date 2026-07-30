// Package audit owns the audit event schema and its transport. The schema is
// versioned and centralized here because downstream SIEM rules and retention
// policies depend on its stability: a field rename is a breaking change.
package audit

import (
	"context"
	"io"
	"log/slog"
	"time"

	"podmanproxy/internal/authz"
)

// SchemaVersion is emitted on every event. Bump on any incompatible field
// change so downstream consumers can branch.
const SchemaVersion = "1"

// Event names. Decisions and entitlement changes are both recorded:
// knowing who could do what matters as much as who did what.
const (
	EventDecision = "authz.decision"
	EventGrant    = "authz.grant"
	EventRevoke   = "authz.revoke"
)

// Logger writes the audit stream. It is deliberately separate from the
// application logger: different destination, different retention, and
// append-only shipping to the SIEM.
type Logger struct{ log *slog.Logger }

// New builds an audit logger over w. Callers pass a file opened O_APPEND
// (shipped to WORM storage) rather than stdout, so application noise cannot
// interleave with the evidentiary record.
func New(w io.Writer) *Logger {
	return &Logger{log: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(slog.String("schema", SchemaVersion))}
}

// Decision records one authorization outcome — allow and deny alike. Denies
// alone cannot prove a control worked; allows are what incident
// reconstruction and access recertification need.
func (l *Logger) Decision(ctx context.Context, requestID, method, path string, d authz.Decision, elapsed time.Duration) {
	l.log.LogAttrs(ctx, slog.LevelInfo, EventDecision,
		slog.String("request_id", requestID),
		slog.String("method", method),
		slog.String("path", path),
		slog.Any("decision", d),
		slog.Duration("eval", elapsed),
	)
}

// Grant records a relationship tuple write.
func (l *Logger) Grant(ctx context.Context, requestID, subject, relation, object string) {
	l.log.LogAttrs(ctx, slog.LevelInfo, EventGrant,
		slog.String("request_id", requestID),
		slog.String("subject", subject),
		slog.String("relation", relation),
		slog.String("object", object),
	)
}

// Revoke records a relationship tuple deletion.
func (l *Logger) Revoke(ctx context.Context, requestID, object string) {
	l.log.LogAttrs(ctx, slog.LevelInfo, EventRevoke,
		slog.String("request_id", requestID),
		slog.String("object", object),
	)
}

// Startup records the policy version the process is running, tying every
// subsequent decision to a specific model.
func (l *Logger) Startup(ctx context.Context, modelID, version string) {
	l.log.LogAttrs(ctx, slog.LevelInfo, "proxy.startup",
		slog.String("model_id", modelID),
		slog.String("build", version),
	)
}
