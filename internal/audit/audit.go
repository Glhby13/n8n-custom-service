// Package audit writes one structured log record per business operation.
// Records never contain workflow content, tokens or credentials.
package audit

import (
	"context"
	"log/slog"
	"time"
)

// Event describes one publish / rollback / read operation.
type Event struct {
	Operation  string
	Trigger    string // api | poller
	WorkflowID string
	N8NUser    string
	Repository string
	CommitSHA  string
	Changed    *bool
	Result     string // success | unchanged | skipped | error
	Reason     string
	Duration   time.Duration
}

// Logger emits audit events on the service logger with audit=true.
type Logger struct{ log *slog.Logger }

// New returns an audit logger.
func New(log *slog.Logger) *Logger { return &Logger{log: log} }

// Record logs the event at info (or warn for errors/skips).
func (l *Logger) Record(ctx context.Context, e Event) {
	attrs := []any{
		slog.Bool("audit", true),
		slog.String("operation", e.Operation),
		slog.String("result", e.Result),
		slog.String("workflow_id", e.WorkflowID),
		slog.Int64("latency_ms", e.Duration.Milliseconds()),
	}
	// request_id is added by the logger handler from ctx (httpx.NewLogger).
	for _, kv := range [][2]string{
		{"trigger", e.Trigger}, {"n8n_user", e.N8NUser}, {"repository", e.Repository},
		{"commit_sha", e.CommitSHA}, {"reason", e.Reason},
	} {
		if kv[1] != "" {
			attrs = append(attrs, slog.String(kv[0], kv[1]))
		}
	}
	if e.Changed != nil {
		attrs = append(attrs, slog.Bool("changed", *e.Changed))
	}
	level := slog.LevelInfo
	if e.Result == "error" || e.Result == "skipped" {
		level = slog.LevelWarn
	}
	l.log.Log(ctx, level, "audit", attrs...)
}
