package service

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/httpx"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/workflow"
)

// HandlerOptions configures the HTTP API.
type HandlerOptions struct {
	Service      *Service
	Poller       *Poller // optional, reported on /readyz
	Log          *slog.Logger
	APIToken     string
	MaxBodyBytes int64
	RateLimitRPS float64
	Metrics      http.Handler
	// History serves /rest/workflow-history/* (n8n session auth, see internal/historyproxy).
	History http.Handler
	// ShareProxy intercepts PUT /rest/workflows/{workflowId}/share to enable native sharing.
	ShareProxy http.Handler
	StartedAt  time.Time
}

// NewHandler builds the router: probes and metrics without auth, /api/v1/* with bearer auth.
func NewHandler(o HandlerOptions) http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("POST /api/v1/workflows/{workflowId}/publish", o.publish)
	api.HandleFunc("GET /api/v1/workflows/{workflowId}/versions", o.versions)
	api.HandleFunc("GET /api/v1/workflows/{workflowId}/versions/{commitSha}", o.getVersion)
	api.HandleFunc("POST /api/v1/workflows/{workflowId}/rollback", o.rollback)
	api.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "unknown endpoint")
	})
	protected := httpx.Chain(api, httpx.BearerAuth(o.APIToken), httpx.RateLimit(o.RateLimitRPS), httpx.LimitBody(o.MaxBodyBytes))

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.HandleFunc("GET /readyz", o.readyz)
	if o.Metrics != nil {
		root.Handle("GET /metrics", o.Metrics)
	}
	root.Handle("/api/v1/", protected)
	if o.History != nil {
		root.Handle("/rest/workflow-history/", o.History)
	}
	if o.ShareProxy != nil {
		root.Handle("PUT /rest/workflows/{workflowId}/share", o.ShareProxy)
		root.Handle("PUT /rest/workflows/{workflowId}/share/", o.ShareProxy)
		root.Handle("GET /rest/settings", o.ShareProxy)
		root.Handle("GET /rest/settings/", o.ShareProxy)
	}
	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "unknown endpoint")
	})
	return httpx.Chain(root, httpx.RequestID, httpx.Recover(o.Log), httpx.AccessLog(o.Log))
}

// readyz: configuration was validated at startup, so the process is ready. Dependency state
// (last poll) is reported for information only and never fails the probe, so a GitLab or n8n
// outage does not take the pod out of the Service or cause restart loops.
func (o HandlerOptions) readyz(w http.ResponseWriter, _ *http.Request) {
	body := map[string]any{"status": "ready", "startedAt": o.StartedAt.UTC()}
	if o.Poller != nil {
		body["dependencies"] = map[string]any{"poller": o.Poller.Status()}
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

func (o HandlerOptions) fail(w http.ResponseWriter, r *http.Request, err error) {
	var se *Error
	if errors.As(err, &se) {
		msg := se.Msg
		if se.Kind == KindInvalidData && se.Err != nil {
			msg += ": " + se.Err.Error()
		}
		if se.Kind == KindUpstream {
			o.Log.WarnContext(r.Context(), "upstream error", "error", err)
		}
		httpx.WriteError(w, r, se.Status(), string(se.Kind), msg)
		return
	}
	o.Log.ErrorContext(r.Context(), "unexpected error", "error", err)
	httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal error")
}

func (o HandlerOptions) validID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("workflowId")
	if !workflow.ValidID(id) {
		httpx.WriteError(w, r, http.StatusBadRequest, string(KindInvalid), "workflowId must match ^[A-Za-z0-9_-]{1,64}$")
		return "", false
	}
	return id, true
}

func (o HandlerOptions) publish(w http.ResponseWriter, r *http.Request) {
	id, ok := o.validID(w, r)
	if !ok {
		return
	}
	res, err := o.Service.Publish(r.Context(), id, "api")
	if err != nil {
		o.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (o HandlerOptions) versions(w http.ResponseWriter, r *http.Request) {
	id, ok := o.validID(w, r)
	if !ok {
		return
	}
	res, err := o.Service.Versions(r.Context(), id)
	if err != nil {
		o.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (o HandlerOptions) getVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := o.validID(w, r)
	if !ok {
		return
	}
	sha := r.PathValue("commitSha")
	if !workflow.ValidSHA(sha) {
		httpx.WriteError(w, r, http.StatusBadRequest, string(KindInvalid), "commitSha must be exactly 40 hexadecimal characters")
		return
	}
	content, err := o.Service.GetVersion(r.Context(), id, sha)
	if err != nil {
		o.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content) //nolint:gosec // G705: stored workflow JSON served as application/json with nosniff, never as HTML
}

type rollbackRequest struct {
	CommitSHA                string `json:"commitSha"`
	ExpectedPublishedVersion string `json:"expectedPublishedVersion"`
}

func (o HandlerOptions) rollback(w http.ResponseWriter, r *http.Request) {
	id, ok := o.validID(w, r)
	if !ok {
		return
	}
	var req rollbackRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, string(KindInvalid), err.Error())
		return
	}
	res, err := o.Service.Rollback(r.Context(), id, req.CommitSHA, req.ExpectedPublishedVersion)
	if err != nil {
		o.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
