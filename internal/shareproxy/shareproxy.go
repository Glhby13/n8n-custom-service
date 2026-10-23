package shareproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configures the ShareProxy handler.
type Options struct {
	N8NBaseURL string
	CookieName string
	DBURL      string
	Timeout    time.Duration
	Log        *slog.Logger
}

// Handler intercepts PUT /rest/workflows/{workflowId}/share to enable native workflow sharing
// in n8n Community without license errors.
type Handler struct {
	n8nBaseURL string
	cookieName string
	pool       *pgxpool.Pool
	client     *http.Client
	log        *slog.Logger
}

// New creates a new ShareProxy Handler.
func New(ctx context.Context, opts Options) (*Handler, error) {
	if opts.CookieName == "" {
		opts.CookieName = "n8n-auth"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	cfg, err := pgxpool.ParseConfig(opts.DBURL)
	if err != nil {
		return nil, fmt.Errorf("parse share proxy db url: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MinConns = 1

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect share proxy db: %w", err)
	}

	return &Handler{
		n8nBaseURL: strings.TrimRight(opts.N8NBaseURL, "/"),
		cookieName: opts.CookieName,
		pool:       pool,
		client:     &http.Client{Timeout: opts.Timeout},
		log:        opts.Log.With("component", "share-proxy"),
	}, nil
}

// Close closes the database pool.
func (h *Handler) Close() {
	if h != nil && h.pool != nil {
		h.pool.Close()
	}
}

type sharePayload struct {
	ShareWithIds []string `json:"shareWithIds"`
}

type userInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// ServeHTTP handles PUT /rest/workflows/{workflowId}/share and GET /rest/settings.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.TrimRight(r.URL.Path, "/") == "/rest/settings" {
		h.handleSettings(w, r)
		return
	}

	if r.Method != http.MethodPut {
		http.Error(w, `{"status":"error","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	workflowID := r.PathValue("workflowId")
	if workflowID == "" {
		// Fallback for paths like /rest/workflows/123/share
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "rest" && parts[1] == "workflows" && parts[len(parts)-1] == "share" {
			workflowID = parts[2]
		}
	}
	if workflowID == "" {
		http.Error(w, `{"status":"error","message":"missing workflowId"}`, http.StatusBadRequest)
		return
	}

	// 1. Authenticate calling user against n8n /rest/login
	user, err := h.authenticate(r)
	if err != nil {
		h.log.Warn("share request unauthenticated", "workflowId", workflowID, "err", err)
		http.Error(w, `{"status":"error","message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// 2. Parse payload
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, `{"status":"error","message":"failed to read body"}`, http.StatusBadRequest)
		return
	}
	var payload sharePayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, `{"status":"error","message":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	// 3. Verify workflow ownership / permission in n8n_db
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	const checkOwnerQuery = `
		SELECT sw."projectId"
		FROM shared_workflow sw
		JOIN project_relation pr ON sw."projectId" = pr."projectId"
		WHERE sw."workflowId" = $1 AND pr."userId" = $2 AND sw.role IN ('workflow:owner', 'workflow:editor');
	`
	var ownerPID string
	err = h.pool.QueryRow(ctx, checkOwnerQuery, workflowID, user.ID).Scan(&ownerPID)
	if err != nil {
		h.log.Warn("user lacks permission to share workflow", "workflowId", workflowID, "userId", user.ID, "err", err)
		http.Error(w, `{"status":"error","message":"Forbidden"}`, http.StatusForbidden)
		return
	}

	// 4. Update shared_workflow table transactionally
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		h.log.Error("begin tx failed", "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Fetch current editor project IDs (not owner)
	const currentQuery = `
		SELECT "projectId"
		FROM shared_workflow
		WHERE "workflowId" = $1 AND role = 'workflow:editor';
	`
	rows, err := tx.Query(ctx, currentQuery, workflowID)
	if err != nil {
		h.log.Error("query current shares failed", "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}
	var currentEditors []string
	for rows.Next() {
		var pid string
		if err := rows.Scan(&pid); err == nil {
			currentEditors = append(currentEditors, pid)
		}
	}
	rows.Close()

	// New desired editors
	newEditorsMap := make(map[string]bool)
	for _, id := range payload.ShareWithIds {
		id = strings.TrimSpace(id)
		if id != "" && id != ownerPID {
			newEditorsMap[id] = true
		}
	}

	// Delete unshared
	var toDelete []string
	for _, cur := range currentEditors {
		if !newEditorsMap[cur] {
			toDelete = append(toDelete, cur)
		}
	}
	if len(toDelete) > 0 {
		const delQuery = `
			DELETE FROM shared_workflow
			WHERE "workflowId" = $1 AND role = 'workflow:editor' AND "projectId" = ANY($2);
		`
		if _, err := tx.Exec(ctx, delQuery, workflowID, toDelete); err != nil {
			h.log.Error("delete shares failed", "err", err)
			http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
			return
		}
	}

	// Insert new shares
	for newPID := range newEditorsMap {
		const insQuery = `
			INSERT INTO shared_workflow ("workflowId", "projectId", role, "createdAt", "updatedAt")
			VALUES ($1, $2, 'workflow:editor', NOW(), NOW())
			ON CONFLICT ("workflowId", "projectId") DO NOTHING;
		`
		if _, err := tx.Exec(ctx, insQuery, workflowID, newPID); err != nil {
			h.log.Error("insert share failed", "projectId", newPID, "err", err)
			http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		h.log.Error("commit shares failed", "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}

	h.log.Info("workflow sharing updated successfully",
		"workflowId", workflowID, "user", user.Email, "sharedWith", payload.ShareWithIds)

	// 5. Respond with expected n8n response: {"data": null}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"data":null}`))
}

func (h *Handler) authenticate(r *http.Request) (*userInfo, error) {
	c, err := r.Cookie(h.cookieName)
	if err != nil || c.Value == "" {
		return nil, fmt.Errorf("missing %s cookie", h.cookieName)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.n8nBaseURL+"/rest/login", nil)
	if err != nil {
		return nil, err
	}
	req.AddCookie(c)
	if bid := r.Header.Get("browser-id"); bid != "" {
		req.Header.Set("browser-id", bid)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call n8n login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("n8n login returned status %d", resp.StatusCode)
	}

	var res struct {
		Data struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode n8n login: %w", err)
	}
	if res.Data.ID == "" {
		return nil, fmt.Errorf("empty user id in n8n login response")
	}

	return &userInfo{ID: res.Data.ID, Email: res.Data.Email}, nil
}

// handleSettings proxies GET /rest/settings and injects enterprise.sharing = true.
func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"status":"error","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	targetURL := h.n8nBaseURL + "/rest/settings"
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
		h.log.Error("create settings request failed", "err", err)
		http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	for k, vv := range r.Header {
		if strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.log.Error("fetch settings from n8n failed", "err", err)
		http.Error(w, `{"status":"error","message":"Bad gateway"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		h.log.Error("read settings body failed", "err", err)
		http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(bodyBytes)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(bodyBytes, &payload); err == nil {
		if data, ok := payload["data"].(map[string]any); ok {
			var ent map[string]any
			if e, ok := data["enterprise"].(map[string]any); ok {
				ent = e
			} else {
				ent = make(map[string]any)
				data["enterprise"] = ent
			}
			ent["sharing"] = true
			ent["oidc"] = true

			var sso map[string]any
			if s, ok := data["sso"].(map[string]any); ok {
				sso = s
			} else {
				sso = make(map[string]any)
				data["sso"] = sso
			}
			sso["oidc"] = map[string]any{
				"loginEnabled": true,
				"loginUrl":     "/sso/login",
			}

			var userMgmt map[string]any
			if u, ok := data["userManagement"].(map[string]any); ok {
				userMgmt = u
			} else {
				userMgmt = make(map[string]any)
				data["userManagement"] = userMgmt
			}
			userMgmt["authenticationMethod"] = "oidc"
		}
		if modified, err := json.Marshal(payload); err == nil {
			bodyBytes = modified
		}
	}

	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "ETag") || strings.EqualFold(k, "Content-Encoding") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bodyBytes)
}
