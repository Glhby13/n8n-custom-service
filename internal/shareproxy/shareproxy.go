package shareproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
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

// Handler intercepts PUT /rest/workflows/{workflowId}/share and PUT /rest/credentials/{credentialId}/share
// to enable native workflow and credential sharing in n8n Community without license errors.
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

// ProjectRef represents a reference to a project in credential metadata.
type ProjectRef struct {
	ID   string  `json:"id"`
	Name string  `json:"name"`
	Type string  `json:"type"`
	Icon *string `json:"icon"`
}

// ServeHTTP handles PUT /rest/workflows/{workflowId}/share, PUT /rest/credentials/{credentialId}/share,
// GET /rest/credentials/{credentialId}, GET /rest/credentials, and GET /rest/settings.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.cookieName == "" {
		h.cookieName = "n8n-auth"
	}

	if strings.TrimRight(r.URL.Path, "/") == "/rest/settings" {
		h.handleSettings(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/assets/") {
		h.handleAssetProxy(w, r)
		return
	}

	if r.PathValue("workflowId") != "" || isWorkflowSharePath(r.URL.Path) {
		if r.Method != http.MethodPut {
			http.Error(w, `{"status":"error","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		wfID := extractWorkflowPathID(r)
		if wfID == "" {
			http.Error(w, `{"status":"error","message":"missing workflowId"}`, http.StatusBadRequest)
			return
		}
		h.handleWorkflowShare(w, r, wfID)
		return
	}

	if isCredentialRelatedPath(r.URL.Path) {
		if isCredentialSharePath(r.URL.Path) {
			if r.Method != http.MethodPut {
				http.Error(w, `{"status":"error","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			credID := extractCredentialPathID(r)
			if credID == "" {
				http.Error(w, `{"status":"error","message":"missing credentialId"}`, http.StatusBadRequest)
				return
			}
			h.handleCredentialShare(w, r, credID)
			return
		}

		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 2 {
			if r.Method == http.MethodGet {
				h.handleGetCredentials(w, r)
				return
			}
			h.handleTransparentProxy(w, r)
			return
		}

		if len(parts) >= 3 {
			sub := parts[2]
			if isSpecialCredentialSubpath(sub) {
				h.handleTransparentProxy(w, r)
				return
			}
			if r.Method == http.MethodGet {
				h.handleGetCredential(w, r, sub)
				return
			}
			h.handleTransparentProxy(w, r)
			return
		}

		h.handleTransparentProxy(w, r)
		return
	}

	http.Error(w, `{"status":"error","message":"not found"}`, http.StatusNotFound)
}

func (h *Handler) handleWorkflowShare(w http.ResponseWriter, r *http.Request, workflowID string) {
	// 1. Authenticate calling user against n8n /rest/login
	user, err := h.authenticate(r)
	if err != nil {
		h.log.Warn("workflow share request unauthenticated", "workflowId", workflowID, "err", err)
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
		h.log.Error("query current workflow shares failed", "err", err)
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

	toAdd, toDelete := diffShares(currentEditors, payload.ShareWithIds, ownerPID)

	// Delete unshared
	if len(toDelete) > 0 {
		const delQuery = `
			DELETE FROM shared_workflow
			WHERE "workflowId" = $1 AND role = 'workflow:editor' AND "projectId" = ANY($2);
		`
		if _, err := tx.Exec(ctx, delQuery, workflowID, toDelete); err != nil {
			h.log.Error("delete workflow shares failed", "err", err)
			http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
			return
		}
	}

	// Insert new shares
	for _, newPID := range toAdd {
		const insQuery = `
			INSERT INTO shared_workflow ("workflowId", "projectId", role, "createdAt", "updatedAt")
			VALUES ($1, $2, 'workflow:editor', NOW(), NOW())
			ON CONFLICT ("workflowId", "projectId") DO NOTHING;
		`
		if _, err := tx.Exec(ctx, insQuery, workflowID, newPID); err != nil {
			h.log.Error("insert workflow share failed", "projectId", newPID, "err", err)
			http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
			return
		}
	}

	// 5. Auto-share credentials referenced by the workflow nodes
	var nodesBytes []byte
	const getNodesQuery = `SELECT nodes FROM workflow_entity WHERE id = $1;`
	if err := tx.QueryRow(ctx, getNodesQuery, workflowID).Scan(&nodesBytes); err != nil {
		h.log.Warn("fetch workflow nodes failed or workflow not found", "workflowId", workflowID, "err", err)
	} else {
		credIDs := extractCredentialIDs(nodesBytes)
		for _, credID := range credIDs {
			// Verify if caller has permission to share this credential (owner or user)
			const checkPermissionQuery = `
				SELECT 1
				FROM shared_credentials sc
				JOIN project_relation pr ON sc."projectId" = pr."projectId"
				WHERE sc."credentialsId" = $1 AND pr."userId" = $2 AND sc.role IN ('credential:owner', 'credential:user')
				LIMIT 1;
			`
			var allowed int
			if err := tx.QueryRow(ctx, checkPermissionQuery, credID, user.ID).Scan(&allowed); err != nil {
				h.log.Info("skipping credential auto-share: user lacks permission", "credentialId", credID, "userId", user.ID)
				continue
			}

			// Upsert credential:user for target projects in ShareWithIds
			for _, targetPID := range payload.ShareWithIds {
				targetPID = strings.TrimSpace(targetPID)
				if targetPID == "" || targetPID == ownerPID {
					continue
				}
				const insCredQuery = `
					INSERT INTO shared_credentials ("credentialsId", "projectId", role, "createdAt", "updatedAt")
					VALUES ($1, $2, 'credential:user', NOW(), NOW())
					ON CONFLICT ("credentialsId", "projectId") DO NOTHING;
				`
				if _, err := tx.Exec(ctx, insCredQuery, credID, targetPID); err != nil {
					h.log.Error("auto-insert credential share failed", "credentialId", credID, "projectId", targetPID, "err", err)
					http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
					return
				}
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		h.log.Error("commit workflow shares failed", "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}

	h.log.Info("workflow sharing updated successfully",
		"workflowId", workflowID, "user", user.Email, "sharedWith", payload.ShareWithIds)

	// 6. Respond with expected n8n response: {"data": null}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"data":null}`))
}

func (h *Handler) handleCredentialShare(w http.ResponseWriter, r *http.Request, credentialID string) {
	// 1. Authenticate calling user against n8n /rest/login
	user, err := h.authenticate(r)
	if err != nil {
		h.log.Warn("credential share request unauthenticated", "credentialId", credentialID, "err", err)
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

	// 3. Verify credential ownership in n8n_db (user must be owner)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	const checkOwnerQuery = `
		SELECT sc."projectId"
		FROM shared_credentials sc
		JOIN project_relation pr ON sc."projectId" = pr."projectId"
		WHERE sc."credentialsId" = $1 AND pr."userId" = $2 AND sc.role = 'credential:owner';
	`
	var ownerPID string
	err = h.pool.QueryRow(ctx, checkOwnerQuery, credentialID, user.ID).Scan(&ownerPID)
	if err != nil {
		h.log.Warn("user lacks permission to share credential", "credentialId", credentialID, "userId", user.ID, "err", err)
		http.Error(w, `{"status":"error","message":"Forbidden"}`, http.StatusForbidden)
		return
	}

	// 4. Update shared_credentials table transactionally
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		h.log.Error("begin tx failed", "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Fetch current user shares (role = 'credential:user')
	const currentQuery = `
		SELECT "projectId"
		FROM shared_credentials
		WHERE "credentialsId" = $1 AND role = 'credential:user';
	`
	rows, err := tx.Query(ctx, currentQuery, credentialID)
	if err != nil {
		h.log.Error("query current credential shares failed", "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}
	var currentUsers []string
	for rows.Next() {
		var pid string
		if err := rows.Scan(&pid); err == nil {
			currentUsers = append(currentUsers, pid)
		}
	}
	rows.Close()

	toAdd, toDelete := diffShares(currentUsers, payload.ShareWithIds, ownerPID)

	// Delete unshared (only role = 'credential:user')
	if len(toDelete) > 0 {
		const delQuery = `
			DELETE FROM shared_credentials
			WHERE "credentialsId" = $1 AND role = 'credential:user' AND "projectId" = ANY($2);
		`
		if _, err := tx.Exec(ctx, delQuery, credentialID, toDelete); err != nil {
			h.log.Error("delete credential shares failed", "err", err)
			http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
			return
		}
	}

	// Insert new shares (credential:user)
	for _, newPID := range toAdd {
		const insQuery = `
			INSERT INTO shared_credentials ("credentialsId", "projectId", role, "createdAt", "updatedAt")
			VALUES ($1, $2, 'credential:user', NOW(), NOW())
			ON CONFLICT ("credentialsId", "projectId") DO NOTHING;
		`
		if _, err := tx.Exec(ctx, insQuery, credentialID, newPID); err != nil {
			h.log.Error("insert credential share failed", "projectId", newPID, "err", err)
			http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		h.log.Error("commit credential shares failed", "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}

	h.log.Info("credential sharing updated successfully",
		"credentialId", credentialID, "user", user.Email, "sharedWith", payload.ShareWithIds)

	// 5. Respond with expected n8n response: {"data": null}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"data":null}`))
}

// diffShares computes which project IDs need to be added and which need to be removed.
// ownerPID is excluded from both toAdd and toDelete to ensure owner records are never touched.
func diffShares(current []string, desired []string, ownerPID string) (toAdd []string, toDelete []string) {
	ownerPID = strings.TrimSpace(ownerPID)
	desiredMap := make(map[string]bool)
	for _, id := range desired {
		id = strings.TrimSpace(id)
		if id != "" && id != ownerPID {
			desiredMap[id] = true
		}
	}

	currentMap := make(map[string]bool)
	for _, id := range current {
		id = strings.TrimSpace(id)
		if id != "" {
			currentMap[id] = true
		}
	}

	for _, cur := range current {
		cur = strings.TrimSpace(cur)
		if cur != "" && cur != ownerPID && !desiredMap[cur] {
			toDelete = append(toDelete, cur)
		}
	}

	for des := range desiredMap {
		if !currentMap[des] {
			toAdd = append(toAdd, des)
		}
	}

	sort.Strings(toAdd)
	sort.Strings(toDelete)
	return toAdd, toDelete
}

// extractCredentialIDs parses workflow nodes JSON and extracts all credential IDs.
func extractCredentialIDs(data []byte) []string {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	// Handle stringified JSON (e.g. if stored as a JSON-encoded string)
	if len(data) > 0 && data[0] == '"' {
		var unquoted string
		if err := json.Unmarshal(data, &unquoted); err == nil {
			data = bytes.TrimSpace([]byte(unquoted))
		}
	}

	type nodeStruct struct {
		Credentials map[string]struct {
			ID any `json:"id"`
		} `json:"credentials"`
	}

	var nodes []nodeStruct
	if err := json.Unmarshal(data, &nodes); err != nil {
		var wrapper struct {
			Nodes []nodeStruct `json:"nodes"`
		}
		if err2 := json.Unmarshal(data, &wrapper); err2 == nil {
			nodes = wrapper.Nodes
		} else {
			return nil
		}
	}

	seen := make(map[string]bool)
	var credIDs []string

	for _, node := range nodes {
		for _, cred := range node.Credentials {
			if cred.ID == nil {
				continue
			}
			var idStr string
			switch v := cred.ID.(type) {
			case string:
				idStr = strings.TrimSpace(v)
			case float64:
				idStr = fmt.Sprintf("%.0f", v)
			default:
				idStr = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			if idStr != "" && idStr != "<nil>" && !seen[idStr] {
				seen[idStr] = true
				credIDs = append(credIDs, idStr)
			}
		}
	}
	sort.Strings(credIDs)
	return credIDs
}

func isCredentialRelatedPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) >= 2 && parts[0] == "rest" && parts[1] == "credentials"
}

func isSpecialCredentialSubpath(segment string) bool {
	switch segment {
	case "for-workflow", "test", "schema":
		return true
	default:
		return false
	}
}

func isCredentialSharePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) >= 3 && parts[0] == "rest" && parts[1] == "credentials" && parts[len(parts)-1] == "share"
}

func isWorkflowSharePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) >= 3 && parts[0] == "rest" && parts[1] == "workflows" && parts[len(parts)-1] == "share"
}

func extractCredentialPathID(r *http.Request) string {
	if id := r.PathValue("credentialId"); id != "" {
		return id
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "rest" && parts[1] == "credentials" {
		return parts[2]
	}
	return ""
}

func extractWorkflowPathID(r *http.Request) string {
	if id := r.PathValue("workflowId"); id != "" {
		return id
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "rest" && parts[1] == "workflows" && parts[len(parts)-1] == "share" {
		return parts[2]
	}
	return ""
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

// handleAssetProxy proxies static assets from n8n and customizes the SSO button label to "Sign in with AD BTN".
func (h *Handler) handleAssetProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"status":"error","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	targetURL := h.n8nBaseURL + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
		h.log.Error("create asset proxy request failed", "err", err)
		http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	for k, vv := range r.Header {
		if strings.EqualFold(k, "Accept-Encoding") || strings.EqualFold(k, "If-None-Match") || strings.EqualFold(k, "If-Modified-Since") {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.log.Error("fetch asset from n8n failed", "err", err)
		http.Error(w, `{"status":"error","message":"Bad gateway"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		h.log.Error("read asset body failed", "err", err)
		http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	if resp.StatusCode == http.StatusOK {
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte("label:a(o).baseText(`sso.login.button`)"), []byte(`label:"Sign in with AD BTN"`))
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`label:a(o).baseText("sso.login.button")`), []byte(`label:"Sign in with AD BTN"`))
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"Continue with SSO"`), []byte(`"Sign in with AD BTN"`))
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`'Continue with SSO'`), []byte(`'Sign in with AD BTN'`))
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"sso.login.button":"Continue with SSO"`), []byte(`"sso.login.button":"Sign in with AD BTN"`))
		if strings.HasPrefix(r.URL.Path, "/assets/SigninView-") && strings.HasSuffix(r.URL.Path, ".js") {
			patched, ok := patchSigninView(bodyBytes)
			if !ok {
				// n8n changed the sign-in view: keep its own page working rather than break sign-in.
				h.log.Warn("signin view patch did not apply; n8n native sign-in page stays", "path", r.URL.Path)
			}
			bodyBytes = patched
		}
	}

	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "ETag") || strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Cache-Control") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(bodyBytes)
}

// signinSetup finds the start of n8n's sign-in view component (stable across builds: the component name is part of
// n8n's source, only the minified parameter name and the chunk hash change).
var signinSetup = regexp.MustCompile("__name:`SigninView`,setup\\([^)]*\\)\\{")

// signinRedirect is injected at the start of the sign-in view. When n8n's router lands on /signin (client side, so no
// request ever reaches the server) it does one full-page navigation to /signin?ad=1..., which the ingress sends to
// auth-service, which serves the AD BTN / local account sign-in page. The ad=1 marker stops a loop: if the ingress
// route is missing the request comes back to n8n with the marker and the native page simply renders.
const signinRedirect = "if(!/[?&]ad=1(&|$)/.test(location.search)){location.replace(\"/signin?ad=1\"+(location.search?\"&\"+location.search.slice(1):\"\"));return()=>null}"

// patchSigninView returns the sign-in chunk with the redirect injected, and whether it applied.
func patchSigninView(body []byte) ([]byte, bool) {
	loc := signinSetup.FindIndex(body)
	if loc == nil || bytes.Contains(body, []byte(signinRedirect)) {
		return body, bytes.Contains(body, []byte(signinRedirect))
	}
	out := make([]byte, 0, len(body)+len(signinRedirect))
	out = append(out, body[:loc[1]]...)
	out = append(out, signinRedirect...)
	out = append(out, body[loc[1]:]...)
	return out, true
}

// handleTransparentProxy reverse proxies requests under /rest/credentials directly to n8n backend.
func (h *Handler) handleTransparentProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := h.n8nBaseURL + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		h.log.Error("create transparent proxy request failed", "err", err, "path", r.URL.Path)
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
		h.log.Error("transparent proxy request to n8n failed", "err", err, "path", r.URL.Path)
		http.Error(w, `{"status":"error","message":"Bad gateway"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Encoding") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleGetCredential intercepts GET /rest/credentials/{id} to enrich responses for owners
// and safely return metadata (without secrets) for shared users, resolving red popup errors.
func (h *Handler) handleGetCredential(w http.ResponseWriter, r *http.Request, credentialID string) {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		http.Error(w, `{"status":"error","message":"missing credentialId"}`, http.StatusBadRequest)
		return
	}

	user, err := h.authenticate(r)
	if err != nil {
		h.log.Warn("get credential unauthenticated", "credentialId", credentialID, "err", err)
		http.Error(w, `{"status":"error","message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if h.pool == nil {
		h.log.Error("database pool not initialized")
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	type shareRow struct {
		Role        string
		ProjectID   string
		ProjectName string
		ProjectType string
		Icon        *string
	}
	const sharesQuery = `
		SELECT sc.role, p.id, p.name, p.type, p.icon
		FROM shared_credentials sc
		JOIN project p ON sc."projectId" = p.id
		WHERE sc."credentialsId" = $1;
	`
	rows, err := h.pool.Query(ctx, sharesQuery, credentialID)
	if err != nil {
		h.log.Error("query credential shares failed", "credentialId", credentialID, "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var shares []shareRow
	for rows.Next() {
		var s shareRow
		if err := rows.Scan(&s.Role, &s.ProjectID, &s.ProjectName, &s.ProjectType, &s.Icon); err == nil {
			shares = append(shares, s)
		}
	}
	rows.Close()

	const userProjectsQuery = `
		SELECT pr."projectId"
		FROM project_relation pr
		WHERE pr."userId" = $1;
	`
	pRows, err := h.pool.Query(ctx, userProjectsQuery, user.ID)
	if err != nil {
		h.log.Error("query user projects failed", "userId", user.ID, "err", err)
		http.Error(w, `{"status":"error","message":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer pRows.Close()

	userPIDs := make(map[string]bool)
	for pRows.Next() {
		var pid string
		if err := pRows.Scan(&pid); err == nil {
			userPIDs[pid] = true
		}
	}
	pRows.Close()

	var isOwner, isSharee bool
	var homeProject *ProjectRef
	sharedWithProjects := make([]ProjectRef, 0)

	for _, s := range shares {
		pref := ProjectRef{
			ID:   s.ProjectID,
			Name: s.ProjectName,
			Type: s.ProjectType,
			Icon: s.Icon,
		}
		switch s.Role {
		case "credential:owner":
			homeProject = &pref
			if userPIDs[s.ProjectID] {
				isOwner = true
			}
		case "credential:user":
			sharedWithProjects = append(sharedWithProjects, pref)
			if userPIDs[s.ProjectID] {
				isSharee = true
			}
		}
	}

	if !isOwner && !isSharee {
		h.log.Warn("user lacks permission to view credential", "credentialId", credentialID, "userId", user.ID)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		errResp, _ := json.Marshal(map[string]string{
			"message": fmt.Sprintf("Credential with ID %q could not be found.", credentialID),
		})
		_, _ = w.Write(errResp)
		return
	}

	if isOwner {
		targetURL := h.n8nBaseURL + r.URL.RequestURI()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
		if err != nil {
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
			h.log.Error("fetch credential from n8n failed", "credentialId", credentialID, "err", err)
			http.Error(w, `{"status":"error","message":"Bad gateway"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			for k, vv := range resp.Header {
				if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Encoding") {
					continue
				}
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
			return
		}

		var payload map[string]any
		if err := json.Unmarshal(bodyBytes, &payload); err == nil {
			if data, ok := payload["data"].(map[string]any); ok {
				data["homeProject"] = homeProject
				data["sharedWithProjects"] = sharedWithProjects
				if scopes, ok := data["scopes"].([]any); ok {
					hasShare := false
					for _, sc := range scopes {
						if sc == "credential:share" {
							hasShare = true
							break
						}
					}
					if !hasShare {
						data["scopes"] = append(scopes, "credential:share")
					}
				}
				enriched, err := json.Marshal(payload)
				if err == nil {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(enriched)
					return
				}
			}
		}

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bodyBytes)
		return
	}

	// Sharee access (credential:user): NEVER query or return encrypted secrets ("data" column)
	const fetchEntitySQL = `
		SELECT name, type, "createdAt", "updatedAt", COALESCE("isManaged", false), COALESCE("isGlobal", false)
		FROM credentials_entity
		WHERE id = $1;
	`
	var name, credType string
	var createdAt, updatedAt time.Time
	var isManaged, isGlobal bool
	err = h.pool.QueryRow(ctx, fetchEntitySQL, credentialID).Scan(&name, &credType, &createdAt, &updatedAt, &isManaged, &isGlobal)
	if err != nil {
		h.log.Warn("credential not found in entity table", "credentialId", credentialID, "err", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		errResp, _ := json.Marshal(map[string]string{
			"message": fmt.Sprintf("Credential with ID %q could not be found.", credentialID),
		})
		_, _ = w.Write(errResp)
		return
	}

	shareeResp := map[string]any{
		"data": map[string]any{
			"id":                 credentialID,
			"name":               name,
			"type":               credType,
			"createdAt":          createdAt.Format(time.RFC3339Nano),
			"updatedAt":          updatedAt.Format(time.RFC3339Nano),
			"isManaged":          isManaged,
			"isGlobal":           isGlobal,
			"homeProject":        homeProject,
			"sharedWithProjects": sharedWithProjects,
			"scopes":             []string{"credential:read"},
		},
	}

	outBytes, err := json.Marshal(shareeResp)
	if err != nil {
		http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outBytes)
}

// handleGetCredentials intercepts GET /rest/credentials to include credentials shared with the user
// and enrich all credentials with homeProject and sharedWithProjects so collaborator badges render.
func (h *Handler) handleGetCredentials(w http.ResponseWriter, r *http.Request) {
	targetURL := h.n8nBaseURL + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
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
		h.log.Error("fetch credentials list from n8n failed", "err", err)
		http.Error(w, `{"status":"error","message":"Bad gateway"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		for k, vv := range resp.Header {
			if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Encoding") {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bodyBytes)
		return
	}

	user, err := h.authenticate(r)
	if err == nil && user != nil && h.pool != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		const sharedToUserQuery = `
			SELECT c.id, c.name, c.type, c."createdAt", c."updatedAt", COALESCE(c."isManaged", false), COALESCE(c."isGlobal", false)
			FROM credentials_entity c
			JOIN shared_credentials sc ON c.id = sc."credentialsId"
			JOIN project_relation pr ON sc."projectId" = pr."projectId"
			WHERE pr."userId" = $1 AND sc.role = 'credential:user';
		`
		sRows, err := h.pool.Query(ctx, sharedToUserQuery, user.ID)
		if err == nil {
			existingIDs := make(map[string]bool)
			for _, item := range payload.Data {
				if id, ok := item["id"].(string); ok {
					existingIDs[id] = true
				}
			}

			for sRows.Next() {
				var id, name, credType string
				var createdAt, updatedAt time.Time
				var isManaged, isGlobal bool
				if err := sRows.Scan(&id, &name, &credType, &createdAt, &updatedAt, &isManaged, &isGlobal); err == nil {
					if !existingIDs[id] {
						payload.Data = append(payload.Data, map[string]any{
							"id":        id,
							"name":      name,
							"type":      credType,
							"createdAt": createdAt.Format(time.RFC3339Nano),
							"updatedAt": updatedAt.Format(time.RFC3339Nano),
							"isManaged": isManaged,
							"isGlobal":  isGlobal,
							"scopes":    []string{"credential:read"},
						})
						existingIDs[id] = true
					}
				}
			}
			sRows.Close()
		}

		allIDs := make([]string, 0, len(payload.Data))
		for _, item := range payload.Data {
			if id, ok := item["id"].(string); ok && id != "" {
				allIDs = append(allIDs, id)
			}
		}

		if len(allIDs) > 0 {
			const batchSharesQuery = `
				SELECT sc."credentialsId", sc.role, p.id, p.name, p.type, p.icon
				FROM shared_credentials sc
				JOIN project p ON sc."projectId" = p.id
				WHERE sc."credentialsId" = ANY($1);
			`
			bRows, err := h.pool.Query(ctx, batchSharesQuery, allIDs)
			if err == nil {
				homeMap := make(map[string]ProjectRef)
				sharesMap := make(map[string][]ProjectRef)
				for bRows.Next() {
					var credID, role, pID, pName, pType string
					var pIcon *string
					if err := bRows.Scan(&credID, &role, &pID, &pName, &pType, &pIcon); err == nil {
						pref := ProjectRef{
							ID:   pID,
							Name: pName,
							Type: pType,
							Icon: pIcon,
						}
						switch role {
						case "credential:owner":
							homeMap[credID] = pref
						case "credential:user":
							sharesMap[credID] = append(sharesMap[credID], pref)
						}
					}
				}
				bRows.Close()

				for _, item := range payload.Data {
					if id, ok := item["id"].(string); ok {
						if hp, exists := homeMap[id]; exists {
							item["homeProject"] = hp
						} else {
							item["homeProject"] = nil
						}
						if spList, exists := sharesMap[id]; exists {
							item["sharedWithProjects"] = spList
						} else {
							item["sharedWithProjects"] = []ProjectRef{}
						}
					}
				}
			}
		}
	}

	enrichedBytes, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"status":"error","message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(enrichedBytes)
}
