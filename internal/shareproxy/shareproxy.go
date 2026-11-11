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

// ServeHTTP handles PUT /rest/workflows/{workflowId}/share, PUT /rest/credentials/{credentialId}/share, and GET /rest/settings.
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

	if r.Method != http.MethodPut {
		http.Error(w, `{"status":"error","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if r.PathValue("credentialId") != "" || isCredentialSharePath(r.URL.Path) {
		credID := extractCredentialPathID(r)
		if credID == "" {
			http.Error(w, `{"status":"error","message":"missing credentialId"}`, http.StatusBadRequest)
			return
		}
		h.handleCredentialShare(w, r, credID)
		return
	}

	if r.PathValue("workflowId") != "" || isWorkflowSharePath(r.URL.Path) {
		wfID := extractWorkflowPathID(r)
		if wfID == "" {
			http.Error(w, `{"status":"error","message":"missing workflowId"}`, http.StatusBadRequest)
			return
		}
		h.handleWorkflowShare(w, r, wfID)
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
	if len(parts) >= 3 && parts[0] == "rest" && parts[1] == "credentials" && parts[len(parts)-1] == "share" {
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
