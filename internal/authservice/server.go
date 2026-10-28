package authservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/httpx"
)

// Server is the HTTP server for n8n-auth-service.
type Server struct {
	cfg        *Config
	db         *DB
	users      userStore
	oidc       *OIDCClient
	kc         *keycloakAdmin
	httpClient *http.Client
	log        *slog.Logger
	enrol      *enrolStore
	lim        *limiter
}

// userStore is the part of the n8n database the sign-in flow needs (satisfied by *DB).
type userStore interface {
	GetMapping(ctx context.Context, oidcEmail string) (*MappingRecord, error)
	IsUserDisabled(ctx context.Context, email string) (bool, error)
	EnsureUserExists(ctx context.Context, email, firstName, lastName string) error
	SyncUserRole(ctx context.Context, email, targetRole string) error
	EnsureManagedPassword(ctx context.Context, email, plainPassword string) error
}

// NewServer creates a new Server instance.
func NewServer(cfg *Config, db *DB, log *slog.Logger) *Server {
	oidc := NewOIDCClient(cfg.KeycloakURL, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.OIDCRedirectURL)
	return &Server{
		cfg:        cfg,
		db:         db,
		users:      db,
		oidc:       oidc,
		kc:         newKeycloakAdmin(oidc),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		log:        log.With("component", "auth-server"),
		enrol:      newEnrolStore(),
		lim:        newLimiter(),
	}
}

// Handler registers routes and returns the http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	// OIDC SSO Endpoints
	mux.HandleFunc("GET /sso/login", s.handleSSOLogin)
	mux.HandleFunc("GET /sso/callback", s.handleSSOCallback)

	// Sign-in page (served in place of n8n's own /signin) and its JSON endpoints.
	s.registerLogin(mux)

	// Admin API Endpoints (Token-based Bearer authentication)
	mux.HandleFunc("POST /admin/api/v1/transfer-ownership", s.tokenAuth(s.handleTransferOwnership))
	mux.HandleFunc("GET /admin/api/v1/users", s.tokenAuth(s.handleListUsers))
	mux.HandleFunc("POST /admin/api/v1/users/{email}/role", s.tokenAuth(s.handleUpdateUserRole))
	mux.HandleFunc("POST /admin/api/v1/users/{email}/status", s.tokenAuth(s.handleUpdateUserStatus))
	mux.HandleFunc("DELETE /admin/api/v1/users/{email}", s.tokenAuth(s.handleDeleteUser))

	// Legacy compatibility mappings
	mux.HandleFunc("GET /admin/api/mappings", s.tokenAuth(s.handleListMappings))
	mux.HandleFunc("POST /admin/api/mappings", s.tokenAuth(s.handleCreateMapping))
	mux.HandleFunc("DELETE /admin/api/mappings/{oidcEmail}", s.tokenAuth(s.handleDeleteMapping))

	return mux
}

// handleSSOLogin initiates Keycloak OIDC login redirect.
func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	// Set state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "n8n_sso_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL := s.oidc.AuthURL(state, state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleSSOCallback handles OIDC authorization code callback from Keycloak.
func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		s.renderError(w, http.StatusBadRequest, "Missing authorization code from Keycloak")
		return
	}

	stateCookie, err := r.Cookie("n8n_sso_state")
	if err != nil || stateCookie.Value == "" || stateCookie.Value != state {
		s.log.Warn("invalid sso state cookie", "expected", state, "got", stateCookie)
		// We still allow continuation if state parameter is present, but log warning
	}

	// 1. Exchange code for token
	claims, err := s.oidc.ExchangeCode(ctx, code)
	if err != nil {
		s.log.Error("exchange code failed", "err", err)
		s.renderError(w, http.StatusBadGateway, "Gagal menukar token dengan Keycloak: "+err.Error())
		return
	}

	res, fail := s.establishSession(ctx, claims)
	if fail != nil {
		s.renderError(w, fail.status, fail.msg)
		return
	}
	http.SetCookie(w, n8nSessionCookie(res.cookie))
	s.renderHandoff(w, res.email, res.browserID)
}

// loginFailure is a refused sign-in with the HTTP status and the message to show.
type loginFailure struct {
	status int
	msg    string
}

// loginResult is a signed-in n8n session: the cookie n8n issued and the browser id the SPA must store.
type loginResult struct {
	cookie    *http.Cookie
	browserID string
	email     string
}

func n8nSessionCookie(c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:     "n8n-auth",
		Value:    c.Value,
		Path:     "/",
		MaxAge:   7 * 24 * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// establishSession turns verified Keycloak claims into an n8n session: role gate, mapping, disabled check, JIT user,
// role sync, managed password, then n8n's own /rest/login for the official cookie. It is shared by the code flow
// callback and the direct sign-in page.
func (s *Server) establishSession(ctx context.Context, claims *UserClaims) (*loginResult, *loginFailure) {
	if claims.Email == "" {
		return nil, &loginFailure{http.StatusBadRequest, "Akun Keycloak Anda tidak memiliki alamat email."}
	}

	// 2. Enforce Role: n8n-access
	if !claims.HasRole("n8n-access") {
		s.log.Warn("user lacks required role n8n-access", "user", claims.Email, "roles", claims.Roles)
		return nil, &loginFailure{http.StatusForbidden, msgNotAuthorized}
	}

	s.log.Info("oidc authentication successful", "email", claims.Email, "roles", claims.Roles)

	// 3. Resolve target n8n account (Check mapping)
	targetEmail := claims.Email
	mapping, err := s.users.GetMapping(ctx, claims.Email)
	if err == nil && mapping != nil && mapping.TargetN8nEmail != "" {
		targetEmail = mapping.TargetN8nEmail
		s.log.Info("oidc user mapped to existing n8n account", "oidc", claims.Email, "target", targetEmail)
	}

	// 3b. Check if user account is disabled in n8n_db
	if isDisabled, err := s.users.IsUserDisabled(ctx, targetEmail); err == nil && isDisabled {
		s.log.Warn("disabled user attempted sso login", "email", targetEmail)
		return nil, &loginFailure{http.StatusForbidden, "Akses ditolak: Akun " + targetEmail + " telah dinonaktifkan oleh Administrator."}
	}

	// 4. Ensure target user exists in n8n_db (JIT provisioning)
	fName := claims.GivenName
	if fName == "" {
		fName = claims.Name
	}
	lName := claims.FamilyName
	if err := s.users.EnsureUserExists(ctx, targetEmail, fName, lName); err != nil {
		s.log.Error("ensure user exists failed", "email", targetEmail, "err", err)
		return nil, &loginFailure{http.StatusInternalServerError, "Gagal memverifikasi akun di database n8n."}
	}

	// 4b. Sync role with Keycloak (claims.HasRole("n8n-admin") -> global:admin, else global:member)
	targetRole := "global:member"
	if claims.HasRole("n8n-admin") {
		targetRole = "global:admin"
	}
	if err := s.users.SyncUserRole(ctx, targetEmail, targetRole); err != nil {
		s.log.Warn("sync user role failed", "email", targetEmail, "role", targetRole, "err", err)
	} else {
		s.log.Info("user role synced successfully", "email", targetEmail, "role", targetRole)
	}

	// 5. Generate deterministic managed password for n8n login
	h := sha256.New()
	h.Write([]byte(s.cfg.OIDCClientSecret))
	h.Write([]byte("::managed::"))
	h.Write([]byte(strings.ToLower(targetEmail)))
	managedPass := "N8nSsoPass_" + hex.EncodeToString(h.Sum(nil))[:24] + "#"

	if err := s.users.EnsureManagedPassword(ctx, targetEmail, managedPass); err != nil {
		s.log.Error("ensure managed password failed", "email", targetEmail, "err", err)
		return nil, &loginFailure{http.StatusInternalServerError, "Gagal memperbarui kredensial n8n internal."}
	}

	// 6. Login to internal n8n via /rest/login to obtain official session cookie
	browserIDBytes := make([]byte, 16)
	_, _ = rand.Read(browserIDBytes)
	browserID := hex.EncodeToString(browserIDBytes)

	n8nCookie, err := s.loginN8n(ctx, targetEmail, managedPass, browserID)
	if err != nil {
		s.log.Error("internal n8n login failed", "email", targetEmail, "err", err)
		return nil, &loginFailure{http.StatusBadGateway, "Gagal login ke server n8n internal: " + err.Error()}
	}
	return &loginResult{cookie: n8nCookie, browserID: browserID, email: targetEmail}, nil
}

func (s *Server) loginN8n(ctx context.Context, email, password, browserID string) (*http.Cookie, error) {
	loginPayload, _ := json.Marshal(map[string]string{
		"emailOrLdapLoginId": email,
		"password":           password,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.N8NBaseURL+"/rest/login", bytes.NewReader(loginPayload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("browser-id", browserID)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call n8n /rest/login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("n8n login status %d: %s", resp.StatusCode, string(raw))
	}

	for _, c := range resp.Cookies() {
		if c.Name == "n8n-auth" && c.Value != "" {
			return c, nil
		}
	}
	return nil, errors.New("n8n did not return n8n-auth cookie")
}

func (s *Server) renderHandoff(w http.ResponseWriter, email, browserID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	const tmpl = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Membuka n8n...</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2rem 2.5rem; border-radius: 0.75rem; border: 1px solid #334155; text-align: center; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); max-width: 400px; }
    h2 { margin: 0 0 0.5rem; font-size: 1.25rem; font-weight: 600; color: #38bdf8; }
    p { margin: 0; color: #94a3b8; font-size: 0.875rem; }
    .spinner { margin: 1.5rem auto 0; width: 24px; height: 24px; border: 3px solid #334155; border-top-color: #38bdf8; border-radius: 50%; animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="card">
    <h2>Membuka n8n...</h2>
    <p>Autentikasi SSO Keycloak berhasil untuk <b>{{EMAIL}}</b></p>
    <div class="spinner"></div>
  </div>
  <script>
    try {
      localStorage.setItem("n8n-browserId", "{{BROWSER_ID}}");
    } catch(e) {}
    setTimeout(function() { location.replace("/"); }, 200);
  </script>
</body>
</html>`
	out := strings.ReplaceAll(tmpl, "{{EMAIL}}", email)
	out = strings.ReplaceAll(out, "{{BROWSER_ID}}", browserID)
	_, _ = w.Write([]byte(out))
}

func (s *Server) renderError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)

	tmpl := `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Akses n8n Ditolak</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2rem 2.5rem; border-radius: 0.75rem; border: 1px solid #ef4444; text-align: center; max-width: 440px; }
    h2 { margin: 0 0 0.5rem; font-size: 1.25rem; color: #ef4444; }
    p { margin: 0 0 1.5rem; color: #cbd5e1; font-size: 0.875rem; line-height: 1.4; }
    a { display: inline-block; background: #334155; color: #f8fafc; padding: 0.5rem 1rem; border-radius: 0.375rem; text-decoration: none; font-size: 0.875rem; }
    a:hover { background: #475569; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Akses n8n Gagal</h2>
    <p>%s</p>
    <a href="/sso/login">Coba Login Kembali</a>
  </div>
</body>
</html>`
	_, _ = fmt.Fprintf(w, tmpl, msg)
}

// tokenAuth enforces Bearer token authentication (or fallback to X-Admin-Token / Basic Auth).
func (s *Server) tokenAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Bearer Token in Authorization header
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
			token := strings.TrimSpace(authHdr[7:])
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminAPIToken)) == 1 {
				next(w, r)
				return
			}
		}

		// 2. Check X-Admin-Token header
		if customToken := strings.TrimSpace(r.Header.Get("X-Admin-Token")); customToken != "" {
			if subtle.ConstantTimeCompare([]byte(customToken), []byte(s.cfg.AdminAPIToken)) == 1 {
				next(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Bearer realm="n8n-auth-service"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "unauthorized",
			"message": "Invalid or missing Bearer token in Authorization header",
		})
	}
}

type transferOwnershipPayload struct {
	FromEmail     string `json:"from_email"`
	ToEmail       string `json:"to_email"`
	Scope         string `json:"scope"`          // "all" (default) or "workflow"
	WorkflowID    string `json:"workflow_id"`    // optional if scope == "workflow"
	DisableSource bool   `json:"disable_source"` // optional
}

func (s *Server) handleTransferOwnership(w http.ResponseWriter, r *http.Request) {
	var p transferOwnershipPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_json", "invalid json payload: "+err.Error())
		return
	}

	p.FromEmail = strings.TrimSpace(p.FromEmail)
	p.ToEmail = strings.TrimSpace(p.ToEmail)
	if p.FromEmail == "" || p.ToEmail == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, "validation_error", "both from_email and to_email are required")
		return
	}

	if strings.EqualFold(p.Scope, "workflow") && p.WorkflowID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, "validation_error", "workflow_id is required when scope is 'workflow'")
		return
	}

	res, err := s.db.TransferOwnership(r.Context(), p.FromEmail, p.ToEmail, p.DisableSource, p.WorkflowID)
	if err != nil {
		s.log.Error("transfer ownership failed", "err", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "transfer_failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	msg := fmt.Sprintf("Successfully transferred %d workflow(s) and %d credential(s) from %s to %s",
		res.WorkflowsTransferred, res.CredentialsTransferred, res.FromEmail, res.ToEmail)
	if res.WorkflowID != "" {
		msg = fmt.Sprintf("Successfully transferred workflow %s from %s to %s", res.WorkflowID, res.FromEmail, res.ToEmail)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": msg,
		"data":    res,
	})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers(r.Context())
	if err != nil {
		s.log.Error("list users failed", "err", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "db_error", "list users: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": users})
}

type updateUserRolePayload struct {
	Role string `json:"role"`
}

func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	if email == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 2 {
			email = parts[len(parts)-2] // /admin/api/v1/users/{email}/role
		}
	}
	if email == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, "missing_param", "missing user email")
		return
	}

	dec, err := url.PathUnescape(email)
	if err == nil {
		email = dec
	}

	var p updateUserRolePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_json", "invalid json payload: "+err.Error())
		return
	}

	p.Role = strings.TrimSpace(p.Role)
	if p.Role != "global:admin" && p.Role != "global:member" {
		httpx.WriteError(w, r, http.StatusBadRequest, "validation_error", "role must be 'global:admin' or 'global:member'")
		return
	}

	if err := s.db.SyncUserRole(r.Context(), email, p.Role); err != nil {
		s.log.Error("update user role failed", "email", email, "role", p.Role, "err", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "update_role_failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Role for user %s updated to %s", email, p.Role),
	})
}

type updateUserStatusPayload struct {
	Disabled bool `json:"disabled"`
}

func (s *Server) handleUpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	if email == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 2 {
			email = parts[len(parts)-2] // /admin/api/v1/users/{email}/status
		}
	}
	if email == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, "missing_param", "missing user email")
		return
	}

	dec, err := url.PathUnescape(email)
	if err == nil {
		email = dec
	}

	var p updateUserStatusPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_json", "invalid json payload: "+err.Error())
		return
	}

	if err := s.db.SetUserDisabled(r.Context(), email, p.Disabled); err != nil {
		s.log.Error("set user disabled status failed", "email", email, "disabled", p.Disabled, "err", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "update_status_failed", err.Error())
		return
	}

	action := "enabled"
	if p.Disabled {
		action = "disabled"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "success",
		"message":  fmt.Sprintf("User %s has been successfully %s", email, action),
		"disabled": p.Disabled,
	})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	if email == "" {
		parts := strings.Split(r.URL.Path, "/")
		email = parts[len(parts)-1]
	}
	if email == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, "missing_param", "missing user email")
		return
	}

	dec, err := url.PathUnescape(email)
	if err == nil {
		email = dec
	}

	force := strings.EqualFold(r.URL.Query().Get("force"), "true")

	res, err := s.db.DeleteUser(r.Context(), email, force)
	if err != nil {
		s.log.Error("delete user failed", "email", email, "force", force, "err", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "delete_user_failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("User %s and personal project successfully deleted", email),
		"data":    res,
	})
}

func (s *Server) handleListMappings(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.ListMappings(r.Context())
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, "db_error", "list mappings: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": list})
}

type createMappingPayload struct {
	OIDCEmail         string `json:"oidc_email"`
	ReplaceLocalEmail string `json:"replace_local_email"`
	FirstName         string `json:"first_name"`
	LastName          string `json:"last_name"`
}

func (s *Server) handleCreateMapping(w http.ResponseWriter, r *http.Request) {
	var p createMappingPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_json", "invalid json payload: "+err.Error())
		return
	}

	p.OIDCEmail = strings.TrimSpace(p.OIDCEmail)
	p.ReplaceLocalEmail = strings.TrimSpace(p.ReplaceLocalEmail)
	if p.OIDCEmail == "" || p.ReplaceLocalEmail == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, "validation_error", "both oidc_email and replace_local_email are required")
		return
	}

	if err := s.db.ExecuteTakeover(r.Context(), p.OIDCEmail, p.ReplaceLocalEmail, p.FirstName, p.LastName); err != nil {
		s.log.Error("execute takeover failed", "err", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "takeover_failed", "takeover failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Account %s successfully mapped to replace %s", p.OIDCEmail, p.ReplaceLocalEmail),
	})
}

func (s *Server) handleDeleteMapping(w http.ResponseWriter, r *http.Request) {
	oidcEmail := r.PathValue("oidcEmail")
	if oidcEmail == "" {
		parts := strings.Split(r.URL.Path, "/")
		oidcEmail = parts[len(parts)-1]
	}
	if oidcEmail == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, "missing_param", "missing oidcEmail")
		return
	}

	dec, err := url.PathUnescape(oidcEmail)
	if err == nil {
		oidcEmail = dec
	}

	if err := s.db.DeleteMapping(r.Context(), oidcEmail); err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, "db_error", "delete mapping: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted"})
}
