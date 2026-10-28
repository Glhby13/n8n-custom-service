package authservice

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fakes -----------------------------------------------------------------------------------------------------

type kcUser struct {
	id, username, email, password string
	roles                         []string
	otpRaw                        string // raw OTP secret once a credential exists
}

// fakeKeycloak reproduces what the real realm does for client n8n-lab: the n8n-direct-grant flow asks for the code only
// when the user holds an OTP credential AND the n8n-admin role, and (denyNoAccess, as in the real flow) refuses a user
// who proved the password but lacks n8n-access with 401 and an HTML page; the Admin API lists and registers credentials.
type fakeKeycloak struct {
	mu           sync.Mutex
	denyNoAccess bool
	users        map[string]*kcUser // by id
	srv          *httptest.Server
}

func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "h." + base64.RawURLEncoding.EncodeToString(b) + ".s"
}

func newFakeKeycloak(users ...*kcUser) *fakeKeycloak {
	k := &fakeKeycloak{users: map[string]*kcUser{}}
	for _, u := range users {
		k.users[u.id] = u
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/lab/protocol/openid-connect/token", k.token)
	mux.HandleFunc("GET /admin/realms/lab/users", k.list)
	mux.HandleFunc("GET /admin/realms/lab/users/{id}", k.get)
	mux.HandleFunc("PUT /admin/realms/lab/users/{id}", k.put)
	mux.HandleFunc("GET /admin/realms/lab/users/{id}/credentials", k.creds)
	mux.HandleFunc("GET /admin/realms/lab/users/{id}/role-mappings/clients/{cid}/composite", k.roles)
	mux.HandleFunc("GET /admin/realms/lab/clients", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"cli-1"}]`))
	})
	k.srv = httptest.NewServer(mux)
	return k
}

func (k *fakeKeycloak) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("grant_type") == "client_credentials" {
		_, _ = w.Write([]byte(`{"access_token":"svc","expires_in":300}`))
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	bad := func() {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid user credentials"}`))
	}
	var u *kcUser
	for _, c := range k.users {
		if c.username == r.Form.Get("username") || c.email == r.Form.Get("username") {
			u = c
		}
	}
	if u == nil || u.password != r.Form.Get("password") {
		bad()
		return
	}
	if k.denyNoAccess && !hasRole(u.roles, "n8n-access") {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Access denied</body></html>"))
		return
	}
	if u.otpRaw != "" && hasRole(u.roles, "n8n-admin") && !validTOTP(u.otpRaw, r.Form.Get("totp"), time.Now()) {
		bad()
		return
	}
	at := jwt(map[string]any{"sub": u.id, "email": u.email, "preferred_username": u.username, "given_name": "G", "family_name": "F",
		"resource_access": map[string]any{"n8n-lab": map[string]any{"roles": u.roles}}})
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": at, "id_token": at})
}

func hasRole(roles []string, r string) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

func (k *fakeKeycloak) list(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := []map[string]string{}
	for _, u := range k.users {
		if (r.URL.Query().Get("username") != "" && u.username == r.URL.Query().Get("username")) ||
			(r.URL.Query().Get("email") != "" && u.email == r.URL.Query().Get("email")) {
			out = append(out, map[string]string{"id": u.id})
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (k *fakeKeycloak) get(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	u := k.users[r.PathValue("id")]
	_ = json.NewEncoder(w).Encode(map[string]any{"id": u.id, "username": u.username, "enabled": true})
}

func (k *fakeKeycloak) put(w http.ResponseWriter, r *http.Request) {
	var rep struct {
		Credentials []struct {
			Type       string `json:"type"`
			SecretData string `json:"secretData"`
		} `json:"credentials"`
	}
	_ = json.NewDecoder(r.Body).Decode(&rep)
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, c := range rep.Credentials {
		if c.Type == "otp" {
			var sd struct {
				Value string `json:"value"`
			}
			_ = json.Unmarshal([]byte(c.SecretData), &sd)
			k.users[r.PathValue("id")].otpRaw = sd.Value
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (k *fakeKeycloak) creds(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := []map[string]string{{"type": "password"}}
	if k.users[r.PathValue("id")].otpRaw != "" {
		out = append(out, map[string]string{"type": "otp"})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (k *fakeKeycloak) roles(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := []map[string]string{}
	for _, n := range k.users[r.PathValue("id")].roles {
		out = append(out, map[string]string{"name": n})
	}
	_ = json.NewEncoder(w).Encode(out)
}

type fakeStore struct {
	mu       sync.Mutex
	roleSync map[string]string
}

func (f *fakeStore) GetMapping(context.Context, string) (*MappingRecord, error) { return nil, nil }
func (f *fakeStore) IsUserDisabled(context.Context, string) (bool, error)       { return false, nil }
func (f *fakeStore) EnsureUserExists(context.Context, string, string, string) error {
	return nil
}
func (f *fakeStore) EnsureManagedPassword(context.Context, string, string) error { return nil }
func (f *fakeStore) SyncUserRole(_ context.Context, email, role string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roleSync[email] = role
	return nil
}

func fakeN8n(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email, Password, MFA string
		}
		var raw map[string]string
		_ = json.NewDecoder(r.Body).Decode(&raw)
		in.Email, in.Password, in.MFA = raw["emailOrLdapLoginId"], raw["password"], raw["mfaCode"]
		switch {
		case in.Email == "mfa@lab.local" && in.MFA == "":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":998,"message":"MFA Error"}`))
		case strings.HasPrefix(in.Password, "N8nSsoPass_") || in.Password == "LocalPw1":
			http.SetCookie(w, &http.Cookie{Name: "n8n-auth", Value: "sess-" + in.Email})
			_, _ = w.Write([]byte(`{"data":{}}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":401,"message":"Wrong username or password"}`))
		}
	}))
}

type env struct {
	srv   *Server
	kc    *fakeKeycloak
	store *fakeStore
	h     http.Handler
}

func newEnv(t *testing.T, users ...*kcUser) *env {
	t.Helper()
	kc := newFakeKeycloak(users...)
	n8n := fakeN8n(t)
	t.Cleanup(kc.srv.Close)
	t.Cleanup(n8n.Close)
	oidc := NewOIDCClient(kc.srv.URL+"/realms/lab", "n8n-lab", "secret", "http://x/cb")
	st := &fakeStore{roleSync: map[string]string{}}
	s := &Server{
		cfg: &Config{N8NBaseURL: n8n.URL, OIDCClientSecret: "secret"}, users: st, oidc: oidc, kc: newKeycloakAdmin(oidc),
		httpClient: http.DefaultClient, log: slog.New(slog.NewTextHandler(io.Discard, nil)), enrol: newEnrolStore(), lim: newLimiter(),
	}
	mux := http.NewServeMux()
	s.registerLogin(mux)
	return &env{srv: s, kc: kc, store: st, h: mux}
}

func (e *env) post(t *testing.T, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("X-Forwarded-For", "10.1.1.1")
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func cookieOf(rr *httptest.ResponseRecorder) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "n8n-auth" {
			return c.Value
		}
	}
	return ""
}

// codeFor turns the base32 secret shown in the QR code into the code the authenticator app would display.
func codeFor(t *testing.T, b32 string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Fatal(err)
	}
	return totpAt(key, time.Now().Unix()/totpPeriod)
}

var (
	regular = func() *kcUser {
		return &kcUser{id: "u-1", username: "budi", email: "budi@lab.local", password: "Pw-budi", roles: []string{"n8n-access", "n8n-user"}}
	}
	admin = func() *kcUser {
		return &kcUser{id: "u-2", username: "sari", email: "sari@lab.local", password: "Pw-sari", roles: []string{"n8n-access", "n8n-admin"}}
	}
)

// ---- tests -----------------------------------------------------------------------------------------------------

func TestADLoginRegularUserNeedsNoCode(t *testing.T) {
	e := newEnv(t, regular())
	rr, body := e.post(t, "/sso/login/ad", map[string]string{"username": "BUDI", "password": "Pw-budi", "redirect": "%252Fworkflows"})
	if rr.Code != 200 || body["redirect"] != "/workflows" || body["browser_id"] == "" {
		t.Fatalf("regular user must sign in directly: %d %v", rr.Code, body)
	}
	if cookieOf(rr) == "" {
		t.Fatal("n8n session cookie was not set")
	}
	if e.store.roleSync["budi@lab.local"] != "global:member" {
		t.Fatalf("role not synced as member: %v", e.store.roleSync)
	}
}

func TestADLoginWrongPasswordIsGeneric(t *testing.T) {
	e := newEnv(t, regular())
	rr, body := e.post(t, "/sso/login/ad", map[string]string{"username": "budi", "password": "nope"})
	if rr.Code != 401 || body["error"] != "invalid_credentials" || cookieOf(rr) != "" {
		t.Fatalf("got %d %v", rr.Code, body)
	}
}

// Second lock: even when Keycloak lets the user through, the application still refuses a token without n8n-access.
func TestADLoginRequiresN8nAccessRole(t *testing.T) {
	u := regular()
	u.roles = []string{"n8n-user"}
	e := newEnv(t, u)
	rr, body := e.post(t, "/sso/login/ad", map[string]string{"username": "budi", "password": "Pw-budi"})
	if rr.Code != 403 || body["error"] != "access_denied" || body["error_description"] != msgNotAuthorized || cookieOf(rr) != "" {
		t.Fatalf("got %d %v", rr.Code, body)
	}
}

// First lock: Keycloak's flow refuses the user (401 + HTML after the password check); the page shows the neutral
// message, a wrong password is still a normal credential error, and neither case sets a session.
func TestADLoginKeycloakDeniesWithoutAccessRole(t *testing.T) {
	u := regular()
	u.roles = []string{"n8n-user"}
	e := newEnv(t, u)
	e.kc.denyNoAccess = true
	rr, body := e.post(t, "/sso/login/ad", map[string]string{"username": "budi", "password": "Pw-budi"})
	if rr.Code != 403 || body["error"] != "access_denied" || body["error_description"] != msgNotAuthorized || cookieOf(rr) != "" {
		t.Fatalf("denied: got %d %v", rr.Code, body)
	}
	rr, body = e.post(t, "/sso/login/ad", map[string]string{"username": "budi", "password": "nope"})
	if rr.Code != 401 || body["error"] != "invalid_credentials" {
		t.Fatalf("wrong password: got %d %v", rr.Code, body)
	}
}

// The case that motivated the feature: someone becomes administrator, has never enrolled an authenticator, and is
// offered a QR code; the secret ends up in Keycloak and Keycloak then asks for the code on every later sign-in.
func TestAdminWithoutOTPEnrolsAndKeycloakThenVerifies(t *testing.T) {
	e := newEnv(t, admin())
	creds := map[string]string{"username": "sari", "password": "Pw-sari"}

	rr, body := e.post(t, "/sso/login/ad", creds)
	if rr.Code != 401 || body["error"] != "totp_setup_required" || cookieOf(rr) != "" {
		t.Fatalf("first admin sign-in must offer enrolment, no session yet: %d %v", rr.Code, body)
	}
	b32, _ := body["secret"].(string)
	token, _ := body["setup_token"].(string)
	if b32 == "" || token == "" || !strings.HasPrefix(body["qr_code"].(string), "data:image/png;base64,") {
		t.Fatalf("enrolment payload incomplete: %v", body)
	}
	if e.kc.users["u-2"].otpRaw != "" {
		t.Fatal("secret must not reach Keycloak before the user proves the code")
	}

	rr, body = e.post(t, "/sso/login/ad/totp-setup", map[string]string{"setup_token": token, "code": "000000"})
	if rr.Code != 401 || body["error"] != "invalid_code" || e.kc.users["u-2"].otpRaw != "" {
		t.Fatalf("a wrong code must not enrol: %d %v", rr.Code, body)
	}

	rr, body = e.post(t, "/sso/login/ad/totp-setup", map[string]string{"setup_token": token, "code": codeFor(t, b32)})
	if rr.Code != 200 || cookieOf(rr) == "" || body["browser_id"] == "" {
		t.Fatalf("right code must finish the sign-in: %d %v", rr.Code, body)
	}
	if e.kc.users["u-2"].otpRaw == "" {
		t.Fatal("secret was not stored as the Keycloak OTP credential")
	}
	if e.store.roleSync["sari@lab.local"] != "global:admin" {
		t.Fatalf("administrator role not synced: %v", e.store.roleSync)
	}

	// the setup token is single use
	rr, body = e.post(t, "/sso/login/ad/totp-setup", map[string]string{"setup_token": token, "code": codeFor(t, b32)})
	if rr.Code != 400 || body["error"] != "invalid_or_expired_token" {
		t.Fatalf("setup token must not work twice: %d %v", rr.Code, body)
	}

	// from now on Keycloak itself asks for the code
	rr, body = e.post(t, "/sso/login/ad", creds)
	if rr.Code != 401 || body["error"] != "totp_required" {
		t.Fatalf("enrolled admin must be asked for the code: %d %v", rr.Code, body)
	}
	wrong := map[string]string{"username": "sari", "password": "Pw-sari", "totp": "000000"}
	rr, body = e.post(t, "/sso/login/ad", wrong)
	if rr.Code != 401 || body["error"] != "invalid_credentials" || cookieOf(rr) != "" {
		t.Fatalf("wrong code must be refused: %d %v", rr.Code, body)
	}
	good := map[string]string{"username": "sari", "password": "Pw-sari", "totp": codeFor(t, b32)}
	rr, body = e.post(t, "/sso/login/ad", good)
	if rr.Code != 200 || cookieOf(rr) == "" {
		t.Fatalf("right code must sign in: %d %v", rr.Code, body)
	}
}

func TestEnrolmentNeverReplacesExistingOTP(t *testing.T) {
	e := newEnv(t, admin())
	if err := e.srv.kc.RegisterOTP(context.Background(), "u-2", "FirstRawSecret1234567"); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.kc.RegisterOTP(context.Background(), "u-2", "AttackerSecret123456"); !errors.Is(err, errOTPExists) {
		t.Fatalf("expected errOTPExists, got %v", err)
	}
	if e.kc.users["u-2"].otpRaw != "FirstRawSecret1234567" {
		t.Fatal("existing authenticator was overwritten")
	}
}

func TestEnrolmentTokenExpiresAndIsLimited(t *testing.T) {
	e := newEnv(t, admin())
	_, body := e.post(t, "/sso/login/ad", map[string]string{"username": "sari", "password": "Pw-sari"})
	token := body["setup_token"].(string)
	for i := 0; i < maxEnrolAttempts; i++ {
		e.post(t, "/sso/login/ad/totp-setup", map[string]string{"setup_token": token, "code": "000000"})
	}
	_, body = e.post(t, "/sso/login/ad/totp-setup", map[string]string{"setup_token": token, "code": "000000"})
	if body["error"] != "invalid_or_expired_token" {
		t.Fatalf("token must die after %d tries: %v", maxEnrolAttempts, body)
	}

	e.srv.lim = newLimiter() // the wrong codes above also count as failed sign-ins and lock the account
	_, body = e.post(t, "/sso/login/ad", map[string]string{"username": "sari", "password": "Pw-sari"})
	token = body["setup_token"].(string)
	e.srv.enrol.m[token].expires = time.Now().Add(-time.Second)
	_, body = e.post(t, "/sso/login/ad/totp-setup", map[string]string{"setup_token": token, "code": "000000"})
	if body["error"] != "invalid_or_expired_token" {
		t.Fatalf("expired token must be refused: %v", body)
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t, regular())
	for i := 0; i < maxUserFailures; i++ {
		e.post(t, "/sso/login/ad", map[string]string{"username": "budi", "password": "bad"})
	}
	rr, body := e.post(t, "/sso/login/ad", map[string]string{"username": "budi", "password": "Pw-budi"})
	if rr.Code != 429 || body["error"] != "locked" || cookieOf(rr) != "" {
		t.Fatalf("even the right password must be refused while locked: %d %v", rr.Code, body)
	}
}

func TestLocalAccountLogin(t *testing.T) {
	e := newEnv(t)
	rr, body := e.post(t, "/sso/login/local", map[string]string{"username": "owner@lab.local", "password": "LocalPw1", "redirect": "/home"})
	if rr.Code != 200 || cookieOf(rr) != "sess-owner@lab.local" || body["redirect"] != "/home" || body["browser_id"] == "" {
		t.Fatalf("local sign-in failed: %d %v", rr.Code, body)
	}
	rr, body = e.post(t, "/sso/login/local", map[string]string{"username": "owner@lab.local", "password": "wrong"})
	if rr.Code != 401 || body["error"] != "invalid_credentials" || cookieOf(rr) != "" {
		t.Fatalf("wrong local password: %d %v", rr.Code, body)
	}
	rr, body = e.post(t, "/sso/login/local", map[string]string{"username": "mfa@lab.local", "password": "LocalPw1"})
	if rr.Code != 401 || body["error"] != "mfa_required" {
		t.Fatalf("n8n multi-factor challenge must reach the page: %d %v", rr.Code, body)
	}
	rr, _ = e.post(t, "/sso/login/local", map[string]string{"username": "mfa@lab.local", "password": "LocalPw1", "totp": "123456"})
	if rr.Code != 200 {
		t.Fatalf("code must be forwarded to n8n: %d", rr.Code)
	}
}

func TestLoginPageAndAssets(t *testing.T) {
	e := newEnv(t)
	for path, ctype := range map[string]string{
		"/signin":               "text/html",
		"/sso/assets/login.js":  "text/javascript",
		"/sso/assets/login.css": "text/css",
		"/sso/assets/logo.svg":  "image/svg+xml",
	} {
		rr := httptest.NewRecorder()
		e.h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), ctype) || rr.Body.Len() == 0 {
			t.Fatalf("%s: %d %q", path, rr.Code, rr.Header().Get("Content-Type"))
		}
	}
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/signin?ad=1&redirect=%252F", nil))
	body := rr.Body.String()
	for _, want := range []string{"Sign in with AD BTN", "Sign in with local account"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q", want)
		}
	}
	// the logo sits inside the card and the card is centred in the window, like the DrawSpace sign-in page
	if c, b := strings.Index(body, `class="card"`), strings.Index(body, `class="brand"`); c < 0 || b < c {
		t.Fatal("the logo must be inside the card")
	}
	css, _ := webFS.ReadFile("web/login.css")
	if !strings.Contains(string(css), "align-items: center; justify-content: center") {
		t.Fatal("the card must be centred in the window")
	}
	// n8n serves its own favicon at /favicon.ico (same origin, so the page CSP already allows it): no copy to keep in step
	if !strings.Contains(body, `rel="icon" href="/favicon.ico"`) {
		t.Fatal("the page must use n8n's own favicon")
	}
	if strings.Contains(strings.ToLower(body), "forgot") {
		t.Fatal("the page must not offer password recovery")
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("weak page headers: %q", csp)
	}
}

func TestSafeRedirect(t *testing.T) {
	for in, want := range map[string]string{
		"":                        "/",
		"/":                       "/",
		"%252F":                   "/",
		"%252Fworkflow%252F12":    "/workflow/12",
		"/home/workflows":         "/home/workflows",
		"//evil.example":          "/",
		"https://evil.example":    "/",
		"/\\evil.example":         "/",
		"%252F%252Fevil.example":  "/",
		"/signin":                 "/",
		"/signin?ad=1":            "/",
		"/sso/login":              "/",
		"javascript:alert(1)":     "/",
		"/ok%0d%0aSet-Cookie:x=1": "/",
	} {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTOTPKnownVector(t *testing.T) {
	// RFC 6238 appendix B (SHA-1, secret "12345678901234567890", T=59s): 94287082, six digits 287082.
	if got := totpAt([]byte("12345678901234567890"), 59/30); got != "287082" {
		t.Fatalf("totp = %s, want 287082", got)
	}
	raw, b32, err := newOTPSecret()
	if err != nil || len(raw) != secretLen {
		t.Fatalf("secret: %q %v", raw, err)
	}
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if string(key) != raw {
		t.Fatal("base32 form must encode the raw secret bytes")
	}
	now := time.Now()
	if !validTOTP(raw, totpAt([]byte(raw), now.Unix()/30), now) || validTOTP(raw, "12345", now) || validTOTP(raw, "abcdef", now) {
		t.Fatal("validTOTP misjudged codes")
	}
}

func TestOTPLabelMatchesKeycloaksOwn(t *testing.T) {
	// Keycloak's enrolment page labels the entry "<realm display name>:<user name>", e.g. "Lab:lab-test3".
	uri := otpauthURI("JBSWY3DPEHPK3PXP", "lab-test3", "Lab")
	for _, want := range []string{"otpauth://totp/Lab:lab-test3?", "secret=JBSWY3DPEHPK3PXP", "issuer=Lab", "digits=6", "period=30", "algorithm=SHA1"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("uri %q lacks %q", uri, want)
		}
	}
	// the account is the user name even when the e-mail is known, and falls back only when there is none
	c := &UserClaims{PreferredUsername: "lab-test3", Email: "lab-test3@lab.local"}
	if got := otpAccount(c, "LAB-TEST3@lab.local"); got != "lab-test3" {
		t.Fatalf("account = %q, want the Keycloak user name", got)
	}
	if got := otpAccount(&UserClaims{Email: "a@lab.local"}, "typed"); got != "typed" {
		t.Fatalf("fallback account = %q", got)
	}
	if realmName("https://auth.lab.local/realms/lab") != "lab" || realmName("https://x") != "Keycloak" {
		t.Fatal("realmName fallback wrong")
	}
}

// The page shown right after a code-flow sign-in: neutral wording (no mention of Keycloak), the e-mail is escaped,
// the browser id is handed to n8n, and the theme follows the sign-in page.
func TestHandoffPageWordingAndEscaping(t *testing.T) {
	rr := httptest.NewRecorder()
	(&Server{}).renderHandoff(rr, `a<b>&"@lab.local`, "abc123")
	body := rr.Body.String()
	for _, want := range []string{"Autentikasi user AD berhasil untuk", "a&lt;b&gt;&amp;&#34;@lab.local", `localStorage.setItem("n8n-browserId", "abc123")`, "#f0752e", "prefers-reduced-motion"} {
		if !strings.Contains(body, want) {
			t.Errorf("handoff page lacks %q", want)
		}
	}
	for _, bad := range []string{"Keycloak", "a<b>"} {
		if strings.Contains(body, bad) {
			t.Errorf("handoff page must not contain %q", bad)
		}
	}
	if rr.Code != 200 || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d %v", rr.Code, rr.Header())
	}
}
