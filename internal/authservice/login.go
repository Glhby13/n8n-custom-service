package authservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The sign-in page replaces n8n's own /signin. It is a plain HTML page with a script, not a patched n8n bundle, so
// n8n itself is untouched: the page only calls this service, and this service obtains the session from n8n.

//go:embed web/login.html web/login.js web/login.css web/logo.svg
var webFS embed.FS

const (
	adminRole        = "n8n-admin"
	maxUserFailures  = 5
	maxIPFailures    = 20
	failWindow       = 15 * time.Minute
	enrolTTL         = 5 * time.Minute
	maxEnrolAttempts = 5
)

// loginCSP allows only this service's own script and styles; no inline code and no framing.
const loginCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func (s *Server) registerLogin(mux *http.ServeMux) {
	mux.HandleFunc("GET /signin", s.handleLoginPage)
	mux.HandleFunc("GET /sso/assets/login.js", s.asset("web/login.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /sso/assets/login.css", s.asset("web/login.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /sso/assets/logo.svg", s.asset("web/logo.svg", "image/svg+xml"))
	mux.HandleFunc("POST /sso/login/ad", s.handleLoginAD)
	mux.HandleFunc("POST /sso/login/ad/totp-setup", s.handleLoginADSetup)
	mux.HandleFunc("POST /sso/login/local", s.handleLoginLocal)
}

func (s *Server) asset(name, ctype string) http.HandlerFunc {
	body, err := webFS.ReadFile(name)
	return func(w http.ResponseWriter, _ *http.Request) {
		if err != nil {
			http.NotFound(w, nil)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
	}
}

func (s *Server) handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	body, err := webFS.ReadFile("web/login.html")
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", loginCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

// ---- JSON helpers --------------------------------------------------------------------------------------------

type loginReply map[string]any

func writeLogin(w http.ResponseWriter, code int, v loginReply) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string, desc ...string) {
	r := loginReply{"error": msg}
	if len(desc) > 0 && desc[0] != "" {
		r["error_description"] = desc[0]
	}
	writeLogin(w, code, r)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// safeRedirect keeps only a same-site absolute path. n8n's own router hands us /signin?redirect=%252F (encoded
// twice), so the value is decoded up to twice; anything that could leave the site, or loop back here, becomes "/".
func safeRedirect(raw string) string {
	v := raw
	for range 2 {
		if d, err := url.QueryUnescape(v); err == nil {
			v = d
		}
	}
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.Contains(v, "\\") ||
		strings.ContainsAny(v, "\r\n") || v == "/signin" || strings.HasPrefix(v, "/signin?") || strings.HasPrefix(v, "/sso/") {
		return "/"
	}
	return v
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
	Redirect string `json:"redirect"`
}

func decodeCreds(r *http.Request) (credentials, bool) {
	var in credentials
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		return in, false
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if in.Username == "" || in.Password == "" || len(in.Username) > 128 || len(in.Password) > 256 {
		return in, false
	}
	return in, true
}

// locked reports whether this user or address has used up its failed sign-in allowance.
func (s *Server) locked(user, ip string) bool {
	return s.lim.count("u:"+user) >= maxUserFailures || s.lim.count("ip:"+ip) >= maxIPFailures
}

func (s *Server) failed(user, ip string) {
	s.lim.add("u:"+user, failWindow)
	s.lim.add("ip:"+ip, failWindow)
}

func (s *Server) finish(w http.ResponseWriter, res *loginResult, redirect string) {
	http.SetCookie(w, n8nSessionCookie(res.cookie))
	writeLogin(w, http.StatusOK, loginReply{"redirect": safeRedirect(redirect), "browser_id": res.browserID})
}

// ---- Sign in with AD BTN: Keycloak direct grant --------------------------------------------------------------

func (s *Server) handleLoginAD(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeCreds(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	if s.locked(in.Username, ip) {
		w.Header().Set("Retry-After", "900")
		s.log.Warn("ad sign-in locked", "user", in.Username)
		writeErr(w, http.StatusTooManyRequests, "locked", "Terlalu banyak percobaan gagal. Coba lagi dalam 15 menit.")
		return
	}

	claims, err := s.oidc.DirectGrant(ctx, in.Username, in.Password, strings.TrimSpace(in.TOTP))
	switch {
	case errors.Is(err, ErrBadCredentials):
		// Keycloak answers the same for a wrong password and for an administrator who has not sent the code yet.
		if strings.TrimSpace(in.TOTP) == "" {
			if need, kerr := s.kc.OTPRequiredFor(ctx, in.Username, adminRole); kerr == nil && need {
				writeErr(w, http.StatusUnauthorized, "totp_required")
				return
			}
		}
		s.failed(in.Username, ip)
		s.log.Info("ad sign-in refused", "user", in.Username)
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "Username, password, atau kode authenticator tidak valid.")
		return
	case errors.Is(err, ErrAccessDenied):
		writeErr(w, http.StatusForbidden, "access_denied", "Akun Anda tidak punya akses ke n8n.")
		return
	case err != nil:
		s.log.Error("ad sign-in backend", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "Layanan autentikasi tidak tersedia.")
		return
	}

	if !claims.HasRole("n8n-access") {
		s.log.Warn("user lacks required role n8n-access", "user", claims.Email)
		writeErr(w, http.StatusForbidden, "access_denied", "Akun "+claims.Email+" tidak memiliki role 'n8n-access' di Keycloak.")
		return
	}

	// Keycloak let an administrator through without asking for a code: the account has no OTP credential yet.
	if claims.HasRole(adminRole) {
		has, kerr := s.kc.HasOTP(ctx, claims.Subject)
		if kerr != nil {
			s.log.Error("otp lookup failed", "user", in.Username, "err", kerr)
			writeErr(w, http.StatusServiceUnavailable, "unavailable", "Layanan autentikasi tidak tersedia.")
			return
		}
		if !has {
			s.beginEnrolment(w, claims, in)
			return
		}
	}

	s.lim.reset("u:" + in.Username)
	res, fail := s.establishSession(ctx, claims)
	if fail != nil {
		writeErr(w, fail.status, "login_failed", fail.msg)
		return
	}
	s.log.Info("ad sign-in ok", "user", in.Username, "email", res.email)
	s.finish(w, res, in.Redirect)
}

// otpAccount is the account name shown in the authenticator app: the Keycloak user name, as on Keycloak's own
// enrolment page (never the e-mail address, and never the application name, because the code belongs to the user).
func otpAccount(c *UserClaims, typed string) string {
	for _, v := range []string{c.PreferredUsername, typed, c.Email} {
		if v != "" {
			return v
		}
	}
	return "user"
}

// beginEnrolment makes a secret and the QR code for it and holds the secret in memory (not in Keycloak, not in any
// database) until the user proves the authenticator works.
func (s *Server) beginEnrolment(w http.ResponseWriter, claims *UserClaims, in credentials) {
	raw, b32, err := newOTPSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	qr, err := qrDataURI(b32, otpAccount(claims, in.Username), s.cfg.OTPIssuer)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	token := randomToken(32)
	s.enrol.put(token, enrolEntry{claims: claims, raw: raw, username: in.Username, redirect: in.Redirect, expires: time.Now().Add(enrolTTL)})
	s.log.Info("otp enrolment started", "user", in.Username)
	writeLogin(w, http.StatusUnauthorized, loginReply{"error": "totp_setup_required", "qr_code": qr, "secret": b32, "setup_token": token})
}

func (s *Server) handleLoginADSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SetupToken string `json:"setup_token"`
		Code       string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || in.SetupToken == "" || in.Code == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	e, state := s.enrol.attempt(in.SetupToken)
	if state != enrolOK {
		writeErr(w, http.StatusBadRequest, "invalid_or_expired_token", "Sesi pendaftaran kedaluwarsa. Silakan login kembali.")
		return
	}
	if s.locked(e.username, ip) {
		w.Header().Set("Retry-After", "900")
		writeErr(w, http.StatusTooManyRequests, "locked", "Terlalu banyak percobaan gagal. Coba lagi dalam 15 menit.")
		return
	}
	if !validTOTP(e.raw, in.Code, time.Now()) {
		s.failed(e.username, ip)
		writeErr(w, http.StatusUnauthorized, "invalid_code", "Kode authenticator tidak valid. Coba lagi.")
		return
	}
	s.enrol.drop(in.SetupToken)
	if err := s.kc.RegisterOTP(ctx, e.claims.Subject, e.raw); err != nil {
		if errors.Is(err, errOTPExists) {
			writeErr(w, http.StatusConflict, "otp_exists", "Akun ini sudah punya authenticator. Silakan login kembali.")
			return
		}
		s.log.Error("register otp in keycloak failed", "user", e.username, "err", err)
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "Gagal menyimpan authenticator di Keycloak.")
		return
	}
	s.lim.reset("u:" + e.username)
	s.log.Info("otp registered in keycloak", "user", e.username)
	res, fail := s.establishSession(ctx, e.claims)
	if fail != nil {
		writeErr(w, fail.status, "login_failed", fail.msg)
		return
	}
	s.finish(w, res, e.redirect)
}

// ---- Sign in with local account: n8n's own /rest/login ---------------------------------------------------------

func (s *Server) handleLoginLocal(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeCreds(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	ip := clientIP(r)
	if s.locked(in.Username, ip) {
		w.Header().Set("Retry-After", "900")
		writeErr(w, http.StatusTooManyRequests, "locked", "Terlalu banyak percobaan gagal. Coba lagi dalam 15 menit.")
		return
	}
	browserID := randomToken(16)
	cookie, status, code, err := s.localN8nLogin(r.Context(), in.Username, in.Password, strings.TrimSpace(in.TOTP), browserID)
	switch {
	case err != nil:
		s.log.Error("local sign-in backend", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "Server n8n tidak tersedia.")
	case cookie != nil:
		s.lim.reset("u:" + in.Username)
		s.log.Info("local sign-in ok", "user", in.Username)
		s.finish(w, &loginResult{cookie: cookie, browserID: browserID, email: in.Username}, in.Redirect)
	case code == 998:
		writeErr(w, http.StatusUnauthorized, "mfa_required")
	case status == http.StatusTooManyRequests:
		writeErr(w, http.StatusTooManyRequests, "locked", "Terlalu banyak percobaan. Coba lagi sebentar lagi.")
	default:
		s.failed(in.Username, ip)
		s.log.Info("local sign-in refused", "user", in.Username)
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "Email atau password tidak valid.")
	}
}

// localN8nLogin posts the credentials to n8n. It returns the session cookie on success, otherwise n8n's HTTP status
// and its numeric error code (998 = a multi-factor code is needed).
func (s *Server) localN8nLogin(ctx context.Context, email, password, mfaCode, browserID string) (*http.Cookie, int, int, error) {
	payload := map[string]string{"emailOrLdapLoginId": email, "password": password}
	if mfaCode != "" {
		payload["mfaCode"] = mfaCode
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.N8NBaseURL+"/rest/login", bytes.NewReader(b))
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("browser-id", browserID)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode == http.StatusOK {
		for _, c := range resp.Cookies() {
			if c.Name == "n8n-auth" && c.Value != "" {
				return c, resp.StatusCode, 0, nil
			}
		}
		return nil, resp.StatusCode, 0, errors.New("n8n did not return n8n-auth cookie")
	}
	var e struct {
		Code int `json:"code"`
	}
	_ = json.Unmarshal(raw, &e)
	return nil, resp.StatusCode, e.Code, nil
}

// ---- in-memory state ---------------------------------------------------------------------------------------------

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type enrolEntry struct {
	claims   *UserClaims
	raw      string
	username string
	redirect string
	expires  time.Time
	tries    int
}

type enrolState int

const (
	enrolOK enrolState = iota
	enrolGone
)

// enrolStore holds pending authenticator enrolments for a few minutes. It lives in the pod's memory on purpose: the
// secret is not written anywhere until the user has proved the code, and a pod restart only means signing in again.
type enrolStore struct {
	mu sync.Mutex
	m  map[string]*enrolEntry
}

func newEnrolStore() *enrolStore { return &enrolStore{m: map[string]*enrolEntry{}} }

func (st *enrolStore) put(token string, e enrolEntry) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	for k, v := range st.m {
		if now.After(v.expires) {
			delete(st.m, k)
		}
	}
	st.m[token] = &e
}

// attempt returns the entry and counts one try; after maxEnrolAttempts tries it is discarded.
func (st *enrolStore) attempt(token string) (enrolEntry, enrolState) {
	st.mu.Lock()
	defer st.mu.Unlock()
	e, ok := st.m[token]
	if !ok || time.Now().After(e.expires) {
		delete(st.m, token)
		return enrolEntry{}, enrolGone
	}
	e.tries++
	if e.tries > maxEnrolAttempts {
		delete(st.m, token)
		return enrolEntry{}, enrolGone
	}
	return *e, enrolOK
}

func (st *enrolStore) drop(token string) {
	st.mu.Lock()
	delete(st.m, token)
	st.mu.Unlock()
}

// limiter counts failed sign-ins per key inside a window.
type limiter struct {
	mu sync.Mutex
	m  map[string]*bucket
}

type bucket struct {
	n       int
	expires time.Time
}

func newLimiter() *limiter { return &limiter{m: map[string]*bucket{}} }

func (l *limiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.m[key]
	if !ok || time.Now().After(b.expires) {
		delete(l.m, key)
		return 0
	}
	return b.n
}

func (l *limiter) add(key string, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > 10000 {
		for k, v := range l.m {
			if now.After(v.expires) {
				delete(l.m, k)
			}
		}
	}
	b, ok := l.m[key]
	if !ok || now.After(b.expires) {
		l.m[key] = &bucket{n: 1, expires: now.Add(window)}
		return
	}
	b.n++
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
