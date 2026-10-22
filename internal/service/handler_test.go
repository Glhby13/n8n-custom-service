package service

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/httpx"
)

const apiToken = "service-token-0123456789"

func newHandler(t *testing.T) (*env, http.Handler, *bytes.Buffer) {
	t.Helper()
	e := newEnv(t)
	var buf bytes.Buffer
	log := httpx.NewLogger(&buf, "debug", "test")
	h := NewHandler(HandlerOptions{Service: e.svc, Log: log, APIToken: apiToken, MaxBodyBytes: 1 << 10,
		RateLimitRPS: 1000, StartedAt: time.Now()})
	return e, h, &buf
}

func do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProbesNeedNoAuth(t *testing.T) {
	_, h, _ := newHandler(t)
	for _, p := range []string{"/healthz", "/readyz"} {
		if rec := do(h, http.MethodGet, p, "", ""); rec.Code != 200 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestAPIRequiresBearerToken(t *testing.T) {
	_, h, _ := newHandler(t)
	for _, tok := range []string{"", "wrong", apiToken + "x", strings.ToUpper(apiToken)} {
		rec := do(h, http.MethodPost, "/api/v1/workflows/123/publish", tok, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: %d", tok, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/123/versions", nil)
	req.Header.Set("Authorization", "Basic "+apiToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("non-bearer scheme accepted: %d", rec.Code)
	}
}

func TestPublishEndpointAndRequestID(t *testing.T) {
	e, h, _ := newHandler(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/123/publish", nil)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("X-Request-ID", "req-abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Header().Get("X-Request-ID") != "req-abc" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var res PublishResult
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if !res.Changed || res.Repository != repoPluto || res.CommitSHA == nil {
		t.Fatalf("%+v", res)
	}
	rec = do(h, http.MethodPost, "/api/v1/workflows/123/publish", apiToken, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Changed {
		t.Fatal("second publish must report changed=false")
	}
}

func TestInputValidationAndErrors(t *testing.T) {
	e, h, _ := newHandler(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	cases := []struct {
		method, path, body string
		want               int
		code               string
	}{
		{http.MethodPost, "/api/v1/workflows/bad.id/publish", "", 400, "invalid_request"},
		{http.MethodGet, "/api/v1/workflows/123/versions/xyz", "", 400, "invalid_request"},
		{http.MethodPost, "/api/v1/workflows/123/publish", "", 409, "not_published"},
		{http.MethodPost, "/api/v1/workflows/123/rollback", `{"commitSha":"x"`, 400, "invalid_request"},
		{http.MethodPost, "/api/v1/workflows/123/rollback", `{"commitSha":"` + strings.Repeat("a", 40) + `","repository":"evil/repo"}`, 400, "invalid_request"},
		{http.MethodPost, "/api/v1/workflows/123/rollback", `{"commitSha":"` + strings.Repeat("a", 40) + `"}`, 400, "invalid_request"},
		{http.MethodPost, "/api/v1/workflows/123/rollback", `{"commitSha":"` + strings.Repeat("a", 2000) + `"}`, 413, ""},
		{http.MethodGet, "/api/v1/unknown", "", 404, "not_found"},
	}
	for _, c := range cases {
		rec := do(h, c.method, c.path, apiToken, c.body)
		if rec.Code != c.want && !(c.want == 413 && rec.Code == 400) {
			t.Errorf("%s %s: got %d want %d (%s)", c.method, c.path, rec.Code, c.want, rec.Body)
			continue
		}
		if c.code != "" && !strings.Contains(rec.Body.String(), `"code":"`+c.code+`"`) {
			t.Errorf("%s %s: body %s", c.method, c.path, rec.Body)
		}
	}
}

func TestSecretsNeverLogged(t *testing.T) {
	e, h, logs := newHandler(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	do(h, http.MethodPost, "/api/v1/workflows/123/publish", apiToken, "")
	do(h, http.MethodPost, "/api/v1/workflows/123/publish", "leaked-wrong-token", "")
	log := httpx.NewLogger(logs, "debug", "test")
	log.Info("x", "authorization", "Bearer "+apiToken, "GITLAB_TOKEN", "glpat-secret", "n8n_api_key", "n8n-secret", slog.String("password", "p"))
	out := logs.String()
	for _, s := range []string{apiToken, "leaked-wrong-token", "glpat-secret", "n8n-secret", `"password":"p"`} {
		if strings.Contains(out, s) {
			t.Fatalf("log leaks %q:\n%s", s, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") || !strings.Contains(out, `"request_id"`) {
		t.Fatalf("expected redaction marker and request_id in logs:\n%s", out)
	}
	if strings.Contains(out, `"value":"v1"`) {
		t.Fatal("workflow content must not be logged")
	}
}
