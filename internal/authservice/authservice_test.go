package authservice

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestParseJWTClaims(t *testing.T) {
	raw := map[string]any{
		"sub":                "user-1234",
		"email":              "test@lab.local",
		"name":               "Test User",
		"preferred_username": "testuser",
		"resource_access": map[string]any{
			"n8n-lab": map[string]any{
				"roles": []any{"n8n-access"},
			},
		},
	}
	rawBytes, _ := json.Marshal(raw)
	encoded := base64.RawURLEncoding.EncodeToString(rawBytes)
	fakeJWT := "header." + encoded + ".signature"

	claims, err := parseJWTClaims(fakeJWT)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims.Email != "test@lab.local" {
		t.Errorf("expected email test@lab.local, got %s", claims.Email)
	}
	if !claims.HasRole("n8n-access") {
		t.Errorf("expected user to have role n8n-access")
	}
	if claims.HasRole("admin") {
		t.Errorf("expected user not to have role admin")
	}
}

func TestParseJWTClaimsWithAdminRole(t *testing.T) {
	raw := map[string]any{
		"sub":   "admin-5678",
		"email": "lead@lab.local",
		"name":  "Lead Admin",
		"resource_access": map[string]any{
			"n8n-lab": map[string]any{
				"roles": []any{"n8n-access", "n8n-admin"},
			},
		},
	}
	rawBytes, _ := json.Marshal(raw)
	encoded := base64.RawURLEncoding.EncodeToString(rawBytes)
	fakeJWT := "header." + encoded + ".signature"

	claims, err := parseJWTClaims(fakeJWT)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !claims.HasRole("n8n-access") {
		t.Errorf("expected user to have role n8n-access")
	}
	if !claims.HasRole("n8n-admin") {
		t.Errorf("expected user to have role n8n-admin")
	}
}

func TestTokenAuth(t *testing.T) {
	cfg := &Config{
		AdminAPIToken: "SecretToken1234567890#",
		AdminUsername: "admin",
		AdminPassword: "password",
	}
	srv := &Server{cfg: cfg}

	handler := srv.tokenAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// 1. Missing header -> 401
	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/users", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing token, got %d", rr.Code)
	}

	// 2. Invalid Bearer token -> 401
	req = httptest.NewRequest(http.MethodGet, "/admin/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer WrongToken")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", rr.Code)
	}

	// 3. Valid Bearer token -> 200
	req = httptest.NewRequest(http.MethodGet, "/admin/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer SecretToken1234567890#")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid token, got %d", rr.Code)
	}

	// 4. Valid X-Admin-Token -> 200
	req = httptest.NewRequest(http.MethodGet, "/admin/api/v1/users", nil)
	req.Header.Set("X-Admin-Token", "SecretToken1234567890#")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid X-Admin-Token, got %d", rr.Code)
	}
}

func TestConfigLoad(t *testing.T) {
	_ = os.Setenv("DB_HOST", "127.0.0.1")
	_ = os.Setenv("DB_PASSWORD", "secret")
	_ = os.Setenv("PORT", "9090")
	defer func() {
		_ = os.Unsetenv("DB_HOST")
		_ = os.Unsetenv("DB_PASSWORD")
		_ = os.Unsetenv("PORT")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != "9090" {
		t.Errorf("expected port 9090, got %s", cfg.Port)
	}
	if cfg.OIDCClientID != "n8n-lab" {
		t.Errorf("expected client id n8n-lab, got %s", cfg.OIDCClientID)
	}
}
