package authservice

import (
	"encoding/base64"
	"encoding/json"
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
