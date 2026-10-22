package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/gitlab"
)

func TestGitHubClient_GetFile(t *testing.T) {
	content := []byte("hello github")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/repos/owner/repo/contents/test.json" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"content":  base64.StdEncoding.EncodeToString(content),
				"encoding": "base64",
				"sha":      "blob-sha-123",
			})
			return
		}
		if r.URL.Path == "/repos/owner/repo/commits" {
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"sha": "commit-sha-456",
					"commit": map[string]any{
						"message": "init",
						"author": map[string]any{
							"name":  "Tester",
							"email": "test@example.com",
							"date":  time.Now().Format(time.RFC3339),
						},
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli, err := New(Options{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	f, err := cli.GetFile(context.Background(), "owner/repo", "test.json", "main")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if string(f.Content) != "hello github" {
		t.Errorf("content: %s", string(f.Content))
	}
	if f.LastCommitID != "commit-sha-456" {
		t.Errorf("LastCommitID: %s", f.LastCommitID)
	}

	// 404 test
	_, err = cli.GetFile(context.Background(), "owner/repo", "missing.json", "main")
	if !errors.Is(err, gitlab.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestGitHubClient_WriteFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Simulate existing file
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": "existing-blob-sha",
			})
			return
		}
		if r.Method == http.MethodPut {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["sha"] != "existing-blob-sha" {
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"commit": map[string]any{
					"sha": "new-commit-sha",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli, err := New(Options{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sha, err := cli.WriteFile(context.Background(), "owner/repo", "main", "test.json", []byte("updated"), "update file", "old-commit")
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if sha != "new-commit-sha" {
		t.Errorf("sha: %s", sha)
	}
}
