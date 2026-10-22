package gitlab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const token = "glpat-test-secret"

func newTestClient(t *testing.T, h http.HandlerFunc, timeout time.Duration) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Options{BaseURL: srv.URL, Token: token, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetFileDecodesAndEncodesPath(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != token {
			t.Errorf("token header missing")
		}
		if got := r.URL.EscapedPath(); got != "/api/v4/projects/platform%2Fn8n-git-sync%2Fn8n-pluto/repository/files/123.json" {
			t.Errorf("path %s", got)
		}
		if r.URL.Query().Get("ref") != "main" {
			t.Errorf("ref %s", r.URL.Query().Get("ref"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content": base64.StdEncoding.EncodeToString([]byte(`{"id":"123"}`)), "encoding": "base64",
			"last_commit_id": "abc", "commit_id": "def",
		})
	}, time.Second)
	f, err := c.GetFile(context.Background(), "platform/n8n-git-sync/n8n-pluto", "123.json", "main")
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Content) != `{"id":"123"}` || f.LastCommitID != "abc" {
		t.Fatalf("%+v", f)
	}
}

func TestNotFound(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"404 File Not Found"}`)
	}, time.Second)
	_, err := c.GetFile(context.Background(), "g/p", "1.json", "main")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestFileHistoryQuery(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("path") != "123.json" || q.Get("ref_name") != "main" {
			t.Errorf("query %v", q)
		}
		_, _ = io.WriteString(w, `[{"id":"`+strings.Repeat("a", 40)+`","short_id":"aaaaaaaa","title":"chore(n8n): publish workflow X (123)","author_name":"n8n-git-sync","created_at":"2026-10-20T10:00:00Z"}]`)
	}, time.Second)
	cs, err := c.FileHistory(context.Background(), "g/p", "123.json", "main", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].AuthorName != "n8n-git-sync" || cs[0].CreatedAt.IsZero() {
		t.Fatalf("%+v", cs)
	}
}

func TestWriteFileCreateAndUpdate(t *testing.T) {
	var bodies []map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.EscapedPath(), "/repository/commits") {
			t.Errorf("%s %s", r.Method, r.URL.EscapedPath())
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		_, _ = io.WriteString(w, `{"id":"`+strings.Repeat("b", 40)+`"}`)
	}, time.Second)
	sha, err := c.WriteFile(context.Background(), "g/p", "main", "1.json", []byte("{}\n"), "msg", "")
	if err != nil || sha != strings.Repeat("b", 40) {
		t.Fatalf("%s %v", sha, err)
	}
	if _, err := c.WriteFile(context.Background(), "g/p", "main", "1.json", []byte("{}\n"), "msg", "head1"); err != nil {
		t.Fatal(err)
	}
	a0 := bodies[0]["actions"].([]any)[0].(map[string]any)
	a1 := bodies[1]["actions"].([]any)[0].(map[string]any)
	if a0["action"] != "create" || a0["last_commit_id"] != nil {
		t.Errorf("create action %v", a0)
	}
	if a1["action"] != "update" || a1["last_commit_id"] != "head1" || bodies[1]["branch"] != "main" {
		t.Errorf("update action %v", a1)
	}
	if bodies[0]["force"] != nil {
		t.Error("must never force")
	}
}

func TestConflictDetection(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{400, `{"message":"You are attempting to update a file that has changed since you started editing it."}`},
		{400, `{"message":"A file with this name already exists"}`},
		{409, `{"message":"conflict"}`},
	} {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}, time.Second)
		_, err := c.WriteFile(context.Background(), "g/p", "main", "1.json", []byte("{}"), "m", "x")
		if !errors.Is(err, ErrConflict) {
			t.Errorf("%d %s: got %v", tc.status, tc.body, err)
		}
	}
}

func TestRedirectNotFollowedAndTokenNotLeaked(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	}, time.Second)
	_, err := c.GetFile(context.Background(), "g/p", "1.json", "main")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusFound {
		t.Fatalf("redirect must not be followed: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("error leaks token")
	}
}

func TestTimeout(t *testing.T) {
	c := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}, 100*time.Millisecond)
	start := time.Now()
	_, err := c.GetFile(context.Background(), "g/p", "1.json", "main")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout not enforced: %v after %s", err, time.Since(start))
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("error leaks token")
	}
}

func TestCAFileValidation(t *testing.T) {
	if _, err := New(Options{BaseURL: "https://x", CAFile: "/nonexistent/ca.pem"}); err == nil {
		t.Error("missing CA file accepted")
	}
	bad := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{BaseURL: "https://x", CAFile: bad}); err == nil {
		t.Error("non-PEM CA file accepted")
	}
}

func TestCommentCommit(t *testing.T) {
	var path, note string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		note = b["note"]
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"note":"x"}`)
	}, time.Second)
	if err := c.CommentCommit(context.Background(), "platform/n8n-git-sync/n8n-pluto", strings.Repeat("a", 40), "hello"); err != nil {
		t.Fatal(err)
	}
	if path != "/api/v4/projects/platform%2Fn8n-git-sync%2Fn8n-pluto/repository/commits/"+strings.Repeat("a", 40)+"/comments" || note != "hello" {
		t.Fatalf("%s %q", path, note)
	}
}
