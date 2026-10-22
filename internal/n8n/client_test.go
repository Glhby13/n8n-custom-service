package n8n

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const apiKey = "n8n-test-api-key"

func newTestClient(t *testing.T, h http.HandlerFunc, timeout time.Duration) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewHTTPClient(Options{BaseURL: srv.URL, APIKey: apiKey, Timeout: timeout, PageSize: 2})
}

const wfJSON = `{"id":"123","name":"Draft name","active":true,"versionId":"v-draft","nodes":[{"id":"n1"}],
 "connections":{},"settings":{"executionOrder":"v1"},"tags":[{"id":"1","name":"prod"}],"pinData":{"x":1},
 "shared":[{"role":"workflow:owner","projectId":"p1","project":{"id":"p1","name":"admin psa <admin@btn.co.id>","type":"personal"}}],
 "activeVersion":{"versionId":"v-pub","workflowId":"123","nodes":[{"id":"n1","name":"pub"}],"connections":{"a":1}}}`

func TestListWorkflowsPaginates(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-N8N-API-KEY") != apiKey {
			t.Error("api key header missing")
		}
		q := r.URL.Query()
		if q.Get("excludePinnedData") != "true" || q.Get("limit") != "2" {
			t.Errorf("query %v", q)
		}
		if q.Get("cursor") == "" {
			_, _ = io.WriteString(w, `{"data":[{"id":"1"},{"id":"2"}],"nextCursor":"c2"}`)
			return
		}
		if q.Get("cursor") != "c2" {
			t.Errorf("cursor %s", q.Get("cursor"))
		}
		_, _ = io.WriteString(w, `{"data":[`+wfJSON+`],"nextCursor":null}`)
	}, time.Second)
	list, err := c.ListWorkflows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(list) != 3 {
		t.Fatalf("calls=%d len=%d", calls, len(list))
	}
	w := list[2]
	if w.ActiveVersion == nil || w.ActiveVersion.VersionID != "v-pub" || w.VersionID != "v-draft" {
		t.Fatalf("active/draft not parsed: %+v", w)
	}
	if len(w.Shared) != 1 || w.Shared[0].Project.Name != "admin psa <admin@btn.co.id>" || w.Shared[0].Role != "workflow:owner" {
		t.Fatalf("shared not parsed: %+v", w.Shared)
	}
	if len(w.Tags) != 1 || w.Tags[0] != "prod" || !w.Active {
		t.Fatalf("tags/active: %+v", w)
	}
}

func TestGetWorkflowNotFoundAndErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"unauthorized"}`)
	}, time.Second)
	if _, err := c.GetWorkflow(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	_, err := c.GetWorkflow(context.Background(), "x")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), apiKey) {
		t.Fatal("error leaks API key")
	}
}

func TestUpdateAndActivate(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/workflows/123":
			if body["name"] != "Restored" || body["versionId"] != nil {
				t.Errorf("put body %v", body)
			}
			_, _ = io.WriteString(w, `{"id":"123","versionId":"v-new","active":true}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workflows/123/activate":
			if body["versionId"] != "v-new" {
				t.Errorf("activate body %v", body)
			}
			_, _ = io.WriteString(w, `{"id":"123","versionId":"v-new","activeVersion":{"versionId":"v-new"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workflows/123/v-pub":
			_, _ = io.WriteString(w, `{"versionId":"v-pub","workflowId":"123","name":"Published name","nodes":[],"connections":{},"authors":"1"}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}, time.Second)
	up, err := c.UpdateWorkflow(context.Background(), "123", map[string]any{"name": "Restored"})
	if err != nil || up.VersionID != "v-new" {
		t.Fatalf("%+v %v", up, err)
	}
	act, err := c.ActivateWorkflow(context.Background(), "123", "v-new")
	if err != nil || act.ActiveVersion == nil || act.ActiveVersion.VersionID != "v-new" {
		t.Fatalf("%+v %v", act, err)
	}
	v, err := c.GetVersion(context.Background(), "123", "v-pub")
	if err != nil || v.Name != "Published name" {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestTimeoutAndNoRedirect(t *testing.T) {
	slow := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}, 100*time.Millisecond)
	start := time.Now()
	if _, err := slow.GetWorkflow(context.Background(), "1"); err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout not enforced: %v", err)
	}
	redir := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example/", http.StatusFound)
	}, time.Second)
	_, err := redir.GetWorkflow(context.Background(), "1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusFound {
		t.Fatalf("redirect followed: %v", err)
	}
}
