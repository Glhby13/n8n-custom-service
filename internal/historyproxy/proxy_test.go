package historyproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/service"
)

const (
	goodCookie = "session-good"
	browserID  = "browser-1"
)

var (
	now  = time.Now().UTC()
	shaA = strings.Repeat("a", 40) // trailer v-pub (also native)  -> deduped
	shaB = strings.Repeat("b", 40) // no trailer, 2 days old         -> git-<sha>
	shaC = strings.Repeat("c", 40) // trailer v-old, pruned in n8n   -> v-old
)

// fakeN8N mimics the n8n endpoints the proxy talks to.
type fakeN8N struct {
	mu          sync.Mutex
	authzCalls  int
	passthrough []string
	otherCookie bool
}

func (f *fakeN8N) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, err := r.Cookie("other"); err == nil && c.Value != "" && strings.HasPrefix(r.URL.Path, "/rest/workflows/") {
		f.otherCookie = true
	}
	c, err := r.Cookie("n8n-auth")
	if err != nil || c.Value != goodCookie || r.Header.Get("browser-id") != browserID {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":401,"message":"Unauthorized"}`)
		return
	}
	switch {
	case r.URL.Path == "/rest/workflows/forbidden":
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"code":403,"message":"Forbidden"}`)
	case r.URL.Path == "/rest/workflows/wf1":
		f.authzCalls++
		// draft v-new differs from published v-pub
		_, _ = io.WriteString(w, `{"data":{"id":"wf1","versionId":"v-new","activeVersionId":"v-pub","updatedAt":"`+now.Format(time.RFC3339Nano)+`"}}`)
	case r.URL.Path == "/rest/workflows/wf3":
		f.authzCalls++
		// same content published again: new live id v-live, no draft
		_, _ = io.WriteString(w, `{"data":{"id":"wf3","versionId":"v-live","activeVersionId":"v-live"}}`)
	case strings.HasPrefix(r.URL.Path, "/rest/workflows/"):
		f.authzCalls++
		_, _ = io.WriteString(w, `{"data":{"id":"x","versionId":"same","activeVersion":{"versionId":"same"}}}`)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/version/v-new"):
		_, _ = io.WriteString(w, `{"data":{"versionId":"v-new","nodes":[{"name":"native"}]}}`)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/version/"):
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"code":404,"message":"Version not found"}`)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/publish-timeline"):
		f.passthrough = append(f.passthrough, r.Method+" "+r.URL.Path)
		_, _ = io.WriteString(w, `{"data":[]}`)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, workflowPrefix):
		_, _ = io.WriteString(w, `{"data":[`+
			`{"versionId":"v-new","name":null,"createdAt":"`+now.Add(-time.Minute).Format(time.RFC3339Nano)+`"},`+
			`{"versionId":"v-pub","name":null,"createdAt":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}]}`)
	default:
		f.passthrough = append(f.passthrough, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}
}

type fakeSource struct {
	synced     *service.SyncedHead
	historyErr error
	versionErr error
	calls      int
}

func (s *fakeSource) GitHistory(_ context.Context, id string) (*service.GitVersionedWorkflow, error) {
	if id == "unmapped" {
		return nil, &service.Error{Kind: service.KindUnmapped, Msg: "owner unmapped"}
	}
	if s.historyErr != nil {
		return nil, s.historyErr
	}
	return &service.GitVersionedWorkflow{
		Owner: service.Owner{N8NUser: "admin psa", Repository: "platform/n8n-git-sync/n8n-pluto"},
		Versions: []service.GitVersion{
			{SHA: shaA, ShortSHA: "aaaaaaaa", Subject: "chore(n8n): publish workflow X (wf1)", Time: now.Add(-50 * time.Minute), N8nVersionID: "v-pub"},
			{SHA: shaB, ShortSHA: "bbbbbbbb", Subject: "chore(n8n): publish workflow X (wf1)", Time: now.Add(-48 * time.Hour)},
			{SHA: shaC, ShortSHA: "cccccccc", Subject: "chore(n8n): publish workflow X (wf1)", Time: now.Add(-72 * time.Hour), N8nVersionID: "v-old"},
		},
	}, nil
}

func (s *fakeSource) SyncedHead(string) (service.SyncedHead, bool) {
	if s.synced == nil {
		return service.SyncedHead{}, false
	}
	return *s.synced, true
}

func (s *fakeSource) GitVersionAt(_ context.Context, _ string, sha string) (*service.GitVersionContent, error) {
	s.calls++
	if s.versionErr != nil {
		return nil, s.versionErr
	}
	return &service.GitVersionContent{
		Version: service.GitVersion{SHA: sha, ShortSHA: sha[:8], Subject: "chore(n8n): publish workflow X (wf1)", Time: now.Add(-72 * time.Hour)},
		Owner:   service.Owner{N8NUser: "admin psa"},
		Name:    "X", Nodes: []any{map[string]any{"name": "from-git-" + sha[:4]}},
		Connections: map[string]any{}, NodeGroups: []any{},
	}, nil
}

func setup(t *testing.T) (*fakeN8N, *fakeSource, http.Handler) {
	t.Helper()
	return setupMode(t, ModeMerged)
}

func setupMode(t *testing.T, mode string) (*fakeN8N, *fakeSource, http.Handler) {
	t.Helper()
	n := &fakeN8N{}
	srv := httptest.NewServer(n)
	t.Cleanup(srv.Close)
	src := &fakeSource{}
	h, err := New(Options{N8NBaseURL: srv.URL, Source: src, Timeout: 2 * time.Second, Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	return n, src, h
}

func call(h http.Handler, method, path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: cookie})
		req.AddCookie(&http.Cookie{Name: "other", Value: "do-not-forward"})
		req.Header.Set("browser-id", browserID)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func ids(t *testing.T, body []byte) []string {
	t.Helper()
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("bad JSON %s: %v", body, err)
	}
	var out []string
	for _, it := range resp.Data {
		out = append(out, it["versionId"].(string))
	}
	return out
}

func TestListMergesNativeAndGit(t *testing.T) {
	n, _, h := setup(t)
	rec := call(h, http.MethodGet, workflowPrefix+"wf1?take=20&skip=0", goodCookie)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	got := strings.Join(ids(t, rec.Body.Bytes()), ",")
	want := "v-new,v-pub,git-" + shaB + ",v-old"
	if got != want {
		t.Fatalf("order/dedupe wrong:\n got %s\nwant %s", got, want)
	}
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	g := resp.Data[2]
	if g["name"] != "GitLab bbbbbbbb" || !strings.Contains(g["description"].(string), "Restore lalu Publish") ||
		g["authors"] != "admin psa" || g["workflowId"] != "wf1" || len(g["workflowPublishHistory"].([]any)) != 1 {
		t.Fatalf("git entry shape: %+v", g)
	}
	if resp.Data[1]["name"] != nil {
		t.Fatal("a version present in n8n must be served as the native entry")
	}
	if n.otherCookie {
		t.Fatal("only the n8n session cookie may be forwarded")
	}

	page := call(h, http.MethodGet, workflowPrefix+"wf1?take=2&skip=1", goodCookie)
	if strings.Join(ids(t, page.Body.Bytes()), ",") != "v-pub,git-"+shaB {
		t.Fatalf("paging wrong: %s", page.Body)
	}
	beyond := call(h, http.MethodGet, workflowPrefix+"wf1?take=20&skip=99", goodCookie)
	if len(ids(t, beyond.Body.Bytes())) != 0 {
		t.Fatal("skip beyond end must return empty list")
	}
}

func TestListFailsOpenToNative(t *testing.T) {
	_, src, h := setup(t)
	nativeOnly := "v-new,v-pub"
	if got := strings.Join(ids(t, call(h, http.MethodGet, workflowPrefix+"unmapped", goodCookie).Body.Bytes()), ","); got != nativeOnly {
		t.Fatalf("unmapped workflow must be native only, got %s", got)
	}
	src.historyErr = errors.New("gitlab down")
	if got := strings.Join(ids(t, call(h, http.MethodGet, workflowPrefix+"wf1", goodCookie).Body.Bytes()), ","); got != nativeOnly {
		t.Fatalf("Git failure must fall back to native, got %s", got)
	}
}

func TestUnauthenticatedGetsN8nAnswer(t *testing.T) {
	_, src, h := setup(t)
	for _, p := range []string{workflowPrefix + "wf1", workflowPrefix + "wf1/version/git-" + shaB, workflowPrefix + "wf1/version/v-old"} {
		rec := call(h, http.MethodGet, p, "stolen-or-missing")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if src.calls != 0 {
		t.Fatal("Git content must not be read for an unauthorized session")
	}
	forbidden := call(h, http.MethodGet, workflowPrefix+"forbidden/version/git-"+shaB, goodCookie)
	if forbidden.Code != http.StatusForbidden || src.calls != 0 {
		t.Fatalf("n8n refusal must be returned: %d", forbidden.Code)
	}
}

func TestVersionSources(t *testing.T) {
	n, _, h := setup(t)
	native := call(h, http.MethodGet, workflowPrefix+"wf1/version/v-new", goodCookie)
	if native.Code != 200 || !strings.Contains(native.Body.String(), `"native"`) {
		t.Fatalf("native version: %d %s", native.Code, native.Body)
	}
	git := call(h, http.MethodGet, workflowPrefix+"wf1/version/git-"+shaB, goodCookie)
	if git.Code != 200 || !strings.Contains(git.Body.String(), `"versionId":"git-`+shaB+`"`) || !strings.Contains(git.Body.String(), "from-git-bbbb") {
		t.Fatalf("git version: %d %s", git.Code, git.Body)
	}
	pruned := call(h, http.MethodGet, workflowPrefix+"wf1/version/v-old", goodCookie)
	if pruned.Code != 200 || !strings.Contains(pruned.Body.String(), "from-git-cccc") || !strings.Contains(pruned.Body.String(), `"versionId":"v-old"`) {
		t.Fatalf("pruned version via trailer: %d %s", pruned.Code, pruned.Body)
	}
	unknown := call(h, http.MethodGet, workflowPrefix+"wf1/version/v-nowhere", goodCookie)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown version must stay 404: %d", unknown.Code)
	}
	before := n.authzCalls
	call(h, http.MethodGet, workflowPrefix+"wf1/version/git-"+shaB, goodCookie)
	if n.authzCalls != before {
		t.Fatal("authorization should be cached for the same session")
	}
}

func TestVersionInvalidData(t *testing.T) {
	_, src, h := setup(t)
	src.versionErr = &service.Error{Kind: service.KindInvalidData, Msg: "historical workflow cannot be restored safely", Err: errors.New("redacted values")}
	rec := call(h, http.MethodGet, workflowPrefix+"wf1/version/git-"+shaB, goodCookie)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"message":"GitLab version:`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestOtherEndpointsPassThrough(t *testing.T) {
	n, _, h := setup(t)
	if rec := call(h, http.MethodGet, workflowPrefix+"wf1/publish-timeline", goodCookie); rec.Code != 200 {
		t.Fatalf("publish-timeline: %d", rec.Code)
	}
	if rec := call(h, http.MethodPatch, workflowPrefix+"wf1/versions/v-new", goodCookie); rec.Code != http.StatusNoContent {
		t.Fatalf("rename: %d", rec.Code)
	}
	if len(n.passthrough) != 2 || n.passthrough[1] != "PATCH "+workflowPrefix+"wf1/versions/v-new" {
		t.Fatalf("passthrough: %v", n.passthrough)
	}
	if rec := call(h, http.MethodGet, "/rest/other", goodCookie); rec.Code != http.StatusNotFound {
		t.Fatalf("paths outside the prefix must not be proxied: %d", rec.Code)
	}
}

func TestGitOnlyListsOnlyCommits(t *testing.T) {
	_, src, h := setupMode(t, "")
	rec := call(h, http.MethodGet, workflowPrefix+"wf1?take=20&skip=0", goodCookie)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Draft v-new differs from published v-pub: it is listed first (as n8n does), then Git.
	got := strings.Join(ids(t, rec.Body.Bytes()), ",")
	if got != "v-new,v-pub,git-"+shaB+",v-old" {
		t.Fatalf("git-only list: %s", got)
	}
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data[0]["name"] != "Draft saat ini (belum dipublish)" {
		t.Fatalf("draft entry: %+v", resp.Data[0])
	}
	for _, it := range resp.Data[1:] {
		if !strings.HasPrefix(it["name"].(string), "GitLab ") {
			t.Fatalf("every other entry must be a GitLab commit: %+v", it)
		}
	}
	if rec := call(h, http.MethodGet, workflowPrefix+"wf1", "bad"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated must get n8n's 401: %d", rec.Code)
	}
	if got := strings.Join(ids(t, call(h, http.MethodGet, workflowPrefix+"unmapped", goodCookie).Body.Bytes()), ","); got != "v-new,v-pub" {
		t.Fatalf("unmapped workflow must stay native: %s", got)
	}
	src.historyErr = errors.New("gitlab down")
	if got := strings.Join(ids(t, call(h, http.MethodGet, workflowPrefix+"wf1", goodCookie).Body.Bytes()), ","); got != "v-new,v-pub" {
		t.Fatalf("Git failure must fall back to native: %s", got)
	}
	if _, err := New(Options{N8NBaseURL: "http://x", Mode: "weird"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestGitOnlyNoDraftEntryWhenInSync(t *testing.T) {
	_, _, h := setupMode(t, ModeGitOnly)
	rec := call(h, http.MethodGet, workflowPrefix+"wf2", goodCookie)
	if got := strings.Join(ids(t, rec.Body.Bytes()), ","); got != "v-pub,git-"+shaB+",v-old" {
		t.Fatalf("no draft entry expected when draft == published: %s", got)
	}
}

func TestGitOnlyMarksSyncedHeadAsPublished(t *testing.T) {
	_, src, h := setupMode(t, ModeGitOnly)
	src.synced = &service.SyncedHead{PublishedVersionID: "v-live", CommitSHA: shaA}
	got := strings.Join(ids(t, call(h, http.MethodGet, workflowPrefix+"wf3", goodCookie).Body.Bytes()), ",")
	if got != "v-live,git-"+shaB+",v-old" {
		t.Fatalf("HEAD commit must carry the live version id: %s", got)
	}
	src.synced = &service.SyncedHead{PublishedVersionID: "something-else", CommitSHA: shaA}
	got = strings.Join(ids(t, call(h, http.MethodGet, workflowPrefix+"wf3", goodCookie).Body.Bytes()), ",")
	if got != "v-pub,git-"+shaB+",v-old" {
		t.Fatalf("unrelated sync state must not relabel commits: %s", got)
	}
}

func TestDuplicateTrailerOnlyNewestKeepsVersionID(t *testing.T) {
	hist := &service.GitVersionedWorkflow{
		Owner: service.Owner{N8NUser: "admin psa"},
		Versions: []service.GitVersion{
			{SHA: shaC, ShortSHA: "cccccccc", Subject: "migration", Time: now, N8nVersionID: "v-live"},
			{SHA: shaA, ShortSHA: "aaaaaaaa", Subject: "publish", Time: now.Add(-time.Hour), N8nVersionID: "v-live"},
		},
	}
	items := Merge("wf1", nil, hist)
	if items[0]["versionId"] != "v-live" || items[1]["versionId"] != "git-"+shaA {
		t.Fatalf("ids: %v, %v", items[0]["versionId"], items[1]["versionId"])
	}
	// merged mode with the version still native: newest commit deduped into the native entry
	items = Merge("wf1", []map[string]any{{"versionId": "v-live", "createdAt": now.Format(time.RFC3339Nano)}}, hist)
	if len(items) != 2 || items[0]["versionId"] != "v-live" || items[1]["versionId"] != "git-"+shaA {
		t.Fatalf("merged: %+v", items)
	}
}
