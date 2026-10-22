package service

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // fake commit IDs only
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/audit"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/config"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/gitlab"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/metrics"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/n8n"
)

const (
	repoPluto = "platform/n8n-git-sync/n8n-pluto"
	repoAI    = "platform/n8n-git-sync/n8n-ai"
)

// ---------- fake n8n (behaves like the documented public API) ----------

type fakeN8N struct {
	mu       sync.Mutex
	wfs      map[string]map[string]any
	versions map[string]map[string]any // id/versionId -> snapshot
	seq      int

	nextMeta                             *[2]string // name/description for the next publish
	listErr, getErr, putErr, activateErr error
	puts                                 []map[string]any
	activations                          []string
}

func newFakeN8N() *fakeN8N {
	return &fakeN8N{wfs: map[string]map[string]any{}, versions: map[string]map[string]any{}}
}

// clone round-trips through JSON (numbers as json.Number), like a real HTTP response.
func clone(v any) map[string]any {
	b, _ := json.Marshal(v)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out map[string]any
	_ = dec.Decode(&out)
	return out
}

func (f *fakeN8N) nextVersion() string {
	f.seq++
	return "v" + strconv.Itoa(f.seq)
}

// add creates a workflow owned by projectName with the given nodes (draft only).
func (f *fakeN8N) add(id, name, projectName string, nodes []any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wfs[id] = map[string]any{
		"id": id, "name": name, "active": false, "versionId": f.nextVersion(),
		"nodes": nodes, "connections": map[string]any{}, "settings": map[string]any{"executionOrder": "v1"},
		"pinData":    map[string]any{"HTTP": []any{map[string]any{"json": map[string]any{"sample": "data"}}}},
		"staticData": map[string]any{"lastId": 1}, "isArchived": false, "triggerCount": 1,
		"createdAt": "2026-10-20T00:00:00.000Z", "updatedAt": "2026-10-20T00:00:00.000Z",
		"shared": []any{map[string]any{"role": "workflow:owner", "projectId": "p-" + id,
			"project": map[string]any{"id": "p-" + id, "name": projectName, "type": "personal"}}},
		"tags":          []any{map[string]any{"id": "1", "name": "prod"}},
		"activeVersion": nil,
	}
}

// edit simulates an autosave: new draft versionId, published snapshot untouched.
func (f *fakeN8N) edit(id string, nodes []any, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.wfs[id]
	w["nodes"] = nodes
	if name != "" {
		w["name"] = name
	}
	w["versionId"] = f.nextVersion()
	w["updatedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
}

// publishWith simulates Publish with a version name and "Describe changes" text.
func (f *fakeN8N) publishWith(id, name, desc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextMeta = &[2]string{name, desc}
	f.publishLocked(id)
}

// publish simulates the user clicking Publish: the current draft becomes activeVersion.
func (f *fakeN8N) publish(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishLocked(id)
}

func (f *fakeN8N) publishLocked(id string) {
	w := f.wfs[id]
	vid := w["versionId"].(string)
	snap := map[string]any{"versionId": vid, "workflowId": id, "nodes": w["nodes"], "connections": w["connections"]}
	w["activeVersion"] = snap
	w["active"] = true
	name, desc := "Version "+vid, ""
	if f.nextMeta != nil {
		name, desc = f.nextMeta[0], f.nextMeta[1]
		f.nextMeta = nil
	}
	f.versions[id+"/"+vid] = map[string]any{"versionId": vid, "workflowId": id, "name": name, "description": desc, "nodes": w["nodes"], "connections": w["connections"]}
}

func (f *fakeN8N) ListWorkflows(context.Context) ([]n8n.Workflow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []n8n.Workflow
	for _, w := range f.wfs {
		out = append(out, n8n.ParseWorkflow(clone(w)))
	}
	return out, nil
}

func (f *fakeN8N) GetWorkflow(_ context.Context, id string) (*n8n.Workflow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	w, ok := f.wfs[id]
	if !ok {
		return nil, n8n.ErrNotFound
	}
	p := n8n.ParseWorkflow(clone(w))
	return &p, nil
}

func (f *fakeN8N) GetVersion(_ context.Context, id, vid string) (*n8n.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.versions[id+"/"+vid]
	if !ok {
		return nil, n8n.ErrNotFound
	}
	v = clone(v)
	desc, _ := v["description"].(string)
	return &n8n.Version{VersionID: vid, WorkflowID: id, Name: v["name"].(string), Description: desc, Nodes: v["nodes"], Connections: v["connections"]}, nil
}

var allowedPut = map[string]bool{"name": true, "nodes": true, "connections": true, "settings": true}

func (f *fakeN8N) UpdateWorkflow(_ context.Context, id string, body map[string]any) (*n8n.Workflow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return nil, f.putErr
	}
	for k := range body {
		if !allowedPut[k] {
			return nil, &n8n.APIError{Status: 400, Body: "request/body must NOT have additional properties: " + k}
		}
	}
	w, ok := f.wfs[id]
	if !ok {
		return nil, n8n.ErrNotFound
	}
	f.puts = append(f.puts, clone(body))
	for k, v := range clone(body) {
		w[k] = v
	}
	w["versionId"] = f.nextVersion()
	if w["active"] == true { // documented: a published workflow is re-published on update
		f.publishLocked(id)
	}
	p := n8n.ParseWorkflow(clone(w))
	return &p, nil
}

func (f *fakeN8N) ActivateWorkflow(_ context.Context, id, vid string) (*n8n.Workflow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.activateErr != nil {
		return nil, f.activateErr
	}
	w, ok := f.wfs[id]
	if !ok {
		return nil, n8n.ErrNotFound
	}
	if w["versionId"] != vid {
		return nil, &n8n.APIError{Status: 400, Body: "unknown version"}
	}
	f.activations = append(f.activations, vid)
	f.publishLocked(id)
	p := n8n.ParseWorkflow(clone(w))
	return &p, nil
}

// ---------- fake GitLab (per-file commit list, last_commit_id enforced) ----------

type fakeCommit struct {
	sha     string
	content []byte
	msg     string
}

type fakeGit struct {
	mu          sync.Mutex
	files       map[string][]fakeCommit
	n           int
	readErr     error
	writeErr    error
	beforeWrite func(f *fakeGit, repo, path string) // runs once, simulates a concurrent writer
	conflictAll bool
	writes      int
	comments    []string // "sha|note"
	commentErr  error
}

func (g *fakeGit) CommentCommit(_ context.Context, _, sha, note string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.commentErr != nil {
		return g.commentErr
	}
	g.comments = append(g.comments, sha+"|"+note)
	return nil
}

func newFakeGit() *fakeGit { return &fakeGit{files: map[string][]fakeCommit{}} }

func key(repo, path string) string { return repo + "\x00" + path }

func (g *fakeGit) commitLocked(repo, path string, content []byte, msg string) string {
	g.n++
	sum := sha1.Sum([]byte(fmt.Sprintf("%s/%s/%d", repo, path, g.n))) //nolint:gosec
	sha := hex.EncodeToString(sum[:])
	g.files[key(repo, path)] = append(g.files[key(repo, path)], fakeCommit{sha: sha, content: append([]byte(nil), content...), msg: msg})
	return sha
}

func (g *fakeGit) history(repo, path string) []fakeCommit {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]fakeCommit(nil), g.files[key(repo, path)]...)
}

func (g *fakeGit) GetFile(_ context.Context, repo, path, ref string) (*gitlab.File, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.readErr != nil {
		return nil, g.readErr
	}
	list := g.files[key(repo, path)]
	if len(list) == 0 {
		return nil, gitlab.ErrNotFound
	}
	if ref == "main" {
		last := list[len(list)-1]
		return &gitlab.File{Content: last.content, LastCommitID: last.sha}, nil
	}
	for _, c := range list {
		if c.sha == ref {
			return &gitlab.File{Content: c.content, LastCommitID: c.sha}, nil
		}
	}
	return nil, gitlab.ErrNotFound
}

func (g *fakeGit) FileHistory(_ context.Context, repo, path, _ string, limit int) ([]gitlab.Commit, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.readErr != nil {
		return nil, g.readErr
	}
	list := g.files[key(repo, path)]
	var out []gitlab.Commit
	for i := len(list) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, gitlab.Commit{ID: list[i].sha, ShortID: list[i].sha[:8], Title: subject(list[i].msg), Message: list[i].msg,
			AuthorName: "n8n-git-sync", CreatedAt: time.Date(2026, 10, 20, 0, 0, i, 0, time.UTC)})
	}
	return out, nil
}

func (g *fakeGit) WriteFile(_ context.Context, repo, _, path string, content []byte, msg, last string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if hook := g.beforeWrite; hook != nil {
		g.beforeWrite = nil
		hook(g, repo, path)
	}
	if g.writeErr != nil {
		return "", g.writeErr
	}
	if g.conflictAll {
		return "", fmt.Errorf("%w: forced", gitlab.ErrConflict)
	}
	list := g.files[key(repo, path)]
	head := ""
	if len(list) > 0 {
		head = list[len(list)-1].sha
	}
	if last != head {
		return "", fmt.Errorf("%w: file has changed since you started editing it", gitlab.ErrConflict)
	}
	g.writes++
	return g.commitLocked(repo, path, content, msg), nil
}

// ---------- helpers ----------

type env struct {
	n8n  *fakeN8N
	git  *fakeGit
	svc  *Service
	logs *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(io.MultiWriter(&buf), nil))
	e := &env{n8n: newFakeN8N(), git: newFakeGit(), logs: &buf}
	e.svc = New(Options{
		N8N: e.n8n, Git: e.git, Branch: "main",
		Mapper: NewMapper([]config.Mapping{
			{N8NUser: "admin psa", Repository: repoPluto},
			{N8NUser: "gen-ai itpd", Repository: repoAI},
		}),
		Log: log, Audit: audit.New(log), Metrics: metrics.New(), MaxCommitRetries: 3,
	})
	return e
}

func nodes(label string) []any {
	return []any{
		map[string]any{"id": "n1", "name": "Trigger", "type": "n8n-nodes-base.manualTrigger", "typeVersion": 1, "position": []any{0, 0}, "parameters": map[string]any{}},
		map[string]any{"id": "n2", "name": "Set", "type": "n8n-nodes-base.set", "typeVersion": 3, "position": []any{200, 0},
			"parameters":  map[string]any{"value": label},
			"credentials": map[string]any{"httpBasicAuth": map[string]any{"id": "9", "name": "basic"}}},
	}
}

func kindIs(t *testing.T, err error, want Kind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", want)
	}
	var se *Error
	if !errors.As(err, &se) || se.Kind != want {
		t.Fatalf("expected %s, got %v", want, err)
	}
}

func subject(msg string) string {
	first, _, _ := strings.Cut(msg, "\n")
	return first
}
