package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/gitlab"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/n8n"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/workflow"
)

var ctx = context.Background()

func TestPublishCreatesCommitWithSanitisedPublishedVersion(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	e.n8n.edit("123", nodes("draft-not-published"), "Draft Name") // autosave after publish

	res, err := e.svc.Publish(ctx, "123", "api")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.CommitSHA == nil || res.Repository != repoPluto || res.FilePath != "123.json" ||
		res.N8NUser != "admin psa" || res.WorkflowName != "Draft Name" || res.Operation != "publish" {
		t.Fatalf("unexpected result %+v", res)
	}
	h := e.git.history(repoPluto, "123.json")
	if len(h) != 1 || subject(h[0].msg) != "Draft Name" || TrailerVersionID(h[0].msg) == "" || strings.Contains(string(h[0].content), `"name": "Version `) {
		t.Fatalf("history %+v", h)
	}
	s := string(h[0].content)
	if strings.Contains(s, "draft-not-published") || !strings.Contains(s, `"value": "v1"`) {
		t.Fatalf("Git must contain the published snapshot, not the draft:\n%s", s)
	}
	for _, banned := range []string{"pinData", "staticData", "createdAt", "updatedAt", "versionId", "activeVersion", "shared", "isArchived", "triggerCount", `"active"`} {
		if strings.Contains(s, banned) {
			t.Errorf("persisted field %s must be omitted", banned)
		}
	}
	if !strings.HasSuffix(s, "}\n") || !strings.Contains(s, "\n  \"connections\"") {
		t.Error("content is not canonical")
	}
	if len(e.git.history(repoAI, "123.json")) != 0 {
		t.Fatal("wrote to a repository that is not the owner's")
	}
}

func TestPublishIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	first, err := e.svc.Publish(ctx, "123", "api")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := e.svc.Publish(ctx, "123", "api")
		if err != nil {
			t.Fatal(err)
		}
		if again.Changed || again.CommitSHA == nil || *again.CommitSHA != *first.CommitSHA {
			t.Fatalf("second publish must be a no-op: %+v", again)
		}
	}
	if len(e.git.history(repoPluto, "123.json")) != 1 {
		t.Fatal("identical publish created a commit")
	}
}

func TestPublishChangedWorkflowUpdatesSameFile(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	if _, err := e.svc.Publish(ctx, "123", "api"); err != nil {
		t.Fatal(err)
	}
	e.n8n.edit("123", nodes("v2"), "Renamed")
	e.n8n.publish("123")
	res, err := e.svc.Publish(ctx, "123", "api")
	if err != nil || !res.Changed {
		t.Fatalf("%+v %v", res, err)
	}
	h := e.git.history(repoPluto, "123.json")
	if len(h) != 2 || !strings.Contains(string(h[1].content), `"value": "v2"`) || subject(h[1].msg) != "Renamed" {
		t.Fatalf("history %+v", h)
	}
	for k := range e.git.files {
		if !strings.HasSuffix(k, "\x00123.json") {
			t.Fatalf("unexpected file %q (no per-version files allowed)", k)
		}
	}
}

func TestPublishSkipsUnpublishedAndUnmapped(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("draft", "Only draft", "admin psa <admin@btn.co.id>", nodes("x"))
	_, err := e.svc.Publish(ctx, "draft", "api")
	kindIs(t, err, KindNotPublished)

	e.n8n.add("orphan", "Other user", "someone else <x@btn.co.id>", nodes("x"))
	e.n8n.publish("orphan")
	_, err = e.svc.Publish(ctx, "orphan", "api")
	kindIs(t, err, KindUnmapped)
	if !strings.Contains(err.Error(), "owner unmapped") {
		t.Errorf("error must explain owner unmapped: %v", err)
	}
	if e.git.writes != 0 {
		t.Fatal("nothing may be committed for unpublished or unmapped workflows")
	}
	if !strings.Contains(e.logs.String(), "owner unmapped") {
		t.Error("audit log must explain owner unmapped")
	}
}

func TestOwnerMappingVariants(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct{ project, repo string }{
		{"admin psa <admin.psa@btn.co.id>", repoPluto},
		{"Admin  PSA", repoPluto},
		{"gen-ai itpd <gen-ai@btn.co.id>", repoAI},
	} {
		wf := &n8n.Workflow{Shared: []n8n.Shared{{Role: "workflow:owner", Project: n8n.Project{ID: "p", Name: tc.project}}}}
		o, ok := e.svc.o.Mapper.Resolve(wf)
		if !ok || o.Repository != tc.repo {
			t.Errorf("%q -> %+v %v", tc.project, o, ok)
		}
	}
	editorOnly := &n8n.Workflow{Shared: []n8n.Shared{{Role: "workflow:editor", Project: n8n.Project{Name: "admin psa"}}}}
	if _, ok := e.svc.o.Mapper.Resolve(editorOnly); ok {
		t.Error("only the owner may select the repository")
	}
	if e.svc.o.Mapper.AllowedRepository("platform/other") || !e.svc.o.Mapper.AllowedRepository(repoAI) {
		t.Error("allow-list wrong")
	}
}

func TestGitConflictRereadsAndRetries(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	// Someone else commits between our read and our write.
	e.git.beforeWrite = func(g *fakeGit, repo, path string) {
		g.commitLocked(repo, path, []byte(`{"id":"123","name":"other"}`), "manual edit")
	}
	res, err := e.svc.Publish(ctx, "123", "api")
	if err != nil || !res.Changed {
		t.Fatalf("%+v %v", res, err)
	}
	h := e.git.history(repoPluto, "123.json")
	if len(h) != 2 || subject(h[0].msg) != "manual edit" {
		t.Fatalf("the concurrent commit must be preserved, not overwritten: %+v", h)
	}
}

func TestGitConflictGivesUpSafely(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	e.git.conflictAll = true
	_, err := e.svc.Publish(ctx, "123", "api")
	kindIs(t, err, KindConflict)
	if len(e.git.history(repoPluto, "123.json")) != 0 {
		t.Fatal("must not commit after repeated conflicts")
	}
}

func TestPublishGitLabDownDoesNotTouchN8N(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	e.git.readErr = errors.New("connection refused")
	_, err := e.svc.Publish(ctx, "123", "api")
	kindIs(t, err, KindUpstream)
	e.git.readErr = nil
	e.git.writeErr = errors.New("500")
	_, err = e.svc.Publish(ctx, "123", "api")
	kindIs(t, err, KindUpstream)
	if len(e.n8n.puts) != 0 || len(e.n8n.activations) != 0 {
		t.Fatal("publish must never modify n8n")
	}
}

func TestConcurrentPublishCreatesOneCommit(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.Publish(ctx, "123", "api"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := len(e.git.history(repoPluto, "123.json")); n != 1 {
		t.Fatalf("expected 1 commit, got %d", n)
	}
}

func TestVersionsAndGetVersion(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	a, _ := e.svc.Publish(ctx, "123", "api")
	e.n8n.edit("123", nodes("v2"), "")
	e.n8n.publish("123")
	b, _ := e.svc.Publish(ctx, "123", "api")

	vs, err := e.svc.Versions(ctx, "123")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].CommitSHA != *b.CommitSHA || vs[1].CommitSHA != *a.CommitSHA || vs[0].ShortSHA == "" ||
		vs[0].Author != "n8n-git-sync" || vs[0].FilePath != "123.json" {
		t.Fatalf("%+v", vs)
	}
	content, err := e.svc.GetVersion(ctx, "123", *a.CommitSHA)
	if err != nil || !strings.Contains(string(content), `"value": "v1"`) {
		t.Fatalf("historical content wrong: %v\n%s", err, content)
	}
	_, err = e.svc.GetVersion(ctx, "123", "abc")
	kindIs(t, err, KindInvalid)
	_, err = e.svc.GetVersion(ctx, "123", strings.Repeat("0", 40))
	kindIs(t, err, KindNotFound)
	_, err = e.svc.Versions(ctx, "../etc")
	kindIs(t, err, KindInvalid)
	_, err = e.svc.Versions(ctx, "nope")
	kindIs(t, err, KindNotFound)
}

// The full scenario from the spec: A -> B -> C, rollback to B, poller commits D = B.
func TestRollbackKeepsHistoryAndPollerCommitsD(t *testing.T) {
	e := newEnv(t)
	p := NewPoller(e.svc, 0, true, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("A"))
	e.n8n.publish("123")
	mustTick(t, p, true)
	for _, label := range []string{"B", "C"} {
		e.n8n.edit("123", nodes(label), "")
		e.n8n.publish("123")
		mustTick(t, p, false)
	}
	h := e.git.history(repoPluto, "123.json")
	if len(h) != 3 {
		t.Fatalf("want A,B,C got %d commits", len(h))
	}
	shaB := h[1].sha
	gitWritesBefore := e.git.writes

	wf, _ := e.n8n.GetWorkflow(ctx, "123")
	res, err := e.svc.Rollback(ctx, "123", strings.ToUpper(shaB), wf.ActiveVersion.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if res.GitHistoryRewritten || res.RestoredFromCommit != shaB || res.Operation != "rollback" || res.Repository != repoPluto {
		t.Fatalf("%+v", res)
	}
	if e.git.writes != gitWritesBefore {
		t.Fatal("rollback itself must not write to Git")
	}
	if len(e.n8n.puts) != 1 || len(e.n8n.activations) != 1 || e.n8n.activations[0] != res.PublishedVersion {
		t.Fatalf("expected PUT then activate(versionId): puts=%d activations=%v", len(e.n8n.puts), e.n8n.activations)
	}
	put := e.n8n.puts[0]
	if len(put) != 4 || put["name"] != "Example" {
		t.Fatalf("PUT body must only contain name/nodes/connections/settings: %v", put)
	}
	now, _ := e.n8n.GetWorkflow(ctx, "123")
	if now.ActiveVersion.VersionID != res.PublishedVersion {
		t.Fatal("restored version is not published")
	}

	mustTick(t, p, false) // poller sees the new published version
	h = e.git.history(repoPluto, "123.json")
	if len(h) != 4 {
		t.Fatalf("want A,B,C,D got %d", len(h))
	}
	if !workflow.Equal(h[3].content, h[1].content) {
		t.Fatalf("D must equal B:\n%s\n---\n%s", h[3].content, h[1].content)
	}
	for i, label := range []string{"A", "B", "C"} {
		if !strings.Contains(string(h[i].content), `"value": "`+label+`"`) {
			t.Fatalf("history rewritten at %d", i)
		}
	}
}

func mustTick(t *testing.T, p *Poller, first bool) {
	t.Helper()
	if err := p.Tick(ctx, first); err != nil {
		t.Fatal(err)
	}
}

func setupRollback(t *testing.T) (*env, string, string) {
	t.Helper()
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("A"))
	e.n8n.publish("123")
	a, err := e.svc.Publish(ctx, "123", "api")
	if err != nil {
		t.Fatal(err)
	}
	wf, _ := e.n8n.GetWorkflow(ctx, "123")
	return e, *a.CommitSHA, wf.ActiveVersion.VersionID
}

func TestRollbackOptimisticConcurrency(t *testing.T) {
	e, sha, _ := setupRollback(t)
	_, err := e.svc.Rollback(ctx, "123", sha, "stale-version")
	kindIs(t, err, KindConflict)
	_, err = e.svc.Rollback(ctx, "123", sha, "")
	kindIs(t, err, KindInvalid)
	if len(e.n8n.puts) != 0 {
		t.Fatal("n8n modified despite failed precondition")
	}
}

func TestRollbackValidation(t *testing.T) {
	e, sha, cur := setupRollback(t)
	_, err := e.svc.Rollback(ctx, "123", "not-a-sha", cur)
	kindIs(t, err, KindInvalid)
	_, err = e.svc.Rollback(ctx, "bad/id", sha, cur)
	kindIs(t, err, KindInvalid)
	_, err = e.svc.Rollback(ctx, "123", strings.Repeat("f", 40), cur)
	kindIs(t, err, KindNotFound)

	// malformed JSON committed by someone else
	e.git.mu.Lock()
	bad := e.git.commitLocked(repoPluto, "123.json", []byte(`{"id":"123", broken`), "broken")
	mismatch := e.git.commitLocked(repoPluto, "123.json", []byte(`{"id":"999","name":"x","nodes":[],"connections":{}}`), "other id")
	e.git.mu.Unlock()
	_, err = e.svc.Rollback(ctx, "123", bad, cur)
	kindIs(t, err, KindInvalidData)
	_, err = e.svc.Rollback(ctx, "123", mismatch, cur)
	kindIs(t, err, KindInvalidData)
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("want id mismatch, got %v", err)
	}
	if len(e.n8n.puts) != 0 {
		t.Fatal("invalid rollback modified n8n")
	}
}

func TestRollbackN8NFailureLeavesGitUntouched(t *testing.T) {
	e, sha, cur := setupRollback(t)
	writes := e.git.writes
	e.n8n.putErr = &n8n.APIError{Status: 500, Body: "boom"}
	_, err := e.svc.Rollback(ctx, "123", sha, cur)
	kindIs(t, err, KindUpstream)
	e.n8n.putErr = nil
	e.n8n.getErr = errors.New("n8n down")
	_, err = e.svc.Rollback(ctx, "123", sha, cur)
	kindIs(t, err, KindUpstream)
	if e.git.writes != writes {
		t.Fatal("Git modified during failed rollback")
	}
}

func TestRollbackUnmappedOwnerRejected(t *testing.T) {
	e, sha, cur := setupRollback(t)
	e.n8n.mu.Lock()
	e.n8n.wfs["123"]["shared"] = []any{map[string]any{"role": "workflow:owner", "project": map[string]any{"id": "x", "name": "intruder"}}}
	e.n8n.mu.Unlock()
	_, err := e.svc.Rollback(ctx, "123", sha, cur)
	kindIs(t, err, KindUnmapped)
}

func TestErrorStatusMapping(t *testing.T) {
	for kind, want := range map[Kind]int{KindInvalid: 400, KindNotFound: 404, KindNotPublished: 409, KindConflict: 409, KindUnmapped: 422, KindInvalidData: 422, KindUpstream: 502} {
		if got := (&Error{Kind: kind}).Status(); got != want {
			t.Errorf("%s: %d", kind, got)
		}
	}
	if KindOf(gitlab.ErrConflict) != KindUpstream {
		t.Error("foreign errors map to upstream")
	}
}

func TestGitHistoryAndVersionForEditor(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("A"))
	e.n8n.publish("123")
	a, err := e.svc.Publish(ctx, "123", "api")
	if err != nil {
		t.Fatal(err)
	}
	e.n8n.edit("123", nodes("B"), "")
	e.n8n.publish("123")
	if _, err := e.svc.Publish(ctx, "123", "api"); err != nil {
		t.Fatal(err)
	}
	h, err := e.svc.GitHistory(ctx, "123")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Versions) != 2 || h.Owner.Repository != repoPluto || h.Versions[1].SHA != *a.CommitSHA || h.Versions[1].N8nVersionID != a.PublishedVersion {
		t.Fatalf("history %+v", h)
	}
	if got := h.FindGitVersion(a.PublishedVersion); got == nil || got.SHA != *a.CommitSHA {
		t.Fatal("trailer lookup failed")
	}
	c, err := e.svc.GitVersionAt(ctx, "123", *a.CommitSHA)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "Example" || len(c.Nodes) != 2 || c.NodeGroups == nil {
		t.Fatalf("content %+v", c)
	}
	if c.Nodes[1].(map[string]any)["parameters"].(map[string]any)["value"] != "A" {
		t.Fatal("wrong version content")
	}
	_, err = e.svc.GitVersionAt(ctx, "123", strings.Repeat("0", 40))
	kindIs(t, err, KindNotFound)
	_, err = e.svc.GitVersionAt(ctx, "123", "nope")
	kindIs(t, err, KindInvalid)
	_, err = e.svc.GitHistory(ctx, "missing")
	kindIs(t, err, KindNotFound)
}

func TestTrailerParsing(t *testing.T) {
	if TrailerVersionID("subject\n\nN8n-Version-Id: abc-123\n") != "abc-123" || TrailerVersionID("subject only") != "" {
		t.Fatal("trailer parsing")
	}
}

func TestSyncedHeadRecordedOnUnchangedPublish(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("A"))
	e.n8n.publish("123")
	first, _ := e.svc.Publish(ctx, "123", "api")
	// same content published again -> new n8n version id, no new commit
	e.n8n.edit("123", nodes("A"), "")
	e.n8n.publish("123")
	again, err := e.svc.Publish(ctx, "123", "api")
	if err != nil || again.Changed {
		t.Fatalf("%+v %v", again, err)
	}
	head, ok := e.svc.SyncedHead("123")
	if !ok || head.PublishedVersionID != again.PublishedVersion || head.CommitSHA != *first.CommitSHA {
		t.Fatalf("synced head %+v", head)
	}
}

func TestPublishDescriptionInCommitAndComment(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("A"))
	e.n8n.publishWith("123", "Rilis Oktober", "Tambah node email\nperbaiki komentar")
	res, err := e.svc.Publish(ctx, "123", "poller")
	if err != nil || !res.Changed {
		t.Fatalf("%+v %v", res, err)
	}
	msg := e.git.history(repoPluto, "123.json")[0].msg
	for _, want := range []string{"Example\n\nTambah node email\nperbaiki komentar\n\nN8n-Version-Name: Rilis Oktober\nN8n-Version-Id: "} {
		if !strings.HasPrefix(msg, want) {
			t.Fatalf("commit message:\n%s", msg)
		}
	}
	if len(e.git.comments) != 1 || !strings.HasPrefix(e.git.comments[0], *res.CommitSHA+"|") || !strings.Contains(e.git.comments[0], "Tambah node email") {
		t.Fatalf("comment: %v", e.git.comments)
	}
	h, _ := e.svc.GitHistory(ctx, "123")
	if h.Versions[0].Description != "Tambah node email\nperbaiki komentar" {
		t.Fatalf("description parsed from commit: %q", h.Versions[0].Description)
	}

	// Same content published again with a description: no commit, one comment on HEAD.
	e.n8n.edit("123", nodes("A"), "")
	e.n8n.publishWith("123", "Rilis ulang", "Kembali ke versi ini")
	again, err := e.svc.Publish(ctx, "123", "poller")
	if err != nil || again.Changed {
		t.Fatalf("%+v %v", again, err)
	}
	if _, err := e.svc.Publish(ctx, "123", "api"); err != nil { // repeated sync: no duplicate comment
		t.Fatal(err)
	}
	if len(e.git.history(repoPluto, "123.json")) != 1 || len(e.git.comments) != 2 || !strings.Contains(e.git.comments[1], "tanpa perubahan isi") {
		t.Fatalf("republish comments: %v", e.git.comments)
	}
}

func TestPublishWithoutDescriptionAndCommentFailure(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("A"))
	e.n8n.publish("123")
	e.git.commentErr = errors.New("notes API down")
	res, err := e.svc.Publish(ctx, "123", "poller")
	if err != nil || !res.Changed {
		t.Fatalf("comment problems must never fail a publish: %+v %v", res, err)
	}
	msg := e.git.history(repoPluto, "123.json")[0].msg
	if !strings.HasPrefix(msg, "Example\n\nN8n-Version-Name: Version ") || !strings.HasSuffix(msg, "\nN8n-Workflow-Id: 123") || len(e.git.comments) != 0 {
		t.Fatalf("message without description:\n%s", msg)
	}
}

func TestFormatMigrationCommit(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("A"))
	e.n8n.publishWith("123", "Rilis", "deskripsi publish lama")
	// Simulate a file written by an older service version (no formatVersion), same content.
	first, _ := e.svc.Publish(ctx, "123", "poller")
	h := e.git.history(repoPluto, "123.json")
	stored, _ := workflow.DecodeObject(h[0].content)
	delete(stored, workflow.FormatKey)
	oldBytes, _ := workflow.Canonical(stored)
	e.git.mu.Lock()
	e.git.commitLocked(repoPluto, "123.json", oldBytes, "chore(n8n): publish workflow Example (123)")
	e.git.mu.Unlock()
	comments := len(e.git.comments)

	res, err := e.svc.Publish(ctx, "123", "poller") // e.g. startup reconciliation after a bump
	if err != nil || !res.Changed || *res.CommitSHA == *first.CommitSHA {
		t.Fatalf("%+v %v", res, err)
	}
	h = e.git.history(repoPluto, "123.json")
	msg := h[len(h)-1].msg
	if !strings.HasPrefix(msg, "Example\n\nFormat file diperbarui ke formatVersion 2") || strings.Contains(msg, "deskripsi publish lama") {
		t.Fatalf("migration commit message:\n%s", msg)
	}
	if len(e.git.comments) != comments {
		t.Fatal("a format migration must not post a Publish comment")
	}
	again, _ := e.svc.Publish(ctx, "123", "poller")
	if again.Changed {
		t.Fatal("migration must happen only once")
	}
}
