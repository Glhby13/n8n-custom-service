package service

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func quietPoller(e *env, syncOnStartup bool) *Poller {
	return NewPoller(e.svc, time.Second, syncOnStartup, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

func TestAutosaveDoesNotCommit(t *testing.T) {
	e := newEnv(t)
	p := quietPoller(e, true)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	mustTick(t, p, true)
	if len(e.git.history(repoPluto, "123.json")) != 1 {
		t.Fatal("published workflow not synced")
	}
	for i := 0; i < 5; i++ { // repeated autosaves: draft versionId and updatedAt change
		e.n8n.edit("123", nodes("autosave"), "Autosaved name")
		mustTick(t, p, false)
	}
	if n := len(e.git.history(repoPluto, "123.json")); n != 1 {
		t.Fatalf("autosave created commits: %d", n)
	}
	e.n8n.publish("123") // now the user clicks Publish
	mustTick(t, p, false)
	if n := len(e.git.history(repoPluto, "123.json")); n != 2 {
		t.Fatalf("publish not detected: %d", n)
	}
}

func TestPollerIgnoresInactiveAndUnmapped(t *testing.T) {
	e := newEnv(t)
	p := quietPoller(e, true)
	e.n8n.add("draft", "never published", "admin psa <a@b>", nodes("x"))
	e.n8n.add("orphan", "unmapped", "stranger <s@b>", nodes("x"))
	e.n8n.publish("orphan")
	mustTick(t, p, true)
	mustTick(t, p, false)
	if e.git.writes != 0 {
		t.Fatal("inactive or unmapped workflows must never be committed")
	}
	if p.Status().Workflows != 1 {
		t.Errorf("status %+v", p.Status())
	}
}

func TestRestartReconcilesWithoutDuplicates(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	mustTick(t, quietPoller(e, true), true)

	// "restart": fresh in-memory state, nothing changed -> no new commit.
	mustTick(t, quietPoller(e, true), true)
	if n := len(e.git.history(repoPluto, "123.json")); n != 1 {
		t.Fatalf("restart duplicated commit: %d", n)
	}
	// published while the service was down -> reconciled on startup.
	e.n8n.edit("123", nodes("v2"), "")
	e.n8n.publish("123")
	mustTick(t, quietPoller(e, true), true)
	if n := len(e.git.history(repoPluto, "123.json")); n != 2 {
		t.Fatalf("startup reconciliation missed a publish: %d", n)
	}
}

func TestSyncOnStartupDisabledOnlySeeds(t *testing.T) {
	e := newEnv(t)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	p := quietPoller(e, false)
	mustTick(t, p, true)
	if e.git.writes != 0 {
		t.Fatal("SYNC_ON_STARTUP=false must not commit on the first pass")
	}
	e.n8n.edit("123", nodes("v2"), "")
	e.n8n.publish("123")
	mustTick(t, p, false)
	if e.git.writes != 1 {
		t.Fatal("later publish not detected")
	}
}

func TestPollerRetriesTransientGitErrors(t *testing.T) {
	e := newEnv(t)
	p := quietPoller(e, true)
	e.n8n.add("123", "Example", "admin psa <admin@btn.co.id>", nodes("v1"))
	e.n8n.publish("123")
	e.git.readErr = errors.New("gitlab down")
	mustTick(t, p, true)
	e.git.readErr = nil
	mustTick(t, p, false)
	if n := len(e.git.history(repoPluto, "123.json")); n != 1 {
		t.Fatalf("transient failure not retried: %d", n)
	}
}

func TestPollerListErrorAndBackoff(t *testing.T) {
	e := newEnv(t)
	p := quietPoller(e, true)
	e.n8n.listErr = errors.New("n8n down")
	if err := p.Tick(ctx, true); err == nil {
		t.Fatal("expected error")
	}
	if st := p.Status(); st.ConsecutiveFailures != 1 || st.LastError == "" {
		t.Fatalf("%+v", st)
	}
	if backoff(time.Second, 1, time.Minute) != time.Second || backoff(time.Second, 4, time.Minute) != 8*time.Second ||
		backoff(time.Second, 30, time.Minute) != time.Minute {
		t.Fatal("backoff")
	}
}
