package service

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/httpx"
)

// Poller detects publishes by watching activeVersion.versionId of every workflow.
// Draft autosaves change only the top-level versionId, so they never trigger a commit.
// State is in memory only; after a restart the first pass reconciles every published
// workflow against Git HEAD (Publish is idempotent, so nothing unchanged is committed).
type Poller struct {
	svc           *Service
	interval      time.Duration
	syncOnStartup bool
	log           *slog.Logger
	maxBackoff    time.Duration

	mu   sync.Mutex
	seen map[string]string // workflowID -> last handled activeVersion.versionId

	status atomic.Pointer[PollStatus]
	pass   atomic.Int64
}

// PollStatus is reported (informationally) on /readyz.
type PollStatus struct {
	LastRun             time.Time `json:"lastRun"`
	LastSuccess         time.Time `json:"lastSuccess"`
	LastError           string    `json:"lastError,omitempty"`
	ConsecutiveFailures int       `json:"consecutiveFailures"`
	Workflows           int       `json:"publishedWorkflows"`
}

// NewPoller creates a poller.
func NewPoller(svc *Service, interval time.Duration, syncOnStartup bool, log *slog.Logger) *Poller {
	p := &Poller{svc: svc, interval: interval, syncOnStartup: syncOnStartup, log: log,
		maxBackoff: 5 * time.Minute, seen: map[string]string{}}
	p.status.Store(&PollStatus{})
	return p
}

// Status returns a snapshot of the last poll.
func (p *Poller) Status() PollStatus { return *p.status.Load() }

// Run polls until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	first := true
	failures := 0
	for {
		err := p.Tick(ctx, first)
		delay := p.interval
		if err != nil {
			failures++
			delay = backoff(p.interval, failures, p.maxBackoff)
		} else {
			failures = 0
			first = false
		}
		// jitter up to 10% so replicas/restarts do not align.
		delay += time.Duration(rand.Int64N(int64(delay)/10 + 1)) //nolint:gosec // G404: scheduling jitter, not security relevant
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func backoff(base time.Duration, failures int, maxDelay time.Duration) time.Duration {
	d := base
	for i := 1; i < failures && d < maxDelay; i++ {
		d *= 2
	}
	if d > maxDelay {
		d = maxDelay
	}
	return d
}

// Tick runs one pass. first=true is the startup pass (reconciliation when syncOnStartup).
func (p *Poller) Tick(ctx context.Context, first bool) error {
	ctx = httpx.WithRequestID(ctx, "poll-"+strconv.FormatInt(p.pass.Add(1), 10))
	st := *p.status.Load()
	st.LastRun = time.Now().UTC()

	list, err := p.svc.o.N8N.ListWorkflows(ctx)
	if err != nil {
		st.LastError = "n8n list failed: " + err.Error()
		st.ConsecutiveFailures++
		p.status.Store(&st)
		p.log.WarnContext(ctx, "poll failed", "error", err)
		return err
	}

	published := 0
	for i := range list {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wf := &list[i]
		if wf.ID == "" || wf.IsArchived {
			p.forget(wf.ID)
			continue
		}
		active := ""
		if wf.ActiveVersion != nil {
			active = wf.ActiveVersion.VersionID
		} else if wf.Active {
			// The list may omit activeVersion; read the detail for published workflows only.
			full, gerr := p.svc.o.N8N.GetWorkflow(ctx, wf.ID)
			if gerr != nil {
				p.log.WarnContext(ctx, "poll: cannot read workflow detail", "workflow_id", wf.ID, "error", gerr)
				continue
			}
			if full.ActiveVersion != nil {
				active = full.ActiveVersion.VersionID
			}
		}
		if active == "" {
			p.forget(wf.ID) // unpublished: never committed; a later publish is detected again
			continue
		}
		published++

		p.mu.Lock()
		prev, known := p.seen[wf.ID]
		p.mu.Unlock()
		if known && prev == active {
			continue
		}
		if !known && first && !p.syncOnStartup {
			p.remember(wf.ID, active)
			continue
		}
		_, serr := p.svc.Publish(ctx, wf.ID, "poller")
		if serr == nil {
			p.remember(wf.ID, active)
			continue
		}
		switch KindOf(serr) {
		case KindUnmapped, KindNotPublished, KindInvalidData, KindNotFound, KindInvalid:
			// Permanent for this version: do not retry every tick; a new publish is retried.
			p.remember(wf.ID, active)
		default:
			// Transient (GitLab/n8n down, conflict): retried on the next tick.
		}
	}
	st.LastSuccess = time.Now().UTC()
	st.LastError = ""
	st.ConsecutiveFailures = 0
	st.Workflows = published
	p.status.Store(&st)
	return nil
}

func (p *Poller) remember(id, version string) {
	p.mu.Lock()
	p.seen[id] = version
	p.mu.Unlock()
}

func (p *Poller) forget(id string) {
	p.mu.Lock()
	delete(p.seen, id)
	p.mu.Unlock()
}
