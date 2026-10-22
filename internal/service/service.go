// Package service implements publish synchronisation, version history and rollback.
//
// Invariants:
//   - the repository always comes from OWNER_MAPPINGS (never from a caller);
//   - only the published snapshot (activeVersion) is written to Git, never the draft;
//   - Git writes are guarded by last_commit_id; Git history is never rewritten;
//   - rollback only calls the n8n API (PUT + activate) and never writes to Git; the poller then
//     commits the restored published version as a new commit.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/audit"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/gitlab"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/metrics"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/n8n"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/workflow"
)

// Options configures a Service.
type Options struct {
	N8N              n8n.Client
	Git              gitlab.Store
	Mapper           *Mapper
	Branch           string
	RedactKeys       []string
	MaxCommitRetries int
	MaxHistory       int
	MaxWorkflowBytes int64
	Log              *slog.Logger
	Audit            *audit.Logger
	Metrics          *metrics.Metrics
	Now              func() time.Time
}

// Service is safe for concurrent use.
type Service struct {
	o      Options
	locks  sync.Map // key -> *sync.Mutex (per repository + workflow)
	synced sync.Map // workflowID -> SyncedHead (last successful publish sync)
}

// New returns a Service.
func New(o Options) *Service {
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.MaxCommitRetries <= 0 {
		o.MaxCommitRetries = 3
	}
	if o.MaxHistory <= 0 {
		o.MaxHistory = 500
	}
	if o.MaxWorkflowBytes <= 0 {
		o.MaxWorkflowBytes = 8 << 20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{o: o}
}

// PublishResult is returned by Publish.
type PublishResult struct {
	WorkflowID       string    `json:"workflowId"`
	WorkflowName     string    `json:"workflowName"`
	N8NUser          string    `json:"n8nUser"`
	Repository       string    `json:"repository"`
	FilePath         string    `json:"filePath"`
	Changed          bool      `json:"changed"`
	CommitSHA        *string   `json:"commitSha"`
	PublishedVersion string    `json:"publishedVersion"`
	Operation        string    `json:"operation"`
	Timestamp        time.Time `json:"timestamp"`
}

// VersionInfo is one Git commit of a workflow file.
type VersionInfo struct {
	CommitSHA string    `json:"commitSha"`
	ShortSHA  string    `json:"shortSha"`
	Message   string    `json:"message"`
	Author    string    `json:"author"`
	Timestamp time.Time `json:"timestamp"`
	FilePath  string    `json:"filePath"`
}

// RollbackResult is returned by Rollback.
type RollbackResult struct {
	WorkflowID          string    `json:"workflowId"`
	WorkflowName        string    `json:"workflowName"`
	N8NUser             string    `json:"n8nUser"`
	Repository          string    `json:"repository"`
	FilePath            string    `json:"filePath"`
	RestoredFromCommit  string    `json:"restoredFromCommit"`
	PreviousVersion     string    `json:"previousPublishedVersion"`
	PublishedVersion    string    `json:"publishedVersion"`
	Operation           string    `json:"operation"`
	GitHistoryRewritten bool      `json:"gitHistoryRewritten"`
	Timestamp           time.Time `json:"timestamp"`
}

func (s *Service) lock(repo, id string) func() {
	v, _ := s.locks.LoadOrStore(repo+"\x00"+id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (s *Service) observe(op string, start time.Time, err error) {
	if s.o.Metrics == nil {
		return
	}
	s.o.Metrics.Duration.WithLabelValues(op).Observe(time.Since(start).Seconds())
	if err != nil {
		s.o.Metrics.Errors.WithLabelValues(op, string(KindOf(err))).Inc()
	}
}

func (s *Service) record(ctx context.Context, e audit.Event) {
	if s.o.Audit != nil {
		s.o.Audit.Record(ctx, e)
	}
}

func n8nErr(err error, what string) *Error {
	if errors.Is(err, n8n.ErrNotFound) {
		return newErr(KindNotFound, what+" not found in n8n", nil)
	}
	return newErr(KindUpstream, "n8n API error while reading "+what, err)
}

func gitErr(err error, what string) *Error {
	switch {
	case errors.Is(err, gitlab.ErrNotFound):
		return newErr(KindNotFound, what+" not found in GitLab", nil)
	case errors.Is(err, gitlab.ErrConflict):
		return newErr(KindConflict, "GitLab reported a concurrent modification", err)
	}
	return newErr(KindUpstream, "GitLab API error ("+what+")", err)
}

// fetchOwned loads a workflow from n8n and resolves its configured repository.
func (s *Service) fetchOwned(ctx context.Context, id string) (*n8n.Workflow, Owner, error) {
	if !workflow.ValidID(id) {
		return nil, Owner{}, newErr(KindInvalid, "invalid workflow id", nil)
	}
	wf, err := s.o.N8N.GetWorkflow(ctx, id)
	if err != nil {
		return nil, Owner{}, n8nErr(err, "workflow")
	}
	if wf.ID != id {
		return nil, Owner{}, newErr(KindUpstream, "n8n returned a different workflow id", nil)
	}
	owner, ok := s.o.Mapper.Resolve(wf)
	if !ok {
		return wf, owner, newErr(KindUnmapped, fmt.Sprintf("owner unmapped (owner project %q is not in OWNER_MAPPINGS)", owner.Project), nil)
	}
	if !s.o.Mapper.AllowedRepository(owner.Repository) {
		return wf, owner, newErr(KindUnmapped, "resolved repository is not in the allow-list", nil)
	}
	return wf, owner, nil
}

// Publish synchronises the published (active) version of workflow id to Git.
// It is shared by POST /publish and the poller and is idempotent.
func (s *Service) Publish(ctx context.Context, id, trigger string) (res *PublishResult, err error) {
	start := time.Now()
	ev := audit.Event{Operation: "publish", Trigger: trigger, WorkflowID: id}
	defer func() {
		ev.Duration = time.Since(start)
		s.observe("publish", start, err)
		result := "error"
		switch {
		case err == nil && res.Changed:
			result = "changed"
			ev.Result = "success"
		case err == nil:
			result = "unchanged"
			ev.Result = "unchanged"
		case KindOf(err) == KindNotPublished || KindOf(err) == KindUnmapped:
			result = "skipped"
			ev.Result = "skipped"
			ev.Reason = err.Error()
		default:
			ev.Result = "error"
			ev.Reason = err.Error()
		}
		if s.o.Metrics != nil {
			s.o.Metrics.Publish.WithLabelValues(result).Inc()
		}
		if res != nil {
			ev.Changed = &res.Changed
			if res.CommitSHA != nil {
				ev.CommitSHA = *res.CommitSHA
			}
		}
		s.record(ctx, ev)
	}()

	wf, owner, err := s.fetchOwned(ctx, id)
	ev.N8NUser, ev.Repository = owner.N8NUser, owner.Repository
	if err != nil {
		return nil, err
	}
	if wf.IsArchived || wf.ActiveVersion == nil || wf.ActiveVersion.VersionID == "" {
		return nil, newErr(KindNotPublished, "workflow is not published (activeVersion is null); nothing is committed", nil)
	}
	av := wf.ActiveVersion

	// activeVersion carries nodes/connections but not the workflow name. The top-level name is
	// used. GET /workflows/{id}/{versionId} is NOT used for it: on n8n 2.28.6 its `name` is the
	// version label (e.g. "Version 3ae8d960"), not the workflow name (observed 2026-10-20).
	name := wf.Name
	nodes, conns := av.Nodes, av.Connections
	if nodes == nil {
		return nil, newErr(KindUpstream, "n8n activeVersion has no nodes", nil)
	}
	def, err := workflow.BuildDefinition(workflow.Source{
		ID: id, Name: name, Nodes: nodes, Connections: conns,
		NodeGroups: av.NodeGroups, Settings: wf.Settings, Meta: wf.Meta, Tags: wf.Tags,
	}, s.o.RedactKeys)
	if err != nil {
		return nil, newErr(KindInvalidData, "cannot build workflow definition", err)
	}
	content, err := workflow.Canonical(def)
	if err != nil {
		return nil, newErr(KindInvalidData, "cannot serialise workflow", err)
	}
	if int64(len(content)) > s.o.MaxWorkflowBytes {
		return nil, newErr(KindInvalidData, "workflow JSON exceeds MAX_WORKFLOW_BYTES", nil)
	}

	path := workflow.FileName(id)
	res = &PublishResult{
		WorkflowID: id, WorkflowName: name, N8NUser: owner.N8NUser, Repository: owner.Repository,
		FilePath: path, PublishedVersion: av.VersionID, Operation: "publish",
	}
	unlock := s.lock(owner.Repository, id)
	defer unlock()

	verName, verDesc := s.versionMeta(ctx, id, av.VersionID)
	msg := commitMessage(name, id, verName, verDesc, av.VersionID)
	prev, hadPrev := s.SyncedHead(id)
	republished := !hadPrev || prev.PublishedVersionID != av.VersionID
	for attempt := 1; attempt <= s.o.MaxCommitRetries; attempt++ {
		head := ""
		file, gerr := s.o.Git.GetFile(ctx, owner.Repository, path, s.o.Branch)
		switch {
		case gerr == nil:
			head = file.LastCommitID
			if workflow.Equal(file.Content, content) {
				sha := head
				res.CommitSHA = &sha
				res.Timestamp = s.o.Now().UTC()
				s.synced.Store(id, SyncedHead{PublishedVersionID: av.VersionID, CommitSHA: sha})
				if republished && hadPrev && verDesc != "" {
					s.comment(ctx, owner.Repository, sha, id, republishNote(verName, verDesc))
				}
				return res, nil
			}
		case errors.Is(gerr, gitlab.ErrNotFound):
		default:
			return nil, gitErr(gerr, "read file at HEAD")
		}
		commitMsg, formatOnly := msg, gerr == nil && workflow.SameContent(file.Content, def)
		if formatOnly {
			// Only the way the file is written changed (formatVersion bump): label it so.
			commitMsg = commitMessage(name, id, verName, workflow.MigrationDescription(), av.VersionID)
		}
		sha, werr := s.o.Git.WriteFile(ctx, owner.Repository, s.o.Branch, path, content, commitMsg, head)
		if werr == nil {
			res.Changed = true
			res.CommitSHA = &sha
			res.Timestamp = s.o.Now().UTC()
			s.synced.Store(id, SyncedHead{PublishedVersionID: av.VersionID, CommitSHA: sha})
			if verDesc != "" && !formatOnly {
				s.comment(ctx, owner.Repository, sha, id, publishNote(verName, verDesc))
			}
			return res, nil
		}
		if !errors.Is(werr, gitlab.ErrConflict) {
			return nil, gitErr(werr, "commit")
		}
		if s.o.Log != nil {
			s.o.Log.WarnContext(ctx, "git conflict, re-reading HEAD", "workflow_id", id, "repository", owner.Repository, "attempt", attempt)
		}
	}
	return nil, newErr(KindConflict, "GitLab kept reporting concurrent modifications; nothing was overwritten", nil)
}

// VersionTrailer is the commit-body trailer that records which n8n version (activeVersion.versionId)
// a commit holds. It lets the n8n history panel match Git commits to n8n versions.
const VersionTrailer = "N8n-Version-Id"

// TrailerVersionID extracts the N8n-Version-Id trailer from a full commit message ("" if absent).
func TrailerVersionID(message string) string {
	for _, line := range strings.Split(message, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), VersionTrailer+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// VersionNameTrailer records the version name given in n8n's Publish dialog.
const VersionNameTrailer = "N8n-Version-Name"

// WorkflowTrailer records the n8n workflow id (the file is <id>.json; the subject is only the name).
const WorkflowTrailer = "N8n-Workflow-Id"

// commitMessage builds "<workflow name>", then the Publish description (if any), then the trailers
// N8n-Version-Name, N8n-Version-Id and N8n-Workflow-Id.
func commitMessage(name, id, versionName, description, versionID string) string {
	name = oneLine(name, 120)
	if name == "" {
		name = id
	}
	var b strings.Builder
	b.WriteString(name)
	if d := strings.TrimSpace(description); d != "" {
		if r := []rune(d); len(r) > 4000 {
			d = string(r[:4000]) + "..."
		}
		b.WriteString("\n\n" + d)
	}
	b.WriteString("\n")
	if vn := oneLine(versionName, 200); vn != "" {
		b.WriteString("\n" + VersionNameTrailer + ": " + vn)
	}
	b.WriteString("\n" + VersionTrailer + ": " + versionID)
	b.WriteString("\n" + WorkflowTrailer + ": " + id)
	return b.String()
}

func oneLine(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "..."
	}
	return s
}

// versionMeta reads the name and description given in n8n's Publish dialog for the published
// version. Failures only mean the commit has no description.
func (s *Service) versionMeta(ctx context.Context, id, versionID string) (name, description string) {
	v, err := s.o.N8N.GetVersion(ctx, id, versionID)
	if err != nil {
		if s.o.Log != nil {
			s.o.Log.DebugContext(ctx, "version metadata unavailable", "workflow_id", id, "error", err.Error())
		}
		return "", ""
	}
	return v.Name, v.Description
}

func publishNote(versionName, description string) string {
	return "**Dipublish dari n8n** — " + oneLine(versionName, 200) + "\n\n" + strings.TrimSpace(description)
}

func republishNote(versionName, description string) string {
	return "**Dipublish ulang dari n8n tanpa perubahan isi** — " + oneLine(versionName, 200) + "\n\n" + strings.TrimSpace(description)
}

// comment posts a commit comment; a failure is logged and never fails the publish.
func (s *Service) comment(ctx context.Context, repo, sha, id, note string) {
	if err := s.o.Git.CommentCommit(ctx, repo, sha, note); err != nil && s.o.Log != nil {
		s.o.Log.WarnContext(ctx, "commit comment failed", "workflow_id", id, "repository", repo, "commit_sha", sha, "error", err.Error())
	}
}

// Versions lists the Git history of <id>.json in the owner's repository.
func (s *Service) Versions(ctx context.Context, id string) (out []VersionInfo, err error) {
	start := time.Now()
	defer func() { s.observe("versions", start, err) }()
	_, owner, err := s.fetchOwned(ctx, id)
	if err != nil {
		return nil, err
	}
	commits, err := s.o.Git.FileHistory(ctx, owner.Repository, workflow.FileName(id), s.o.Branch, s.o.MaxHistory)
	if err != nil {
		return nil, gitErr(err, "file history")
	}
	out = make([]VersionInfo, 0, len(commits))
	for _, c := range commits {
		msg := c.Title
		if msg == "" {
			msg = strings.TrimSpace(c.Message)
		}
		out = append(out, VersionInfo{
			CommitSHA: c.ID, ShortSHA: c.ShortID, Message: msg, Author: c.AuthorName,
			Timestamp: c.CreatedAt.UTC(), FilePath: workflow.FileName(id),
		})
	}
	return out, nil
}

// inHistory checks that sha is a commit that touched <id>.json on the branch.
func (s *Service) inHistory(ctx context.Context, repo, id, sha string) error {
	commits, err := s.o.Git.FileHistory(ctx, repo, workflow.FileName(id), s.o.Branch, s.o.MaxHistory)
	if err != nil {
		return gitErr(err, "file history")
	}
	for _, c := range commits {
		if strings.EqualFold(c.ID, sha) {
			return nil
		}
	}
	return newErr(KindNotFound, "commit is not part of this workflow's history", nil)
}

// GetVersion returns <id>.json exactly as stored at commit sha.
func (s *Service) GetVersion(ctx context.Context, id, sha string) (content []byte, err error) {
	start := time.Now()
	defer func() { s.observe("get_version", start, err) }()
	if !workflow.ValidSHA(sha) {
		return nil, newErr(KindInvalid, "commitSha must be exactly 40 hexadecimal characters", nil)
	}
	_, owner, err := s.fetchOwned(ctx, id)
	if err != nil {
		return nil, err
	}
	sha = strings.ToLower(sha)
	if err := s.inHistory(ctx, owner.Repository, id, sha); err != nil {
		return nil, err
	}
	file, err := s.o.Git.GetFile(ctx, owner.Repository, workflow.FileName(id), sha)
	if err != nil {
		return nil, gitErr(err, "file at commit")
	}
	return file.Content, nil
}

// Rollback restores <id>.json@sha into n8n and publishes it. Git is never modified here.
func (s *Service) Rollback(ctx context.Context, id, sha, expectedPublished string) (res *RollbackResult, err error) {
	start := time.Now()
	ev := audit.Event{Operation: "rollback", Trigger: "api", WorkflowID: id, CommitSHA: sha}
	defer func() {
		ev.Duration = time.Since(start)
		s.observe("rollback", start, err)
		result := "success"
		ev.Result = "success"
		if err != nil {
			result, ev.Result, ev.Reason = "error", "error", err.Error()
		}
		if s.o.Metrics != nil {
			s.o.Metrics.Rollback.WithLabelValues(result).Inc()
		}
		s.record(ctx, ev)
	}()

	if !workflow.ValidSHA(sha) {
		return nil, newErr(KindInvalid, "commitSha must be exactly 40 hexadecimal characters", nil)
	}
	if strings.TrimSpace(expectedPublished) == "" {
		return nil, newErr(KindInvalid, "expectedPublishedVersion is required (current activeVersion.versionId)", nil)
	}
	sha = strings.ToLower(sha)

	wf, owner, err := s.fetchOwned(ctx, id)
	ev.N8NUser, ev.Repository = owner.N8NUser, owner.Repository
	if err != nil {
		return nil, err
	}
	unlock := s.lock(owner.Repository, id)
	defer unlock()

	current := ""
	if wf.ActiveVersion != nil {
		current = wf.ActiveVersion.VersionID
	}
	if current != expectedPublished {
		return nil, newErr(KindConflict, fmt.Sprintf("published version changed (expected %q, current %q)", expectedPublished, current), nil)
	}
	if err := s.inHistory(ctx, owner.Repository, id, sha); err != nil {
		return nil, err
	}
	file, err := s.o.Git.GetFile(ctx, owner.Repository, workflow.FileName(id), sha)
	if err != nil {
		return nil, gitErr(err, "file at commit")
	}
	def, err := workflow.DecodeObject(file.Content)
	if err != nil {
		return nil, newErr(KindInvalidData, "historical workflow JSON is malformed", err)
	}
	if err := workflow.Validate(def, id); err != nil {
		return nil, newErr(KindInvalidData, "historical workflow JSON is invalid", err)
	}
	body, err := workflow.RestoreBody(def, wf.Raw)
	if err != nil {
		return nil, newErr(KindInvalidData, "historical workflow cannot be restored safely", err)
	}

	// From here on n8n is modified. Git stays untouched in every outcome.
	updated, err := s.o.N8N.UpdateWorkflow(ctx, id, body)
	if err != nil {
		return nil, newErr(KindUpstream, "n8n rejected the restored workflow (PUT)", err)
	}
	newVersion := updated.VersionID
	if newVersion == "" {
		return nil, newErr(KindUpstream, "n8n PUT returned no versionId", nil)
	}
	activated, err := s.o.N8N.ActivateWorkflow(ctx, id, newVersion)
	if err != nil {
		return nil, newErr(KindUpstream, "workflow restored as draft but publishing it failed; publish it in n8n or retry", err)
	}
	published := ""
	if activated.ActiveVersion != nil {
		published = activated.ActiveVersion.VersionID
	}
	if published != newVersion {
		check, cerr := s.o.N8N.GetWorkflow(ctx, id)
		if cerr == nil && check.ActiveVersion != nil {
			published = check.ActiveVersion.VersionID
		}
	}
	if published != newVersion {
		return nil, newErr(KindUpstream, fmt.Sprintf("restored version %q is not the published version (%q)", newVersion, published), nil)
	}
	name, _ := def["name"].(string)
	return &RollbackResult{
		WorkflowID: id, WorkflowName: name, N8NUser: owner.N8NUser, Repository: owner.Repository,
		FilePath: workflow.FileName(id), RestoredFromCommit: sha, PreviousVersion: current,
		PublishedVersion: newVersion, Operation: "rollback", GitHistoryRewritten: false,
		Timestamp: s.o.Now().UTC(),
	}, nil
}
