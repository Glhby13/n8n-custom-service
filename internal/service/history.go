package service

import (
	"context"
	"strings"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/gitlab"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/workflow"
)

// GitVersion is one commit of <id>.json, as shown in the n8n history panel.
type GitVersion struct {
	SHA          string
	ShortSHA     string
	Subject      string
	Author       string
	Owner        string // from N8n-Workflow-Owner trailer
	Publisher    string // from N8n-Workflow-Publisher trailer
	Time         time.Time
	N8nVersionID string // from the N8n-Version-Id trailer; "" for commits written before it existed
	Description  string // commit body without trailers (the Publish description), may be empty
}

// GitVersionedWorkflow is a mapped workflow with its Git history (newest first).
type GitVersionedWorkflow struct {
	Owner    Owner
	Versions []GitVersion
}

// GitHistory returns the Git history of a workflow whose owner is mapped. Errors use the usual
// kinds (KindUnmapped when the owner has no repository, KindNotFound when unknown in n8n).
func (s *Service) GitHistory(ctx context.Context, id string) (*GitVersionedWorkflow, error) {
	_, owner, err := s.fetchOwned(ctx, id)
	if err != nil {
		return nil, err
	}
	commits, err := s.o.Git.FileHistory(ctx, owner.Repository, workflow.FileName(id), s.o.Branch, s.o.MaxHistory)
	if err != nil {
		return nil, gitErr(err, "file history")
	}
	out := &GitVersionedWorkflow{Owner: owner, Versions: make([]GitVersion, 0, len(commits))}
	for _, c := range commits {
		out.Versions = append(out.Versions, toGitVersion(c))
	}
	return out, nil
}

func toGitVersion(c gitlab.Commit) GitVersion {
	subject := c.Title
	if subject == "" {
		subject, _, _ = strings.Cut(strings.TrimSpace(c.Message), "\n")
	}
	short := c.ShortID
	if short == "" && len(c.ID) >= 8 {
		short = c.ID[:8]
	}
	return GitVersion{
		SHA: strings.ToLower(c.ID), ShortSHA: short, Subject: subject, Author: c.AuthorName,
		Owner:        TrailerValue(c.Message, WorkflowOwnerTrailer),
		Publisher:    TrailerValue(c.Message, WorkflowPublisherTrailer),
		Time:         c.CreatedAt.UTC(),
		N8nVersionID: TrailerVersionID(c.Message),
		Description:  commitBody(c.Message),
	}
}

// GitVersionContent is the node graph of a Git version, in the shape n8n's editor restores.
type GitVersionContent struct {
	Version     GitVersion
	Owner       Owner
	Name        string
	Nodes       []any
	Connections any
	NodeGroups  []any
}

// GitVersionAt loads <id>.json at commit sha and converts it for n8n's editor: multi-line text
// joined back, redacted values refilled from the current workflow. The commit must belong to
// the workflow's history; the JSON must be valid and carry the same id.
func (s *Service) GitVersionAt(ctx context.Context, id, sha string) (*GitVersionContent, error) {
	if !workflow.ValidSHA(sha) {
		return nil, newErr(KindInvalid, "commitSha must be exactly 40 hexadecimal characters", nil)
	}
	sha = strings.ToLower(sha)
	wf, owner, err := s.fetchOwned(ctx, id)
	if err != nil {
		return nil, err
	}
	commits, err := s.o.Git.FileHistory(ctx, owner.Repository, workflow.FileName(id), s.o.Branch, s.o.MaxHistory)
	if err != nil {
		return nil, gitErr(err, "file history")
	}
	var meta *GitVersion
	for _, c := range commits {
		if strings.EqualFold(c.ID, sha) {
			v := toGitVersion(c)
			meta = &v
			break
		}
	}
	if meta == nil {
		return nil, newErr(KindNotFound, "commit is not part of this workflow's history", nil)
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
	nodes, conns, groups, err := workflow.VersionPayload(def, wf.Raw)
	if err != nil {
		return nil, newErr(KindInvalidData, "historical workflow cannot be restored safely", err)
	}
	name, _ := def["name"].(string)
	return &GitVersionContent{Version: *meta, Owner: owner, Name: name, Nodes: nodes, Connections: conns, NodeGroups: groups}, nil
}

// FindGitVersion returns the commit whose trailer names n8n version versionID (nil if none).
func (h *GitVersionedWorkflow) FindGitVersion(versionID string) *GitVersion {
	for i := range h.Versions {
		if h.Versions[i].N8nVersionID != "" && h.Versions[i].N8nVersionID == versionID {
			return &h.Versions[i]
		}
	}
	return nil
}

// SyncedHead records that n8n version PublishedVersionID has exactly the content of commit
// CommitSHA (set by every successful publish sync, including "unchanged" ones). Publishing the
// same content again creates a new n8n version id without a new commit; this lets the history
// panel still mark that commit as the published one.
type SyncedHead struct {
	PublishedVersionID string
	CommitSHA          string
}

// SyncedHead returns the last successful sync of workflow id (in memory; rebuilt by the
// startup reconciliation).
func (s *Service) SyncedHead(id string) (SyncedHead, bool) {
	v, ok := s.synced.Load(id)
	if !ok {
		return SyncedHead{}, false
	}
	return v.(SyncedHead), true
}

// commitBody returns the commit message without its subject line and N8n-* trailers.
func commitBody(message string) string {
	_, body, _ := strings.Cut(strings.TrimSpace(message), "\n")
	var keep []string
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "N8n-") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}
