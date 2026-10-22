package service

import (
	"regexp"
	"strings"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/config"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/n8n"
)

// Owner is the resolved owner of a workflow and its configured repository.
type Owner struct {
	N8NUser    string // the n8nUser value from OWNER_MAPPINGS that matched
	Repository string
	ProjectID  string
	Project    string // n8n owner project name, as reported by the API
}

// Mapper resolves workflow ownership to a repository using server-side configuration only.
// There is no fallback repository and no client-supplied repository.
type Mapper struct {
	byKey map[string]config.Mapping
	repos map[string]bool
}

// NewMapper indexes the configured mappings.
func NewMapper(ms []config.Mapping) *Mapper {
	m := &Mapper{byKey: map[string]config.Mapping{}, repos: map[string]bool{}}
	for _, x := range ms {
		m.byKey[normalizeIdent(x.N8NUser)] = x
		m.repos[x.Repository] = true
	}
	return m
}

// AllowedRepository reports whether repo is one of the configured repositories (allow-list).
func (m *Mapper) AllowedRepository(repo string) bool { return m.repos[repo] }

var emailInName = regexp.MustCompile(`^(.*?)\s*<([^<>]+)>\s*$`)

// ownerCandidates lists the identifiers of the owning project that a mapping may name.
// n8n names a personal project "First Last <email>"; team projects carry their own name.
func ownerCandidates(sh n8n.Shared) []string {
	var c []string
	name := strings.TrimSpace(sh.Project.Name)
	if name != "" {
		c = append(c, name)
		if m := emailInName.FindStringSubmatch(name); m != nil {
			c = append(c, m[1], m[2])
		}
	}
	if sh.Project.ID != "" {
		c = append(c, sh.Project.ID)
	} else if sh.ProjectID != "" {
		c = append(c, sh.ProjectID)
	}
	return c
}

// Resolve finds the owner entry (role workflow:owner) and its mapping.
// ok is false when the workflow has no owner or the owner is not mapped.
func (m *Mapper) Resolve(wf *n8n.Workflow) (Owner, bool) {
	var owner *n8n.Shared
	for i := range wf.Shared {
		if wf.Shared[i].Role == "workflow:owner" {
			owner = &wf.Shared[i]
			break
		}
	}
	if owner == nil {
		return Owner{}, false
	}
	o := Owner{ProjectID: owner.Project.ID, Project: owner.Project.Name}
	if o.ProjectID == "" {
		o.ProjectID = owner.ProjectID
	}
	for _, cand := range ownerCandidates(*owner) {
		if mp, hit := m.byKey[normalizeIdent(cand)]; hit {
			o.N8NUser = mp.N8NUser
			o.Repository = mp.Repository
			return o, true
		}
	}
	return o, false
}

func normalizeIdent(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
