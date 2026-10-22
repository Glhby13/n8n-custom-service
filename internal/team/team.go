package team

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Team defines a collaboration team of n8n users.
type Team struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Members []string `json:"members"` // list of user emails
}

// ParseTeams parses a JSON array of Team definitions.
func ParseTeams(raw string) ([]Team, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil, nil
	}
	var teams []Team
	if err := json.Unmarshal([]byte(raw), &teams); err != nil {
		return nil, fmt.Errorf("invalid TEAMS json: %w", err)
	}
	for i, t := range teams {
		if t.ID == "" {
			return nil, fmt.Errorf("team at index %d missing id", i)
		}
		if len(t.Members) == 0 {
			return nil, fmt.Errorf("team %q has no members", t.ID)
		}
		for j, m := range t.Members {
			teams[i].Members[j] = strings.ToLower(strings.TrimSpace(m))
		}
	}
	return teams, nil
}

// Options configures the team Reconciler.
type Options struct {
	DBURL    string
	Teams    []Team
	Interval time.Duration
	Log      *slog.Logger
}

// Reconciler synchronises workflow sharing between team members in n8n's database.
type Reconciler struct {
	pool     *pgxpool.Pool
	teams    []Team
	interval time.Duration
	log      *slog.Logger
	mu       sync.Mutex
}

// New creates a new Reconciler. If DBURL is empty or teams are empty, returns nil.
func New(ctx context.Context, opts Options) (*Reconciler, error) {
	if strings.TrimSpace(opts.DBURL) == "" || len(opts.Teams) == 0 {
		return nil, nil
	}
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	cfg, err := pgxpool.ParseConfig(opts.DBURL)
	if err != nil {
		return nil, fmt.Errorf("parse team db url: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MinConns = 1

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect team db: %w", err)
	}

	return &Reconciler{
		pool:     pool,
		teams:    opts.Teams,
		interval: opts.Interval,
		log:      opts.Log.With("component", "team-reconciler"),
	}, nil
}

// Close closes the database pool.
func (r *Reconciler) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}

// Run executes the reconcile loop until context cancellation.
func (r *Reconciler) Run(ctx context.Context) {
	if r == nil {
		return
	}
	r.log.Info("team reconciler started", "teams_count", len(r.teams), "interval", r.interval.String())

	// Run once immediately
	if err := r.Reconcile(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.log.Warn("initial team reconcile failed", "err", err)
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.log.Info("team reconciler stopped")
			return
		case <-ticker.C:
			if err := r.Reconcile(ctx); err != nil && !errors.Is(err, context.Canceled) {
				r.log.Warn("team reconcile error", "err", err)
			}
		}
	}
}

// Reconcile executes a single reconciliation run across all configured teams.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Fetch user email -> personal project ID mapping
	const userQuery = `
		SELECT LOWER(u.email), pr."projectId"
		FROM "user" u
		JOIN project_relation pr ON u.id = pr."userId"
		JOIN project p ON pr."projectId" = p.id AND p.type = 'personal'
		WHERE u.disabled = false;
	`
	rows, err := r.pool.Query(ctx, userQuery)
	if err != nil {
		return fmt.Errorf("query user project mapping: %w", err)
	}
	defer rows.Close()

	emailToProject := make(map[string]string)
	for rows.Next() {
		var email, projectID string
		if err := rows.Scan(&email, &projectID); err != nil {
			return fmt.Errorf("scan user project mapping: %w", err)
		}
		emailToProject[email] = projectID
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 2. Process each team
	for _, t := range r.teams {
		var teamProjectIDs []string
		for _, member := range t.Members {
			if pid, ok := emailToProject[member]; ok {
				teamProjectIDs = append(teamProjectIDs, pid)
			} else {
				r.log.Debug("team member not found in n8n users", "team", t.ID, "member", member)
			}
		}

		if len(teamProjectIDs) < 2 {
			// Sharing needs at least 2 active member projects
			continue
		}

		// Find all workflows owned by any of the team members
		const wfQuery = `
			SELECT sw."workflowId", sw."projectId"
			FROM shared_workflow sw
			WHERE sw.role = 'workflow:owner'
			  AND sw."projectId" = ANY($1);
		`
		wfRows, err := r.pool.Query(ctx, wfQuery, teamProjectIDs)
		if err != nil {
			r.log.Warn("query team workflows failed", "team", t.ID, "err", err)
			continue
		}

		type ownedWF struct {
			workflowID string
			ownerPID   string
		}
		var workflows []ownedWF
		for wfRows.Next() {
			var wf ownedWF
			if err := wfRows.Scan(&wf.workflowID, &wf.ownerPID); err != nil {
				wfRows.Close()
				r.log.Warn("scan team workflow failed", "team", t.ID, "err", err)
				break
			}
			workflows = append(workflows, wf)
		}
		wfRows.Close()

		// For each workflow, ensure all OTHER team member projects have role = 'workflow:editor'
		for _, wf := range workflows {
			for _, pid := range teamProjectIDs {
				if pid == wf.ownerPID {
					continue // Owner already has role = 'workflow:owner'
				}

				const shareInsert = `
					INSERT INTO shared_workflow ("workflowId", "projectId", role, "createdAt", "updatedAt")
					VALUES ($1, $2, 'workflow:editor', NOW(), NOW())
					ON CONFLICT ("workflowId", "projectId") DO NOTHING;
				`
				tag, err := r.pool.Exec(ctx, shareInsert, wf.workflowID, pid)
				if err != nil {
					r.log.Warn("failed to share workflow with team member", "team", t.ID, "workflowId", wf.workflowID, "targetProjectId", pid, "err", err)
				} else if tag.RowsAffected() > 0 {
					r.log.Info("shared workflow with team member", "team", t.ID, "workflowId", wf.workflowID, "targetProjectId", pid)
				}
			}
		}
	}

	return nil
}

// FindTeamForUser returns the team that contains the user email, if any.
func FindTeamForUser(teams []Team, email string) *Team {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, t := range teams {
		for _, m := range t.Members {
			if m == email {
				return &t
			}
		}
	}
	return nil
}
