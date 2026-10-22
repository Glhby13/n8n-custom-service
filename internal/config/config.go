// Package config loads and validates the service configuration from environment variables.
// Secrets (GITLAB_TOKEN, N8N_API_KEY, SERVICE_API_TOKEN) are only ever read from env,
// which Kubernetes fills from the n8n-git-service-secret Secret.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/team"
)

// repoPattern is a strict GitLab project path: group[/subgroup...]/project.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$`)

// Mapping binds an n8n workflow owner to exactly one GitLab repository.
type Mapping struct {
	N8NUser    string `json:"n8nUser"`
	Repository string `json:"repository"`
}

// Config is the full runtime configuration.
type Config struct {
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	N8NBaseURL string
	N8NAPIKey  string

	GitProvider   string
	GitLabBaseURL string
	GitLabToken   string
	GitLabBranch  string
	GitLabCAFile  string

	ServiceAPIToken string

	PollEnabled   bool
	PollInterval  time.Duration
	SyncOnStartup bool

	DefaultRepository string
	Mappings          []Mapping
	RedactParamKeys   []string
	MaxBodyBytes      int64
	HTTPTimeout       time.Duration
	RateLimitRPS      float64
	MaxCommitRetries  int
	MaxHistoryCommits int
	MaxWorkflowBytes  int64
	WorkflowPageSize  int

	HistoryProxyEnabled bool
	HistoryProxyMode    string
	N8NAuthCookieName   string

	Teams                 []team.Team
	DBURL                 string
	TeamReconcileInterval time.Duration
}

// Getenv is the lookup function; tests inject their own.
type Getenv func(string) string

// Load reads the configuration through getenv and validates it.
func Load(getenv Getenv) (*Config, error) {
	var errs []error
	str := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	boolean := func(key string, def bool) bool {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: not a boolean", key))
			return def
		}
		return b
	}
	dur := func(key string, def time.Duration) time.Duration {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: not a duration", key))
			return def
		}
		return d
	}
	integer := func(key string, def int64) int64 {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			return def
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: not an integer", key))
			return def
		}
		return n
	}
	float := func(key string, def float64) float64 {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			return def
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: not a number", key))
			return def
		}
		return f
	}

	c := &Config{
		Port:                str("PORT", "8080"),
		LogLevel:            str("LOG_LEVEL", "info"),
		ShutdownTimeout:     time.Duration(integer("SHUTDOWN_TIMEOUT_SECONDS", 20)) * time.Second,
		N8NBaseURL:          strings.TrimRight(str("N8N_BASE_URL", ""), "/"),
		N8NAPIKey:           getenv("N8N_API_KEY"),
		GitProvider:         strings.ToLower(str("GIT_PROVIDER", "")),
		GitLabBaseURL:       strings.TrimRight(str("GITLAB_BASE_URL", ""), "/"),
		GitLabToken:         getenv("GITLAB_TOKEN"),
		GitLabBranch:        str("GITLAB_BRANCH", "main"),
		GitLabCAFile:        str("GITLAB_CA_FILE", ""),
		ServiceAPIToken:     getenv("SERVICE_API_TOKEN"),
		PollEnabled:         boolean("POLL_ENABLED", true),
		PollInterval:        dur("POLL_INTERVAL", 30*time.Second),
		SyncOnStartup:       boolean("SYNC_ON_STARTUP", true),
		MaxBodyBytes:        integer("MAX_BODY_BYTES", 1<<20),
		HTTPTimeout:         dur("HTTP_TIMEOUT", 20*time.Second),
		RateLimitRPS:        float("RATE_LIMIT_RPS", 10),
		MaxCommitRetries:    int(integer("MAX_COMMIT_RETRIES", 3)),
		MaxHistoryCommits:   int(integer("MAX_HISTORY_COMMITS", 500)),
		MaxWorkflowBytes:    integer("MAX_WORKFLOW_BYTES", 8<<20),
		WorkflowPageSize:    int(integer("N8N_PAGE_SIZE", 100)),
		HistoryProxyEnabled: boolean("HISTORY_PROXY_ENABLED", false),
		HistoryProxyMode:    str("HISTORY_PROXY_MODE", "git-only"),
		N8NAuthCookieName:   str("N8N_AUTH_COOKIE_NAME", "n8n-auth"),
	}

	if c.GitProvider == "" {
		if strings.Contains(c.GitLabBaseURL, "github.com") || getenv("GITHUB_TOKEN") != "" || getenv("GIT_TOKEN") != "" {
			c.GitProvider = "github"
		} else {
			c.GitProvider = "gitlab"
		}
	}
	if c.GitLabToken == "" {
		if t := getenv("GITHUB_TOKEN"); t != "" {
			c.GitLabToken = t
		} else if t := getenv("GIT_TOKEN"); t != "" {
			c.GitLabToken = t
		}
	}
	if c.GitProvider == "github" && c.GitLabBaseURL == "" {
		c.GitLabBaseURL = "https://api.github.com"
	}

	c.DefaultRepository = str("DEFAULT_REPOSITORY", str("GIT_REPOSITORY", ""))

	for _, k := range strings.Split(getenv("REDACT_PARAMETER_KEYS"), ",") {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			c.RedactParamKeys = append(c.RedactParamKeys, k)
		}
	}

	if raw := strings.TrimSpace(getenv("OWNER_MAPPINGS")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.Mappings); err != nil {
			errs = append(errs, fmt.Errorf("OWNER_MAPPINGS: invalid JSON: %w", err))
		}
	}

	if rawTeams := strings.TrimSpace(getenv("TEAMS")); rawTeams != "" {
		teams, err := team.ParseTeams(rawTeams)
		if err != nil {
			errs = append(errs, fmt.Errorf("TEAMS: %w", err))
		} else {
			c.Teams = teams
		}
	}

	c.TeamReconcileInterval = time.Duration(integer("TEAM_RECONCILE_INTERVAL_SECONDS", 10)) * time.Second

	dbURL := strings.TrimSpace(getenv("DB_URL"))
	if dbURL == "" {
		dbURL = strings.TrimSpace(getenv("DATABASE_URL"))
	}
	if dbURL == "" {
		dbHost := strings.TrimSpace(getenv("DB_HOST"))
		dbPass := strings.TrimSpace(getenv("DB_PASSWORD"))
		if dbPass == "" {
			dbPass = strings.TrimSpace(getenv("PG_PASSWORD"))
		}
		if dbPass == "" {
			dbPass = strings.TrimSpace(getenv("DB_POSTGRESDB_PASSWORD"))
		}
		if dbHost != "" && dbPass != "" {
			dbPort := str("DB_PORT", "5432")
			dbUser := str("DB_USER", "lab_worker")
			dbName := str("DB_NAME", "n8n_db")
			dbSSL := str("DB_SSLMODE", "disable")
			dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPass, dbHost, dbPort, dbName, dbSSL)
		}
	}
	c.DBURL = dbURL

	errs = append(errs, c.validate()...)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func (c *Config) validate() []error {
	var errs []error
	required := map[string]string{
		"N8N_BASE_URL":      c.N8NBaseURL,
		"N8N_API_KEY":       c.N8NAPIKey,
		"GITLAB_BASE_URL":   c.GitLabBaseURL,
		"GITLAB_TOKEN":      c.GitLabToken,
		"SERVICE_API_TOKEN": c.ServiceAPIToken,
	}
	for k, v := range required {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", k))
		}
	}
	for _, kv := range []struct{ k, v string }{{"N8N_BASE_URL", c.N8NBaseURL}, {"GITLAB_BASE_URL", c.GitLabBaseURL}} {
		if kv.v == "" {
			continue
		}
		u, err := url.Parse(kv.v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("%s must be an http(s) URL", kv.k))
		}
	}
	if c.GitLabBaseURL != "" && strings.HasPrefix(c.GitLabBaseURL, "http://") {
		errs = append(errs, errors.New("GITLAB_BASE_URL must use https (the token is sent in a header)"))
	}
	if len(c.ServiceAPIToken) > 0 && len(c.ServiceAPIToken) < 16 {
		errs = append(errs, errors.New("SERVICE_API_TOKEN is too short (min 16 characters)"))
	}
	if c.DefaultRepository == "" && len(c.Mappings) == 0 {
		errs = append(errs, errors.New("DEFAULT_REPOSITORY or OWNER_MAPPINGS must be specified"))
	}
	if c.DefaultRepository != "" && (!repoPattern.MatchString(c.DefaultRepository) || strings.Contains(c.DefaultRepository, "..")) {
		errs = append(errs, fmt.Errorf("DEFAULT_REPOSITORY is not a valid repository path: %q", c.DefaultRepository))
	}
	seen := map[string]bool{}
	for i, m := range c.Mappings {
		user := strings.TrimSpace(m.N8NUser)
		if user == "" {
			errs = append(errs, fmt.Errorf("OWNER_MAPPINGS[%d].n8nUser is empty", i))
		}
		if !repoPattern.MatchString(m.Repository) || strings.Contains(m.Repository, "..") {
			errs = append(errs, fmt.Errorf("OWNER_MAPPINGS[%d].repository is not a valid GitLab project path", i))
		}
		key := strings.ToLower(user)
		if seen[key] {
			errs = append(errs, fmt.Errorf("OWNER_MAPPINGS[%d].n8nUser %q is duplicated", i, user))
		}
		seen[key] = true
	}
	if c.PollInterval < time.Second {
		errs = append(errs, errors.New("POLL_INTERVAL must be >= 1s"))
	}
	if c.MaxCommitRetries < 1 || c.MaxCommitRetries > 10 {
		errs = append(errs, errors.New("MAX_COMMIT_RETRIES must be 1..10"))
	}
	if c.MaxBodyBytes < 1 {
		errs = append(errs, errors.New("MAX_BODY_BYTES must be positive"))
	}
	return errs
}
