// Package gitlab is a minimal GitLab REST API v4 client for one-file-per-workflow storage.
//
// Reads use the Repository Files API (GET /projects/:id/repository/files/:path?ref=...).
// History uses the Commits API filtered by path. Writes use POST /projects/:id/repository/commits
// with a single create/update action; updates carry last_commit_id so GitLab rejects the write if
// the file changed since it was read (optimistic concurrency). The Commits API returns the new
// commit SHA directly. No clone, no push, no force, no history rewrite.
package gitlab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("gitlab: not found")
	ErrConflict = errors.New("gitlab: concurrent modification")
)

// APIError is any other non-2xx answer.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitLab API returned HTTP %d: %s", e.Status, e.Body)
}

// File is a repository file at a ref.
type File struct {
	Content      []byte
	LastCommitID string
	CommitID     string
}

// Commit is one entry of the file history.
type Commit struct {
	ID          string    `json:"id"`
	ShortID     string    `json:"short_id"`
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	AuthorName  string    `json:"author_name"`
	AuthorEmail string    `json:"author_email"`
	CreatedAt   time.Time `json:"created_at"`
}

// Store is the contract the service depends on (faked in tests).
type Store interface {
	GetFile(ctx context.Context, repo, path, ref string) (*File, error)
	FileHistory(ctx context.Context, repo, path, ref string, limit int) ([]Commit, error)
	// WriteFile creates (lastCommitID == "") or updates the file in one commit and returns its SHA.
	WriteFile(ctx context.Context, repo, branch, path string, content []byte, message, lastCommitID string) (string, error)
	// CommentCommit adds a comment (note) to a commit.
	CommentCommit(ctx context.Context, repo, sha, note string) error
}

// Client talks to a real GitLab.
type Client struct {
	base    string
	token   string
	http    *http.Client
	maxBody int64
	observe func(method, code string)
}

// Options configures New.
type Options struct {
	BaseURL   string
	Token     string
	Timeout   time.Duration
	CAFile    string
	MaxBody   int64
	Observe   func(method, code string)
	Transport http.RoundTripper // tests only
}

// New builds a client: TLS verification always on (optionally with an extra internal CA),
// redirects disabled, hard timeout.
func New(o Options) (*Client, error) {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 16 << 20
	}
	if o.Observe == nil {
		o.Observe = func(string, string) {}
	}
	rt := o.Transport
	if rt == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if o.CAFile != "" {
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return nil, fmt.Errorf("GITLAB_CA_FILE: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("GITLAB_CA_FILE: no PEM certificate found")
			}
			tlsCfg.RootCAs = pool
		}
		tr.TLSClientConfig = tlsCfg
		rt = tr
	}
	return &Client{
		base:    strings.TrimRight(o.BaseURL, "/") + "/api/v4",
		token:   o.Token,
		maxBody: o.MaxBody,
		observe: o.Observe,
		http: &http.Client{
			Timeout:       o.Timeout,
			Transport:     rt,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func projectPath(repo string) string { return "/projects/" + url.PathEscape(repo) }

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u, err := url.Parse(c.base + path)
	if err != nil {
		return err
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.observe(method, "error")
		return fmt.Errorf("GitLab request failed: %w", err)
	}
	defer resp.Body.Close()
	c.observe(method, strconv.Itoa(resp.StatusCode))
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return fmt.Errorf("GitLab response read failed: %w", err)
	}
	if int64(len(data)) > c.maxBody {
		return errors.New("GitLab response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := string(data)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return ErrNotFound
		case resp.StatusCode == http.StatusConflict, isConflictMessage(resp.StatusCode, msg):
			return fmt.Errorf("%w: %s", ErrConflict, msg)
		}
		return &APIError{Status: resp.StatusCode, Body: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("GitLab response decode failed: %w", err)
	}
	return nil
}

// GitLab answers 400 with these messages when last_commit_id is stale or a create races.
func isConflictMessage(status int, msg string) bool {
	if status != http.StatusBadRequest {
		return false
	}
	m := strings.ToLower(msg)
	return strings.Contains(m, "changed since") || strings.Contains(m, "already exists") ||
		strings.Contains(m, "doesn't exist") || strings.Contains(m, "does not exist") ||
		strings.Contains(m, "last_commit_id")
}

// GetFile reads path at ref (branch name or commit SHA).
func (c *Client) GetFile(ctx context.Context, repo, path, ref string) (*File, error) {
	var resp struct {
		Content      string `json:"content"`
		Encoding     string `json:"encoding"`
		LastCommitID string `json:"last_commit_id"`
		CommitID     string `json:"commit_id"`
	}
	q := url.Values{"ref": {ref}}
	if err := c.do(ctx, http.MethodGet, projectPath(repo)+"/repository/files/"+url.PathEscape(path), q, nil, &resp); err != nil {
		return nil, err
	}
	content := []byte(resp.Content)
	if resp.Encoding == "base64" {
		dec, err := base64.StdEncoding.DecodeString(resp.Content)
		if err != nil {
			return nil, fmt.Errorf("GitLab file content: %w", err)
		}
		content = dec
	}
	return &File{Content: content, LastCommitID: resp.LastCommitID, CommitID: resp.CommitID}, nil
}

// FileHistory lists commits touching path on ref, newest first, up to limit.
func (c *Client) FileHistory(ctx context.Context, repo, path, ref string, limit int) ([]Commit, error) {
	if limit <= 0 {
		limit = 100
	}
	var all []Commit
	for page := 1; len(all) < limit; page++ {
		perPage := 100
		if rest := limit - len(all); rest < perPage {
			perPage = rest
		}
		q := url.Values{
			"ref_name": {ref},
			"path":     {path},
			"per_page": {strconv.Itoa(perPage)},
			"page":     {strconv.Itoa(page)},
		}
		var batch []Commit
		if err := c.do(ctx, http.MethodGet, projectPath(repo)+"/repository/commits", q, nil, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < perPage {
			break
		}
	}
	return all, nil
}

// WriteFile commits content to path on branch. lastCommitID empty = create, otherwise update
// guarded by last_commit_id.
func (c *Client) WriteFile(ctx context.Context, repo, branch, path string, content []byte, message, lastCommitID string) (string, error) {
	action := map[string]any{
		"action":    "create",
		"file_path": path,
		"content":   base64.StdEncoding.EncodeToString(content),
		"encoding":  "base64",
	}
	if lastCommitID != "" {
		action["action"] = "update"
		action["last_commit_id"] = lastCommitID
	}
	body := map[string]any{
		"branch":         branch,
		"commit_message": message,
		"actions":        []any{action},
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, projectPath(repo)+"/repository/commits", nil, body, &resp); err != nil {
		return "", err
	}
	if resp.ID == "" {
		return "", errors.New("GitLab returned no commit id")
	}
	return resp.ID, nil
}

// CommentCommit posts a comment on commit sha (POST /projects/:id/repository/commits/:sha/comments).
func (c *Client) CommentCommit(ctx context.Context, repo, sha, note string) error {
	return c.do(ctx, http.MethodPost, projectPath(repo)+"/repository/commits/"+url.PathEscape(sha)+"/comments", nil,
		map[string]any{"note": note}, nil)
}
