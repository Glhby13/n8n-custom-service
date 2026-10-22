// Package github is a minimal GitHub REST API client implementing gitlab.Store.
package github

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/gitlab"
)

// Client talks to the GitHub REST API.
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
	MaxBody   int64
	Observe   func(method, code string)
	Transport http.RoundTripper // tests only
}

// New builds a GitHub client.
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
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" || base == "https://github.com" {
		base = "https://api.github.com"
	}
	rt := o.Transport
	if rt == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		rt = tr
	}
	return &Client{
		base:    base,
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
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.observe(method, "error")
		return fmt.Errorf("GitHub request failed: %w", err)
	}
	defer resp.Body.Close()
	c.observe(method, strconv.Itoa(resp.StatusCode))
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return fmt.Errorf("GitHub response read failed: %w", err)
	}
	if int64(len(data)) > c.maxBody {
		return errors.New("GitHub response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := string(data)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return gitlab.ErrNotFound
		case http.StatusConflict:
			return fmt.Errorf("%w: %s", gitlab.ErrConflict, msg)
		}
		return &gitlab.APIError{Status: resp.StatusCode, Body: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("GitHub response decode failed: %w", err)
	}
	return nil
}

// GetFile reads path at ref. Returns gitlab.File.
func (c *Client) GetFile(ctx context.Context, repo, path, ref string) (*gitlab.File, error) {
	var resp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		SHA      string `json:"sha"` // blob SHA
	}
	q := url.Values{}
	if ref != "" {
		q.Set("ref", ref)
	}
	if err := c.do(ctx, http.MethodGet, "/repos/"+repo+"/contents/"+path, q, nil, &resp); err != nil {
		return nil, err
	}
	clean := strings.ReplaceAll(resp.Content, "\n", "")
	content, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("GitHub file content decode: %w", err)
	}

	// Fetch latest commit for this file to get the real commit SHA
	commitSHA := ""
	commits, err := c.FileHistory(ctx, repo, path, ref, 1)
	if err == nil && len(commits) > 0 {
		commitSHA = commits[0].ID
	}
	if commitSHA == "" {
		commitSHA = resp.SHA
	}

	return &gitlab.File{
		Content:      content,
		LastCommitID: commitSHA,
		CommitID:     commitSHA,
	}, nil
}

// FileHistory lists commits touching path on ref up to limit.
func (c *Client) FileHistory(ctx context.Context, repo, path, ref string, limit int) ([]gitlab.Commit, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []gitlab.Commit
	for page := 1; len(out) < limit; page++ {
		perPage := 100
		if rest := limit - len(out); rest < perPage {
			perPage = rest
		}
		q := url.Values{
			"path":     {path},
			"per_page": {strconv.Itoa(perPage)},
			"page":     {strconv.Itoa(page)},
		}
		if ref != "" {
			q.Set("sha", ref)
		}
		var ghCommits []struct {
			SHA    string `json:"sha"`
			Commit struct {
				Author struct {
					Name  string    `json:"name"`
					Email string    `json:"email"`
					Date  time.Time `json:"date"`
				} `json:"author"`
				Message string `json:"message"`
			} `json:"commit"`
		}
		if err := c.do(ctx, http.MethodGet, "/repos/"+repo+"/commits", q, nil, &ghCommits); err != nil {
			return nil, err
		}
		if len(ghCommits) == 0 {
			break
		}
		for _, gc := range ghCommits {
			title := gc.Commit.Message
			if idx := strings.IndexByte(title, '\n'); idx >= 0 {
				title = title[:idx]
			}
			short := gc.SHA
			if len(short) > 8 {
				short = short[:8]
			}
			out = append(out, gitlab.Commit{
				ID:          gc.SHA,
				ShortID:     short,
				Title:       title,
				Message:     gc.Commit.Message,
				AuthorName:  gc.Commit.Author.Name,
				AuthorEmail: gc.Commit.Author.Email,
				CreatedAt:   gc.Commit.Author.Date,
			})
			if len(out) >= limit {
				break
			}
		}
		if len(ghCommits) < perPage {
			break
		}
	}
	return out, nil
}

// WriteFile creates or updates a file in one commit and returns the new commit SHA.
func (c *Client) WriteFile(ctx context.Context, repo, branch, path string, content []byte, message, lastCommitID string) (string, error) {
	reqBody := map[string]any{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  branch,
	}

	// If updating an existing file, GitHub requires the current blob SHA
	var current struct {
		SHA string `json:"sha"`
	}
	q := url.Values{"ref": {branch}}
	err := c.do(ctx, http.MethodGet, "/repos/"+repo+"/contents/"+path, q, nil, &current)
	switch {
	case err == nil:
		reqBody["sha"] = current.SHA
	case errors.Is(err, gitlab.ErrNotFound):
		// New file, no sha needed
	default:
		return "", err
	}

	var resp struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := c.do(ctx, http.MethodPut, "/repos/"+repo+"/contents/"+path, nil, reqBody, &resp); err != nil {
		return "", err
	}
	return resp.Commit.SHA, nil
}

// CommentCommit adds a commit comment.
func (c *Client) CommentCommit(ctx context.Context, repo, sha, note string) error {
	reqBody := map[string]string{"body": note}
	return c.do(ctx, http.MethodPost, "/repos/"+repo+"/commits/"+sha+"/comments", nil, reqBody, nil)
}
