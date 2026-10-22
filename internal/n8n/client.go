// Package n8n is a minimal client for the n8n public REST API (/api/v1).
// Only read endpoints plus PUT /workflows/{id} and POST /workflows/{id}/activate are used.
// No database access, no credential endpoints, no encryption key.
package n8n

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("n8n: not found")
)

// APIError is a non-2xx answer from n8n (body is truncated and never contains our key).
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("n8n API returned HTTP %d: %s", e.Status, e.Body)
}

// Shared is one entry of a workflow's `shared` array (ownership).
type Shared struct {
	Role      string
	ProjectID string
	Project   Project
}

// Project is the project a workflow lives in.
type Project struct {
	ID   string
	Name string
	Type string
}

// ActiveVersion is the currently published snapshot of a workflow.
type ActiveVersion struct {
	VersionID   string
	Nodes       any
	Connections any
	NodeGroups  any // visual frames on the canvas
}

// Workflow is the subset of the workflow object the service needs. Raw keeps the full decoded
// object (numbers preserved) for sanitisation and restore.
type Workflow struct {
	ID            string
	Name          string
	Active        bool
	IsArchived    bool
	VersionID     string
	Nodes         any
	Connections   any
	Settings      any
	Meta          any
	Tags          []string
	Shared        []Shared
	ActiveVersion *ActiveVersion
	Raw           map[string]any
}

// Version is GET /workflows/{id}/{versionId}.
type Version struct {
	VersionID   string
	WorkflowID  string
	Name        string // version name from the Publish dialog (or n8n's default "Version <id8>")
	Description string // "Describe changes" from the Publish dialog
	Nodes       any
	Connections any
}

// Client is the contract the service depends on (faked in tests).
type Client interface {
	ListWorkflows(ctx context.Context) ([]Workflow, error)
	GetWorkflow(ctx context.Context, id string) (*Workflow, error)
	GetVersion(ctx context.Context, workflowID, versionID string) (*Version, error)
	UpdateWorkflow(ctx context.Context, id string, body map[string]any) (*Workflow, error)
	ActivateWorkflow(ctx context.Context, id, versionID string) (*Workflow, error)
}

// HTTPClient talks to a real n8n instance.
type HTTPClient struct {
	base     string
	apiKey   string
	http     *http.Client
	pageSize int
	maxBody  int64
	observe  func(method, code string)
}

// Options configures NewHTTPClient.
type Options struct {
	BaseURL  string
	APIKey   string
	Timeout  time.Duration
	PageSize int
	MaxBody  int64
	Observe  func(method, code string)
	// Transport is optional (tests).
	Transport http.RoundTripper
}

// NewHTTPClient builds a client with redirects disabled and a hard timeout.
func NewHTTPClient(o Options) *HTTPClient {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.PageSize <= 0 {
		o.PageSize = 100
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 16 << 20
	}
	if o.Observe == nil {
		o.Observe = func(string, string) {}
	}
	return &HTTPClient{
		base:     strings.TrimRight(o.BaseURL, "/") + "/api/v1",
		apiKey:   o.APIKey,
		pageSize: o.PageSize,
		maxBody:  o.MaxBody,
		observe:  o.Observe,
		http: &http.Client{
			Timeout:       o.Timeout,
			Transport:     o.Transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *HTTPClient) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-N8N-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.observe(method, "error")
		// url.Error carries the URL only (never headers), so the key cannot leak here.
		return fmt.Errorf("n8n request failed: %w", err)
	}
	defer resp.Body.Close()
	c.observe(method, strconv.Itoa(resp.StatusCode))
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return fmt.Errorf("n8n response read failed: %w", err)
	}
	if int64(len(data)) > c.maxBody {
		return errors.New("n8n response too large")
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		msg := string(data)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return &APIError{Status: resp.StatusCode, Body: msg}
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("n8n response decode failed: %w", err)
	}
	return nil
}

// ListWorkflows returns every workflow (all pages), without pinned data.
func (c *HTTPClient) ListWorkflows(ctx context.Context) ([]Workflow, error) {
	var all []Workflow
	cursor := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{}
		q.Set("excludePinnedData", "true")
		q.Set("limit", strconv.Itoa(c.pageSize))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp struct {
			Data       []map[string]any `json:"data"`
			NextCursor *string          `json:"nextCursor"`
		}
		if err := c.do(ctx, http.MethodGet, "/workflows", q, nil, &resp); err != nil {
			return nil, err
		}
		for _, raw := range resp.Data {
			all = append(all, ParseWorkflow(raw))
		}
		if resp.NextCursor == nil || *resp.NextCursor == "" {
			return all, nil
		}
		cursor = *resp.NextCursor
	}
	return nil, errors.New("n8n: too many workflow pages")
}

// GetWorkflow returns one workflow (without pinned data).
func (c *HTTPClient) GetWorkflow(ctx context.Context, id string) (*Workflow, error) {
	var raw map[string]any
	q := url.Values{"excludePinnedData": {"true"}}
	if err := c.do(ctx, http.MethodGet, "/workflows/"+url.PathEscape(id), q, nil, &raw); err != nil {
		return nil, err
	}
	w := ParseWorkflow(raw)
	return &w, nil
}

// GetVersion returns a workflow history snapshot.
func (c *HTTPClient) GetVersion(ctx context.Context, workflowID, versionID string) (*Version, error) {
	var raw map[string]any
	if err := c.do(ctx, http.MethodGet, "/workflows/"+url.PathEscape(workflowID)+"/"+url.PathEscape(versionID), nil, nil, &raw); err != nil {
		return nil, err
	}
	return &Version{
		VersionID:   str(raw["versionId"]),
		WorkflowID:  str(raw["workflowId"]),
		Name:        str(raw["name"]),
		Description: str(raw["description"]),
		Nodes:       raw["nodes"],
		Connections: raw["connections"],
	}, nil
}

// UpdateWorkflow replaces name/nodes/connections/settings (n8n re-publishes if it was published).
func (c *HTTPClient) UpdateWorkflow(ctx context.Context, id string, body map[string]any) (*Workflow, error) {
	var raw map[string]any
	if err := c.do(ctx, http.MethodPut, "/workflows/"+url.PathEscape(id), nil, body, &raw); err != nil {
		return nil, err
	}
	w := ParseWorkflow(raw)
	return &w, nil
}

// ActivateWorkflow publishes a specific version.
func (c *HTTPClient) ActivateWorkflow(ctx context.Context, id, versionID string) (*Workflow, error) {
	body := map[string]any{}
	if versionID != "" {
		body["versionId"] = versionID
	}
	var raw map[string]any
	if err := c.do(ctx, http.MethodPost, "/workflows/"+url.PathEscape(id)+"/activate", nil, body, &raw); err != nil {
		return nil, err
	}
	w := ParseWorkflow(raw)
	return &w, nil
}

// ParseWorkflow converts a decoded workflow object (numbers as json.Number) into a Workflow.
func ParseWorkflow(raw map[string]any) Workflow {
	w := Workflow{
		ID:          str(raw["id"]),
		Name:        str(raw["name"]),
		VersionID:   str(raw["versionId"]),
		Nodes:       raw["nodes"],
		Connections: raw["connections"],
		Settings:    raw["settings"],
		Meta:        raw["meta"],
		Raw:         raw,
	}
	w.Active, _ = raw["active"].(bool)
	w.IsArchived, _ = raw["isArchived"].(bool)
	if tags, ok := raw["tags"].([]any); ok {
		for _, t := range tags {
			if tm, ok := t.(map[string]any); ok {
				if n := str(tm["name"]); n != "" {
					w.Tags = append(w.Tags, n)
				}
			}
		}
	}
	if shared, ok := raw["shared"].([]any); ok {
		for _, s := range shared {
			sm, ok := s.(map[string]any)
			if !ok {
				continue
			}
			sh := Shared{Role: str(sm["role"]), ProjectID: str(sm["projectId"])}
			if pm, ok := sm["project"].(map[string]any); ok {
				sh.Project = Project{ID: str(pm["id"]), Name: str(pm["name"]), Type: str(pm["type"])}
			}
			w.Shared = append(w.Shared, sh)
		}
	}
	if av, ok := raw["activeVersion"].(map[string]any); ok && av != nil {
		w.ActiveVersion = &ActiveVersion{
			VersionID:   str(av["versionId"]),
			Nodes:       av["nodes"],
			Connections: av["connections"],
			NodeGroups:  av["nodeGroups"],
		}
	}
	return w
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	}
	return ""
}
