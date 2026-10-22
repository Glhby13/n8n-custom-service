// Package historyproxy serves n8n's internal workflow-history endpoints
// (/rest/workflow-history/workflow/{id}...) so the native "Versions" panel of the n8n editor
// also lists the published versions stored in GitLab, beyond n8n's own (license-pruned) history.
//
// The n8n editor restores a version client-side: it GETs .../version/{versionId} and saves the
// nodes/connections through n8n's normal API with the user's session. So answering that GET from
// Git is enough for the built-in Restore and Compare to work on Git versions; n8n keeps owning
// permissions, credentials and storage.
//
// Authentication is n8n's: the user's n8n-auth cookie and browser-id header are forwarded only to
// N8N_BASE_URL (in-cluster). A workflow's Git versions are served only after n8n itself answers
// 200 to GET /rest/workflows/{id} for that session. Everything not handled here, and every
// failure on the Git side, falls through to n8n unchanged (fail-open to native behaviour).
//
// These are n8n-internal endpoints (not the public API) observed in n8n 2.28.6; re-check them on
// every n8n upgrade (see docs/discovery-n8n-2.28.6.md).
package historyproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/service"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/workflow"
)

// List modes.
const (
	ModeGitOnly = "git-only"
	ModeMerged  = "merged"
)

// Prefix is the path this handler owns (exposed by an Ingress on the n8n host).
const Prefix = "/rest/workflow-history/"

const workflowPrefix = Prefix + "workflow/"

// GitPrefix marks a history entry that only exists in Git (commit without n8n version mapping).
const GitPrefix = "git-"

// Source is the Git side (implemented by *service.Service).
type Source interface {
	GitHistory(ctx context.Context, id string) (*service.GitVersionedWorkflow, error)
	GitVersionAt(ctx context.Context, id, sha string) (*service.GitVersionContent, error)
	SyncedHead(id string) (service.SyncedHead, bool)
}

// Options configures the handler.
type Options struct {
	N8NBaseURL string
	Source     Source
	CookieName string        // n8n session cookie, default n8n-auth
	Timeout    time.Duration // per upstream call
	NativeTake int           // how many native versions to read before merging
	AuthzTTL   time.Duration
	// Mode: ModeGitOnly (default) lists only GitLab commits; ModeMerged also lists n8n's own
	// (draft/autosave) versions.
	Mode      string
	Log       *slog.Logger
	Transport http.RoundTripper // tests
}

// Handler implements http.Handler for Prefix.
type Handler struct {
	o      Options
	base   *url.URL
	client *http.Client
	proxy  *httputil.ReverseProxy

	mu    sync.Mutex
	authz map[string]time.Time // hash(session, workflow) -> allowed until
}

// New builds the handler.
func New(o Options) (*Handler, error) {
	base, err := url.Parse(strings.TrimRight(o.N8NBaseURL, "/"))
	if err != nil || base.Host == "" {
		return nil, errors.New("historyproxy: invalid N8N_BASE_URL")
	}
	if o.CookieName == "" {
		o.CookieName = "n8n-auth"
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.NativeTake <= 0 {
		o.NativeTake = 500
	}
	if o.Mode == "" {
		o.Mode = ModeGitOnly
	}
	if o.Mode != ModeGitOnly && o.Mode != ModeMerged {
		return nil, errors.New("historyproxy: mode must be git-only or merged")
	}
	if o.AuthzTTL <= 0 {
		o.AuthzTTL = 30 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	rt := o.Transport
	if rt == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.ResponseHeaderTimeout = o.Timeout
		rt = tr
	}
	h := &Handler{
		o: o, base: base, authz: map[string]time.Time{},
		client: &http.Client{
			Timeout:       o.Timeout,
			Transport:     rt,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	h.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(base)
			pr.Out.URL.Path = pr.In.URL.Path
			pr.Out.URL.RawPath = pr.In.URL.RawPath
			pr.SetXForwarded()
		},
		Transport: rt,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			o.Log.WarnContext(r.Context(), "history proxy: n8n unreachable", "error", err.Error())
			writeN8nError(w, http.StatusBadGateway, "n8n is not reachable")
		},
	}
	return h, nil
}

// ServeHTTP routes list/version GETs to the merging logic and proxies everything else.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, Prefix) {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if r.Method == http.MethodGet {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, workflowPrefix), "/")
		if strings.HasPrefix(r.URL.Path, workflowPrefix) && workflow.ValidID(parts[0]) {
			switch {
			case len(parts) == 1:
				h.list(w, r, parts[0])
				return
			case len(parts) == 3 && parts[1] == "version" && parts[2] != "":
				h.version(w, r, parts[0], parts[2])
				return
			}
		}
	}
	h.proxy.ServeHTTP(w, r)
}

// upstream performs a GET on n8n with the caller's session (cookie + browser-id only).
func (h *Handler) upstream(r *http.Request, path string, query url.Values) (int, []byte, error) {
	u := *h.base
	u.Path = path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	if c, err := r.Cookie(h.o.CookieName); err == nil {
		// Only the n8n session cookie is forwarded (parsed value, cannot contain ';').
		req.Header.Set("Cookie", c.Name+"="+c.Value)
	}
	if v := r.Header.Get("browser-id"); v != "" {
		req.Header.Set("browser-id", v)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return resp.StatusCode, body, err
}

func (h *Handler) sessionKey(r *http.Request, id string) string {
	c, _ := r.Cookie(h.o.CookieName)
	val := ""
	if c != nil {
		val = c.Value
	}
	sum := sha256.Sum256([]byte(val + "\x00" + r.Header.Get("browser-id") + "\x00" + id))
	return hex.EncodeToString(sum[:])
}

// authorize asks n8n whether this session may read workflow id. It returns the n8n status and
// body so a refusal can be passed back verbatim.
func (h *Handler) authorize(r *http.Request, id string) (int, []byte) {
	key := h.sessionKey(r, id)
	now := time.Now()
	h.mu.Lock()
	until, ok := h.authz[key]
	h.mu.Unlock()
	if ok && now.Before(until) {
		return http.StatusOK, nil
	}
	status, body, err := h.upstream(r, "/rest/workflows/"+id, nil)
	if err != nil {
		return http.StatusBadGateway, n8nErrorBody(http.StatusBadGateway, "n8n is not reachable")
	}
	if status == http.StatusOK {
		h.mu.Lock()
		if len(h.authz) > 10000 {
			h.authz = map[string]time.Time{}
		}
		h.authz[key] = now.Add(h.o.AuthzTTL)
		h.mu.Unlock()
	}
	return status, body
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request, id string) {
	var native []map[string]any
	if h.o.Mode == ModeMerged {
		q := url.Values{"take": {strconv.Itoa(h.o.NativeTake)}, "skip": {"0"}}
		status, body, err := h.upstream(r, workflowPrefix+id, q)
		if err != nil || status != http.StatusOK {
			// n8n decides about auth/not-found; give the panel exactly what n8n would.
			h.proxy.ServeHTTP(w, r)
			return
		}
		var resp struct {
			Data []map[string]any `json:"data"`
		}
		if json.Unmarshal(body, &resp) != nil {
			h.proxy.ServeHTTP(w, r)
			return
		}
		native = resp.Data
	}
	var draft map[string]any
	publishedID := ""
	if h.o.Mode == ModeGitOnly {
		// The workflow request is also the authorization check (n8n's own permissions).
		st, ok := h.workflowState(r, id)
		if !ok {
			// Not allowed (or not logged in): n8n's own answer for the history list.
			h.proxy.ServeHTTP(w, r)
			return
		}
		draft = h.draftEntry(r, id, st)
		publishedID = st.publishedID
	}
	hist, err := h.o.Source.GitHistory(r.Context(), id)
	if err != nil {
		if service.KindOf(err) != service.KindUnmapped {
			h.o.Log.WarnContext(r.Context(), "history proxy: Git history unavailable, serving n8n history", "workflow_id", id, "error", err.Error())
		}
		h.proxy.ServeHTTP(w, r)
		return
	}
	markPublished(hist, publishedID, h.o.Source, id)
	items := Merge(id, native, hist)
	if draft != nil {
		// Like n8n's own list: the current (unpublished) draft is the first entry, so n8n keeps
		// Restore available on the published version below it.
		items = append([]map[string]any{draft}, items...)
	}
	skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
	take, err := strconv.Atoi(r.URL.Query().Get("take"))
	if err != nil || take <= 0 {
		take = len(items)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": page(items, skip, take)})
}

// workflowState is the current workflow as n8n shows it to this session.
type workflowState struct {
	draftID     string // versionId: current draft
	publishedID string // activeVersionId / activeVersion.versionId
	updatedAt   string
}

// workflowState asks n8n for the workflow with the caller's session (authorization) and reads
// its draft and published version ids. ok is false when n8n refuses or is unreachable.
func (h *Handler) workflowState(r *http.Request, id string) (workflowState, bool) {
	status, body, err := h.upstream(r, "/rest/workflows/"+id, nil)
	if err != nil || status != http.StatusOK {
		return workflowState{}, false
	}
	h.mu.Lock()
	if len(h.authz) > 10000 {
		h.authz = map[string]time.Time{}
	}
	h.authz[h.sessionKey(r, id)] = time.Now().Add(h.o.AuthzTTL)
	h.mu.Unlock()
	var resp struct {
		Data struct {
			VersionID       string `json:"versionId"`
			ActiveVersionID string `json:"activeVersionId"`
			UpdatedAt       string `json:"updatedAt"`
			ActiveVersion   *struct {
				VersionID string `json:"versionId"`
			} `json:"activeVersion"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return workflowState{}, true
	}
	st := workflowState{draftID: resp.Data.VersionID, publishedID: resp.Data.ActiveVersionID, updatedAt: resp.Data.UpdatedAt}
	if st.publishedID == "" && resp.Data.ActiveVersion != nil {
		st.publishedID = resp.Data.ActiveVersion.VersionID
	}
	return st, true
}

// draftEntry returns n8n's own history entry for the current draft when it differs from the
// published version (nil otherwise), labelled so it is clearly not a GitLab version.
func (h *Handler) draftEntry(r *http.Request, id string, st workflowState) map[string]any {
	if st.draftID == "" || st.draftID == st.publishedID {
		return nil
	}
	item := map[string]any{"versionId": st.draftID, "workflowId": id, "createdAt": st.updatedAt, "updatedAt": st.updatedAt}
	status, body, err := h.upstream(r, workflowPrefix+id, url.Values{"take": {"20"}, "skip": {"0"}})
	if err == nil && status == http.StatusOK {
		var resp struct {
			Data []map[string]any `json:"data"`
		}
		if json.Unmarshal(body, &resp) == nil {
			for _, it := range resp.Data {
				if v, _ := it["versionId"].(string); v == st.draftID {
					item = it
					break
				}
			}
		}
	}
	if n, _ := item["name"].(string); n == "" {
		item["name"] = "Draft saat ini (belum dipublish)"
	}
	item["description"] = "Versi yang sedang diedit di n8n; belum ada di GitLab sampai di-Publish"
	return item
}

func (h *Handler) version(w http.ResponseWriter, r *http.Request, id, versionID string) {
	if sha, ok := strings.CutPrefix(versionID, GitPrefix); ok {
		h.serveGit(w, r, id, versionID, sha)
		return
	}
	status, body, err := h.upstream(r, r.URL.Path, nil)
	if err == nil && status != http.StatusNotFound {
		// Native version (or an auth error): n8n's answer as-is.
		writeRaw(w, status, body)
		return
	}
	// Pruned from n8n: look for the commit that recorded this n8n version.
	if s, b := h.authorize(r, id); s != http.StatusOK {
		writeRaw(w, s, b)
		return
	}
	hist, gerr := h.o.Source.GitHistory(r.Context(), id)
	if gerr != nil {
		h.fail(w, r, id, gerr)
		return
	}
	gv := hist.FindGitVersion(versionID)
	if gv == nil {
		if err != nil {
			writeN8nError(w, http.StatusBadGateway, "n8n is not reachable")
			return
		}
		writeRaw(w, status, body)
		return
	}
	h.serveGit(w, r, id, versionID, gv.SHA)
}

func (h *Handler) serveGit(w http.ResponseWriter, r *http.Request, id, versionID, sha string) {
	if s, b := h.authorize(r, id); s != http.StatusOK {
		writeRaw(w, s, b)
		return
	}
	c, err := h.o.Source.GitVersionAt(r.Context(), id, sha)
	if err != nil {
		h.fail(w, r, id, err)
		return
	}
	t := c.Version.Time.Format(time.RFC3339Nano)
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"versionId":   versionID,
		"workflowId":  id,
		"name":        label(c.Version),
		"description": description(c.Version),
		"authors":     c.Owner.N8NUser,
		"createdAt":   t,
		"updatedAt":   t,
		"nodes":       c.Nodes,
		"connections": c.Connections,
		"nodeGroups":  c.NodeGroups,
	}})
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, id string, err error) {
	status := http.StatusBadGateway
	var se *service.Error
	if errors.As(err, &se) {
		status = se.Status()
		if se.Kind == service.KindUpstream {
			h.o.Log.WarnContext(r.Context(), "history proxy: Git version unavailable", "workflow_id", id, "error", err.Error())
		}
		msg := se.Msg
		if se.Kind == service.KindInvalidData && se.Err != nil {
			msg += ": " + se.Err.Error()
		}
		writeN8nError(w, status, "GitLab version: "+msg)
		return
	}
	h.o.Log.ErrorContext(r.Context(), "history proxy: unexpected error", "workflow_id", id, "error", err.Error())
	writeN8nError(w, status, "GitLab version unavailable")
}

func label(v service.GitVersion) string { return "GitLab " + v.ShortSHA }

func description(v service.GitVersion) string {
	if v.Description != "" {
		return v.Description + " · Restore lalu Publish untuk rollback"
	}
	return v.Subject + " · Restore lalu Publish untuk rollback"
}

// Merge combines n8n's own history with the Git commits of a workflow, newest first.
// A commit whose N8n-Version-Id trailer matches a native version is shown once, as the native
// entry. Commits without a native counterpart (pruned by n8n, or written before the trailer
// existed) become entries with versionId = the trailer value or "git-<sha>".
func Merge(workflowID string, native []map[string]any, hist *service.GitVersionedWorkflow) []map[string]any {
	type entry struct {
		at   time.Time
		item map[string]any
	}
	nativeByID := make(map[string]bool, len(native))
	entries := make([]entry, 0, len(native)+len(hist.Versions))
	for _, it := range native {
		id, _ := it["versionId"].(string)
		nativeByID[id] = true
		entries = append(entries, entry{at: parseTime(it["createdAt"]), item: it})
	}
	usedTrailer := map[string]bool{}
	for _, v := range hist.Versions {
		// Several commits can record the same n8n version (e.g. a format migration after a
		// publish). Only the newest one is that n8n version; older ones keep their own git-<sha>
		// id so ids stay unique and only one entry is shown as Published.
		trailer := v.N8nVersionID
		if trailer != "" && usedTrailer[trailer] {
			trailer = ""
		}
		if trailer != "" {
			usedTrailer[trailer] = true
			if nativeByID[trailer] {
				continue
			}
		}
		vid := GitPrefix + v.SHA
		if trailer != "" {
			vid = trailer
		}
		t := v.Time.Format(time.RFC3339Nano)
		entries = append(entries, entry{at: v.Time, item: map[string]any{
			"versionId":   vid,
			"workflowId":  workflowID,
			"name":        label(v),
			"description": description(v),
			"authors":     hist.Owner.N8NUser,
			"createdAt":   t,
			"updatedAt":   t,
			"workflowPublishHistory": []any{map[string]any{
				"event": "activated", "versionId": vid, "workflowId": workflowID, "createdAt": t, "userId": nil,
			}},
		}})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].at.After(entries[j].at) })
	out := make([]map[string]any, len(entries))
	for i, e := range entries {
		out[i] = e.item
	}
	return out
}

// markPublished gives the commit that holds the live content the live n8n version id, so n8n
// shows it as "(Published)". Needed when the same content was published again: n8n creates a
// new version id but the service (correctly) makes no new commit, so no trailer carries it.
func markPublished(hist *service.GitVersionedWorkflow, publishedID string, src Source, id string) {
	if publishedID == "" || hist.FindGitVersion(publishedID) != nil {
		return
	}
	head, ok := src.SyncedHead(id)
	if !ok || head.PublishedVersionID != publishedID {
		return
	}
	for i := range hist.Versions {
		if hist.Versions[i].SHA == strings.ToLower(head.CommitSHA) {
			hist.Versions[i].N8nVersionID = publishedID
			return
		}
	}
}

func page(items []map[string]any, skip, take int) []map[string]any {
	if skip < 0 {
		skip = 0
	}
	if skip >= len(items) {
		return []map[string]any{}
	}
	end := skip + take
	if end > len(items) {
		end = len(items)
	}
	return items[skip:end]
}

func parseTime(v any) time.Time {
	s, _ := v.(string)
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	writeRaw(w, status, buf.Bytes())
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body) //nolint:gosec // G705: JSON API response (application/json, nosniff), not HTML
}

func n8nErrorBody(status int, msg string) []byte {
	b, _ := json.Marshal(map[string]any{"code": status, "message": msg})
	return b
}

func writeN8nError(w http.ResponseWriter, status int, msg string) {
	writeRaw(w, status, n8nErrorBody(status, msg))
}
