// Command mock is a LOCAL DEVELOPMENT stand-in for the n8n public API (http :5678) and the
// GitLab REST API (https :8443, self-signed CA written to $CERT_DIR/ca.pem). State is in memory.
// Never deploy it. Extra endpoints to drive the demo:
//
//	POST /mock/edit/{id}     {"label":"..."}  simulate an autosave (new draft, not published)
//	POST /mock/publish/{id}                   simulate the user clicking Publish
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // fake commit ids
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	n8nKey      = "local-dev-n8n-key"
	gitlabToken = "local-dev-gitlab-token"
)

var mu sync.Mutex

// ---------------- n8n ----------------

var (
	workflows = map[string]map[string]any{}
	versions  = map[string]map[string]any{}
	seq       = 0
)

func nextVersion() string { seq++; return fmt.Sprintf("ver-%03d", seq) }

func demoNodes(label string) []any {
	return []any{
		map[string]any{"id": "n1", "name": "Manual Trigger", "type": "n8n-nodes-base.manualTrigger", "typeVersion": 1, "position": []any{0, 0}, "parameters": map[string]any{}},
		map[string]any{"id": "n2", "name": "Set", "type": "n8n-nodes-base.set", "typeVersion": 3, "position": []any{220, 0},
			"parameters": map[string]any{"value": label}, "credentials": map[string]any{"httpBasicAuth": map[string]any{"id": "1", "name": "demo basic"}}},
	}
}

func seed() {
	add := func(id, name, owner string) {
		workflows[id] = map[string]any{
			"id": id, "name": name, "active": false, "isArchived": false, "versionId": nextVersion(),
			"nodes": demoNodes("initial"), "connections": map[string]any{"Manual Trigger": map[string]any{"main": []any{[]any{map[string]any{"node": "Set", "type": "main", "index": 0}}}}},
			"settings": map[string]any{"executionOrder": "v1"}, "staticData": nil, "pinData": map[string]any{},
			"createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(), "tags": []any{},
			"shared": []any{map[string]any{"role": "workflow:owner", "projectId": "p-" + id,
				"project": map[string]any{"id": "p-" + id, "name": owner, "type": "personal"}}},
			"activeVersion": nil,
		}
	}
	add("wf001", "Demo pluto workflow", "admin psa <admin.psa@example.local>")
	add("wf002", "Demo gen-ai workflow", "gen-ai itpd <gen-ai@example.local>")
	add("wf003", "Unmapped workflow", "someone else <someone@example.local>")
	publishLocked("wf001")
}

func publishLocked(id string) {
	w := workflows[id]
	vid := w["versionId"].(string)
	w["activeVersion"] = map[string]any{"versionId": vid, "workflowId": id, "nodes": w["nodes"], "connections": w["connections"], "authors": "1"}
	w["active"] = true
	versions[id+"/"+vid] = map[string]any{"versionId": vid, "workflowId": id, "name": "Version " + vid, "nodes": w["nodes"], "connections": w["connections"], "authors": "1"}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func n8nHandler() http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-N8N-API-KEY") != n8nKey {
				writeJSON(w, 401, map[string]string{"message": "unauthorized"})
				return
			}
			mu.Lock()
			defer mu.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/v1/workflows", auth(func(w http.ResponseWriter, _ *http.Request) {
		data := []any{}
		for _, wf := range workflows {
			data = append(data, wf)
		}
		writeJSON(w, 200, map[string]any{"data": data, "nextCursor": nil})
	}))
	mux.HandleFunc("GET /api/v1/workflows/{id}", auth(func(w http.ResponseWriter, r *http.Request) {
		if wf, ok := workflows[r.PathValue("id")]; ok {
			writeJSON(w, 200, wf)
			return
		}
		writeJSON(w, 404, map[string]string{"message": "not found"})
	}))
	mux.HandleFunc("GET /api/v1/workflows/{id}/{vid}", auth(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := versions[r.PathValue("id")+"/"+r.PathValue("vid")]; ok {
			writeJSON(w, 200, v)
			return
		}
		writeJSON(w, 404, map[string]string{"message": "not found"})
	}))
	mux.HandleFunc("PUT /api/v1/workflows/{id}", auth(func(w http.ResponseWriter, r *http.Request) {
		wf, ok := workflows[r.PathValue("id")]
		if !ok {
			writeJSON(w, 404, map[string]string{"message": "not found"})
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		for k := range body {
			if k != "name" && k != "nodes" && k != "connections" && k != "settings" {
				writeJSON(w, 400, map[string]string{"message": "request/body must NOT have additional properties: " + k})
				return
			}
		}
		for k, v := range body {
			wf[k] = v
		}
		wf["versionId"] = nextVersion()
		wf["updatedAt"] = time.Now().UTC()
		if wf["active"] == true {
			publishLocked(r.PathValue("id"))
		}
		writeJSON(w, 200, wf)
	}))
	mux.HandleFunc("POST /api/v1/workflows/{id}/activate", auth(func(w http.ResponseWriter, r *http.Request) {
		wf, ok := workflows[r.PathValue("id")]
		if !ok {
			writeJSON(w, 404, map[string]string{"message": "not found"})
			return
		}
		var body struct {
			VersionID string `json:"versionId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.VersionID != "" && body.VersionID != wf["versionId"] {
			writeJSON(w, 400, map[string]string{"message": "unknown version"})
			return
		}
		publishLocked(r.PathValue("id"))
		writeJSON(w, 200, wf)
	}))
	// demo helpers (no auth)
	mux.HandleFunc("POST /mock/edit/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		wf, ok := workflows[r.PathValue("id")]
		if !ok {
			writeJSON(w, 404, map[string]string{"message": "not found"})
			return
		}
		var body struct {
			Label string `json:"label"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		wf["nodes"] = demoNodes(body.Label)
		wf["versionId"] = nextVersion()
		writeJSON(w, 200, map[string]any{"versionId": wf["versionId"], "published": wf["activeVersion"]})
	})
	mux.HandleFunc("POST /mock/publish/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := workflows[r.PathValue("id")]; !ok {
			writeJSON(w, 404, map[string]string{"message": "not found"})
			return
		}
		publishLocked(r.PathValue("id"))
		writeJSON(w, 200, map[string]any{"activeVersion": workflows[r.PathValue("id")]["activeVersion"].(map[string]any)["versionId"]})
	})
	return mux
}

// ---------------- GitLab ----------------

type commit struct {
	ID, Title string
	At        time.Time
	Content   []byte
}

var (
	files   = map[string][]commit{} // project + "\x00" + path
	commitN = 0
)

func gitlabHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("PRIVATE-TOKEN") != gitlabToken {
		writeJSON(w, 401, map[string]string{"message": "401 Unauthorized"})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	// /api/v4/projects/<escaped project>/repository/...
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v4/projects/")
	parts := strings.SplitN(rest, "/repository/", 2)
	if len(parts) != 2 {
		writeJSON(w, 404, map[string]string{"message": "404 Not Found"})
		return
	}
	project, _ := url.PathUnescape(parts[0])
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(parts[1], "files/"):
		path, _ := url.PathUnescape(strings.TrimPrefix(parts[1], "files/"))
		list := files[project+"\x00"+path]
		ref := r.URL.Query().Get("ref")
		for i := len(list) - 1; i >= 0; i-- {
			if ref == "main" || list[i].ID == ref {
				writeJSON(w, 200, map[string]string{"file_path": path, "encoding": "base64",
					"content": base64.StdEncoding.EncodeToString(list[i].Content), "last_commit_id": list[i].ID, "commit_id": list[i].ID})
				return
			}
		}
		writeJSON(w, 404, map[string]string{"message": "404 File Not Found"})
	case r.Method == http.MethodGet && parts[1] == "commits":
		list := files[project+"\x00"+r.URL.Query().Get("path")]
		out := []any{}
		for i := len(list) - 1; i >= 0; i-- {
			c := list[i]
			out = append(out, map[string]any{"id": c.ID, "short_id": c.ID[:8], "title": c.Title, "message": c.Title,
				"author_name": "n8n-git-sync", "author_email": "n8n-git-sync@example.local", "created_at": c.At})
		}
		writeJSON(w, 200, out)
	case r.Method == http.MethodPost && parts[1] == "commits":
		var body struct {
			Branch  string `json:"branch"`
			Message string `json:"commit_message"`
			Actions []struct {
				Action, FilePath, Content, Encoding, LastCommitID string
			} `json:"actions"`
		}
		raw := map[string]any{}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			writeJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &body)
		acts, _ := raw["actions"].([]any)
		if len(acts) != 1 {
			writeJSON(w, 400, map[string]string{"message": "exactly one action expected"})
			return
		}
		a := acts[0].(map[string]any)
		path, _ := a["file_path"].(string)
		last, _ := a["last_commit_id"].(string)
		k := project + "\x00" + path
		head := ""
		if l := files[k]; len(l) > 0 {
			head = l[len(l)-1].ID
		}
		if a["action"] == "create" && head != "" {
			writeJSON(w, 400, map[string]string{"message": "A file with this name already exists"})
			return
		}
		if a["action"] == "update" && last != head {
			writeJSON(w, 400, map[string]string{"message": "You are attempting to update a file that has changed since you started editing it."})
			return
		}
		content, err := base64.StdEncoding.DecodeString(a["content"].(string))
		if err != nil {
			writeJSON(w, 400, map[string]string{"message": "bad content"})
			return
		}
		commitN++
		sum := sha1.Sum([]byte(project + path + strconv.Itoa(commitN))) //nolint:gosec
		c := commit{ID: hex.EncodeToString(sum[:]), Title: body.Message, At: time.Now().UTC(), Content: content}
		files[k] = append(files[k], c)
		writeJSON(w, 201, map[string]any{"id": c.ID, "short_id": c.ID[:8], "title": c.Title})
	default:
		writeJSON(w, 404, map[string]string{"message": "404 Not Found"})
	}
}

// ---------------- TLS ----------------

func selfSigned(dir string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "mock-gitlab"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		DNSNames: []string{"mock", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o644); err != nil { //nolint:gosec // public cert
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func main() {
	dir := os.Getenv("CERT_DIR")
	if dir == "" {
		dir = "."
	}
	cert, err := selfSigned(dir)
	if err != nil {
		log.Fatal(err)
	}
	seed()
	go func() {
		srv := &http.Server{Addr: ":8443", Handler: http.HandlerFunc(gitlabHandler), ReadHeaderTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()
	log.Println("mock n8n on :5678, mock GitLab on https://:8443 (CA in", filepath.Join(dir, "ca.pem")+")")
	srv := &http.Server{Addr: ":5678", Handler: n8nHandler(), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
