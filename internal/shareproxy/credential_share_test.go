package shareproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// TestSharePayloadParsing verifies payload decoding and limits.
func TestSharePayloadParsing(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantIDs   []string
		wantError bool
	}{
		{
			name:      "valid single project",
			body:      `{"shareWithIds":["proj-alpha"]}`,
			wantIDs:   []string{"proj-alpha"},
			wantError: false,
		},
		{
			name:      "valid multiple projects",
			body:      `{"shareWithIds":["proj-1","proj-2","proj-3"]}`,
			wantIDs:   []string{"proj-1", "proj-2", "proj-3"},
			wantError: false,
		},
		{
			name:      "empty share list",
			body:      `{"shareWithIds":[]}`,
			wantIDs:   []string{},
			wantError: false,
		},
		{
			name:      "missing field yields nil/empty",
			body:      `{}`,
			wantIDs:   nil,
			wantError: false,
		},
		{
			name:      "invalid json syntax",
			body:      `{invalid:json}`,
			wantIDs:   nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p sharePayload
			err := json.Unmarshal([]byte(tt.body), &p)
			if (err != nil) != tt.wantError {
				t.Fatalf("Unmarshal() error = %v, wantError = %v", err, tt.wantError)
			}
			if !tt.wantError {
				if len(p.ShareWithIds) != len(tt.wantIDs) {
					t.Fatalf("got %d IDs (%v), want %d IDs (%v)", len(p.ShareWithIds), p.ShareWithIds, len(tt.wantIDs), tt.wantIDs)
				}
				for i := range p.ShareWithIds {
					if p.ShareWithIds[i] != tt.wantIDs[i] {
						t.Errorf("ID at index %d = %q, want %q", i, p.ShareWithIds[i], tt.wantIDs[i])
					}
				}
			}
		})
	}
}

// TestSharePayloadSizeLimit tests the 64KB reader limit behavior.
func TestSharePayloadSizeLimit(t *testing.T) {
	// Construct an oversized payload > 64KB
	largeIDs := make([]string, 5000)
	for i := range largeIDs {
		largeIDs[i] = "project-id-with-very-long-name-padding-bytes-0123456789"
	}
	largeData, err := json.Marshal(map[string]any{"shareWithIds": largeIDs})
	if err != nil {
		t.Fatalf("failed to marshal large payload: %v", err)
	}
	if len(largeData) <= 64*1024 {
		t.Fatalf("expected payload > 64KB, got %d bytes", len(largeData))
	}

	// Reading with 64KB limit truncates the stream
	limitReader := io.LimitReader(bytes.NewReader(largeData), 64*1024)
	limitedBytes, err := io.ReadAll(limitReader)
	if err != nil {
		t.Fatalf("failed to read limited body: %v", err)
	}
	if len(limitedBytes) != 64*1024 {
		t.Fatalf("expected exactly 64KB, got %d bytes", len(limitedBytes))
	}

	// Truncated body cannot be unmarshaled (malformed JSON)
	var p sharePayload
	if err := json.Unmarshal(limitedBytes, &p); err == nil {
		t.Fatalf("expected unmarshal error on truncated JSON, got nil")
	}
}

// TestExtractCredentialIDs verifies extraction of credential IDs from workflow nodes.
func TestExtractCredentialIDs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name:     "whitespace only",
			input:    "   \n  \t ",
			expected: nil,
		},
		{
			name:     "empty array",
			input:    "[]",
			expected: nil,
		},
		{
			name: "single node with single credential",
			input: `[
				{
					"id": "node-1",
					"name": "HTTP Request",
					"type": "n8n-nodes-base.httpRequest",
					"credentials": {
						"httpHeaderAuth": {
							"id": "cred-hdr-1",
							"name": "My Header Auth"
						}
					}
				}
			]`,
			expected: []string{"cred-hdr-1"},
		},
		{
			name: "single node with multiple credentials",
			input: `[
				{
					"id": "node-2",
					"name": "Postgres Node",
					"type": "n8n-nodes-base.postgres",
					"credentials": {
						"postgres": {
							"id": "cred-pg-1"
						},
						"sshTunnel": {
							"id": "cred-ssh-2"
						}
					}
				}
			]`,
			expected: []string{"cred-pg-1", "cred-ssh-2"},
		},
		{
			name: "multiple nodes with duplicate credentials are deduplicated and sorted",
			input: `[
				{
					"id": "node-a",
					"credentials": {
						"oauth2": {
							"id": "cred-oauth-9"
						}
					}
				},
				{
					"id": "node-b",
					"credentials": {
						"oauth2": {
							"id": "cred-oauth-9"
						},
						"slackApi": {
							"id": "cred-slack-1"
						}
					}
				},
				{
					"id": "node-c",
					"credentials": {
						"slackApi": {
							"id": "cred-slack-1"
						}
					}
				}
			]`,
			expected: []string{"cred-oauth-9", "cred-slack-1"},
		},
		{
			name: "node without credentials",
			input: `[
				{
					"id": "node-manual",
					"name": "Manual Trigger",
					"type": "n8n-nodes-base.manualTrigger"
				}
			]`,
			expected: nil,
		},
		{
			name: "node with empty credentials or missing id",
			input: `[
				{
					"id": "node-empty",
					"credentials": {
						"someApi": {}
					}
				}
			]`,
			expected: nil,
		},
		{
			name: "numeric credential id",
			input: `[
				{
					"id": "node-num",
					"credentials": {
						"api": {
							"id": 999
						}
					}
				}
			]`,
			expected: []string{"999"},
		},
		{
			name: "stringified JSON format",
			input: `"[` +
				`{\"id\":\"node-1\",\"credentials\":{\"api\":{\"id\":\"cred-str-1\"}}}` +
				`]"`,
			expected: []string{"cred-str-1"},
		},
		{
			name: "object wrapper format",
			input: `{
				"nodes": [
					{
						"credentials": {
							"smtp": {
								"id": "cred-smtp-5"
							}
						}
					}
				]
			}`,
			expected: []string{"cred-smtp-5"},
		},
		{
			name:     "malformed json returns nil",
			input:    `[{broken json`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCredentialIDs([]byte(tt.input))
			if len(got) == 0 && len(tt.expected) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("extractCredentialIDs() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDiffShares verifies diff calculation between current shares and desired shares.
func TestDiffShares(t *testing.T) {
	ownerPID := "owner-project-id"

	tests := []struct {
		name       string
		current    []string
		desired    []string
		wantAdd    []string
		wantDelete []string
	}{
		{
			name:       "add new projects to empty current",
			current:    []string{},
			desired:    []string{"proj-1", "proj-2"},
			wantAdd:    []string{"proj-1", "proj-2"},
			wantDelete: nil,
		},
		{
			name:       "remove all existing projects",
			current:    []string{"proj-1", "proj-2"},
			desired:    []string{},
			wantAdd:    nil,
			wantDelete: []string{"proj-1", "proj-2"},
		},
		{
			name:       "keep unchanged shares",
			current:    []string{"proj-1", "proj-2"},
			desired:    []string{"proj-1", "proj-2"},
			wantAdd:    nil,
			wantDelete: nil,
		},
		{
			name:       "mixed add, keep, and delete",
			current:    []string{"proj-1", "proj-2"},
			desired:    []string{"proj-2", "proj-3"},
			wantAdd:    []string{"proj-3"},
			wantDelete: []string{"proj-1"},
		},
		{
			name:       "owner project ID is never added",
			current:    []string{"proj-1"},
			desired:    []string{"proj-1", ownerPID, "proj-4"},
			wantAdd:    []string{"proj-4"},
			wantDelete: nil,
		},
		{
			name:       "owner project ID is never deleted even if present in desired or current",
			current:    []string{"proj-1", ownerPID},
			desired:    []string{ownerPID},
			wantAdd:    nil,
			wantDelete: []string{"proj-1"},
		},
		{
			name:       "trims whitespace and ignores blank strings",
			current:    []string{"proj-1"},
			desired:    []string{"  proj-1  ", "   ", "", "  proj-new  "},
			wantAdd:    []string{"proj-new"},
			wantDelete: nil,
		},
		{
			name:       "deduplicates duplicate desired project IDs",
			current:    []string{},
			desired:    []string{"proj-dup", "proj-dup", "proj-dup"},
			wantAdd:    []string{"proj-dup"},
			wantDelete: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAdd, gotDelete := diffShares(tt.current, tt.desired, ownerPID)
			if len(gotAdd) == 0 && len(tt.wantAdd) == 0 {
				gotAdd = nil
			}
			if len(gotDelete) == 0 && len(tt.wantDelete) == 0 {
				gotDelete = nil
			}

			if !reflect.DeepEqual(gotAdd, tt.wantAdd) {
				t.Errorf("toAdd = %v, want %v", gotAdd, tt.wantAdd)
			}
			if !reflect.DeepEqual(gotDelete, tt.wantDelete) {
				t.Errorf("toDelete = %v, want %v", gotDelete, tt.wantDelete)
			}
		})
	}
}

// TestPathExtraction verifies routing helpers for credential and workflow shares.
func TestPathExtraction(t *testing.T) {
	t.Run("credential share path match", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/rest/credentials/cred-abc/share", nil)
		if !isCredentialSharePath(req.URL.Path) {
			t.Errorf("expected isCredentialSharePath to be true for %s", req.URL.Path)
		}
		if got := extractCredentialPathID(req); got != "cred-abc" {
			t.Errorf("extractCredentialPathID() = %q, want %q", got, "cred-abc")
		}

		reqSlash := httptest.NewRequest(http.MethodPut, "/rest/credentials/cred-abc/share/", nil)
		if !isCredentialSharePath(reqSlash.URL.Path) {
			t.Errorf("expected isCredentialSharePath to be true with trailing slash")
		}
		if got := extractCredentialPathID(reqSlash); got != "cred-abc" {
			t.Errorf("extractCredentialPathID() with trailing slash = %q, want %q", got, "cred-abc")
		}
	})

	t.Run("workflow share path match", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/rest/workflows/wf-xyz/share", nil)
		if !isWorkflowSharePath(req.URL.Path) {
			t.Errorf("expected isWorkflowSharePath to be true for %s", req.URL.Path)
		}
		if got := extractWorkflowPathID(req); got != "wf-xyz" {
			t.Errorf("extractWorkflowPathID() = %q, want %q", got, "wf-xyz")
		}

		reqSlash := httptest.NewRequest(http.MethodPut, "/rest/workflows/wf-xyz/share/", nil)
		if !isWorkflowSharePath(reqSlash.URL.Path) {
			t.Errorf("expected isWorkflowSharePath to be true with trailing slash")
		}
		if got := extractWorkflowPathID(reqSlash); got != "wf-xyz" {
			t.Errorf("extractWorkflowPathID() with trailing slash = %q, want %q", got, "wf-xyz")
		}
	})

	t.Run("missing credential id returns empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/rest/credentials//share", nil)
		if got := extractCredentialPathID(req); got != "" {
			t.Errorf("extractCredentialPathID() = %q, want empty", got)
		}
	})

	t.Run("missing workflow id returns empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/rest/workflows//share", nil)
		if got := extractWorkflowPathID(req); got != "" {
			t.Errorf("extractWorkflowPathID() = %q, want empty", got)
		}
	})
}

// TestHandlerHTTPValidation tests HTTP method checking and unauthenticated requests.
func TestHandlerHTTPValidation(t *testing.T) {
	h := &Handler{}

	t.Run("method not allowed for GET on credential share", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rest/credentials/123/share", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405 Method Not Allowed, got %d", rec.Code)
		}
	})

	t.Run("unauthenticated credential share request returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/rest/credentials/123/share", strings.NewReader(`{"shareWithIds":[]}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("unauthenticated workflow share request returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/rest/workflows/456/share", strings.NewReader(`{"shareWithIds":[]}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("unauthenticated GET credential returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rest/credentials/cred-abc", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401 Unauthorized, got %d", rec.Code)
		}
	})
}

// TestSpecialCredentialSubpaths verifies special subpath discrimination.
func TestSpecialCredentialSubpaths(t *testing.T) {
	specials := []string{"for-workflow", "test", "schema"}
	for _, s := range specials {
		if !isSpecialCredentialSubpath(s) {
			t.Errorf("expected %q to be recognized as special credential subpath", s)
		}
	}

	regularIDs := []string{"iMjvivyfWB5flRsO", "1JleLoeJBCcjTiP2", "cred-123", "a12aca7b"}
	for _, id := range regularIDs {
		if isSpecialCredentialSubpath(id) {
			t.Errorf("expected %q NOT to be special credential subpath", id)
		}
	}
}

// TestTransparentProxyRouting verifies transparent proxy path forwarding.
func TestTransparentProxyRouting(t *testing.T) {
	mockN8N := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proxied-By-Mock", "true")
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/rest/credentials/for-workflow" {
			_, _ = w.Write([]byte(`{"data":[{"id":"c1","name":"Cred 1"}]}`))
			return
		}
		if r.URL.Path == "/rest/credentials/test" && r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"data":{"status":"ok"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer mockN8N.Close()

	h := &Handler{
		n8nBaseURL: mockN8N.URL,
		client:     mockN8N.Client(),
	}

	t.Run("proxy for-workflow endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rest/credentials/for-workflow?workflowId=123", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if rec.Header().Get("X-Proxied-By-Mock") != "true" {
			t.Fatalf("expected proxy header from mock n8n")
		}
		if !strings.Contains(rec.Body.String(), `"id":"c1"`) {
			t.Fatalf("unexpected body: %s", rec.Body.String())
		}
	})

	t.Run("proxy post test endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/rest/credentials/test", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
			t.Fatalf("unexpected body: %s", rec.Body.String())
		}
	})
}
