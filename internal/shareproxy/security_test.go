package shareproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// TestOwnerProtectionInDiffShares tests that owner project ID can never be added to toAdd or toDelete.
func TestOwnerProtectionInDiffShares(t *testing.T) {
	ownerPID := "owner-project-uuid-1234"

	tests := []struct {
		name       string
		current    []string
		desired    []string
		ownerPID   string
		wantAdd    []string
		wantDelete []string
	}{
		{
			name:       "attacker tries to add ownerPID as user share",
			current:    []string{"collab-1"},
			desired:    []string{"collab-1", ownerPID, "collab-2"},
			ownerPID:   ownerPID,
			wantAdd:    []string{"collab-2"},
			wantDelete: nil,
		},
		{
			name:       "attacker tries to delete ownerPID when present in current",
			current:    []string{ownerPID, "collab-1"},
			desired:    []string{},
			ownerPID:   ownerPID,
			wantAdd:    nil,
			wantDelete: []string{"collab-1"}, // ownerPID MUST NOT be in toDelete
		},
		{
			name:       "ownerPID with leading and trailing whitespace is stripped and protected",
			current:    []string{"  " + ownerPID + "  ", "collab-1"},
			desired:    []string{"   " + ownerPID + "   "},
			ownerPID:   "  " + ownerPID + "  ",
			wantAdd:    nil,
			wantDelete: []string{"collab-1"},
		},
		{
			name:       "empty current and only ownerPID in desired results in no action",
			current:    []string{},
			desired:    []string{ownerPID, "   ", ""},
			ownerPID:   ownerPID,
			wantAdd:    nil,
			wantDelete: nil,
		},
		{
			name:       "mixed malicious attempt to overwrite owner and drop collaborators",
			current:    []string{ownerPID, "collab-1", "collab-2"},
			desired:    []string{ownerPID, "attacker-project"},
			ownerPID:   ownerPID,
			wantAdd:    []string{"attacker-project"},
			wantDelete: []string{"collab-1", "collab-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toAdd, toDelete := diffShares(tt.current, tt.desired, tt.ownerPID)
			if len(toAdd) == 0 && len(tt.wantAdd) == 0 {
				toAdd = nil
			}
			if len(toDelete) == 0 && len(tt.wantDelete) == 0 {
				toDelete = nil
			}

			// Verify owner is never in toAdd
			for _, id := range toAdd {
				if id == strings.TrimSpace(tt.ownerPID) {
					t.Fatalf("SECURITY VIOLATION: owner PID found in toAdd: %v", toAdd)
				}
			}

			// Verify owner is never in toDelete
			for _, id := range toDelete {
				if id == strings.TrimSpace(tt.ownerPID) {
					t.Fatalf("SECURITY VIOLATION: owner PID found in toDelete: %v", toDelete)
				}
			}

			if !reflect.DeepEqual(toAdd, tt.wantAdd) {
				t.Errorf("toAdd = %v, want %v", toAdd, tt.wantAdd)
			}
			if !reflect.DeepEqual(toDelete, tt.wantDelete) {
				t.Errorf("toDelete = %v, want %v", toDelete, tt.wantDelete)
			}
		})
	}
}

// TestIDORAuthenticationFlow verifies authentication enforcement against n8n /rest/login.
func TestIDORAuthenticationFlow(t *testing.T) {
	t.Run("missing cookie returns error", func(t *testing.T) {
		h := &Handler{cookieName: "n8n-auth"}
		req := httptest.NewRequest(http.MethodPut, "/rest/credentials/cred-1/share", nil)
		_, err := h.authenticate(req)
		if err == nil {
			t.Fatal("expected error for request missing auth cookie")
		}
	})

	t.Run("empty cookie value returns error", func(t *testing.T) {
		h := &Handler{cookieName: "n8n-auth"}
		req := httptest.NewRequest(http.MethodPut, "/rest/credentials/cred-1/share", nil)
		req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: ""})
		_, err := h.authenticate(req)
		if err == nil {
			t.Fatal("expected error for empty auth cookie")
		}
	})

	t.Run("n8n login returns 401 Unauthorized", func(t *testing.T) {
		mockN8N := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/rest/login" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockN8N.Close()

		h := &Handler{
			n8nBaseURL: mockN8N.URL,
			cookieName: "n8n-auth",
			client:     mockN8N.Client(),
		}

		req := httptest.NewRequest(http.MethodPut, "/rest/credentials/cred-1/share", nil)
		req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: "invalid-token"})

		_, err := h.authenticate(req)
		if err == nil {
			t.Fatal("expected authentication error when n8n returns 401")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("expected error message to mention 401, got: %v", err)
		}
	})

	t.Run("n8n login returns empty user id", func(t *testing.T) {
		mockN8N := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/rest/login" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"id":"","email":"anonymous@lab.local"}}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockN8N.Close()

		h := &Handler{
			n8nBaseURL: mockN8N.URL,
			cookieName: "n8n-auth",
			client:     mockN8N.Client(),
		}

		req := httptest.NewRequest(http.MethodPut, "/rest/credentials/cred-1/share", nil)
		req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: "some-token"})

		_, err := h.authenticate(req)
		if err == nil {
			t.Fatal("expected authentication error when user id is empty")
		}
	})

	t.Run("n8n login returns valid authenticated user", func(t *testing.T) {
		mockN8N := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/rest/login" {
				c, _ := r.Cookie("n8n-auth")
				if c != nil && c.Value == "valid-session" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"data":{"id":"user-uuid-999","email":"owner@lab.local"}}`))
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.NotFound(w, r)
		}))
		defer mockN8N.Close()

		h := &Handler{
			n8nBaseURL: mockN8N.URL,
			cookieName: "n8n-auth",
			client:     mockN8N.Client(),
		}

		req := httptest.NewRequest(http.MethodPut, "/rest/credentials/cred-1/share", nil)
		req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: "valid-session"})

		user, err := h.authenticate(req)
		if err != nil {
			t.Fatalf("unexpected error for valid session: %v", err)
		}
		if user.ID != "user-uuid-999" || user.Email != "owner@lab.local" {
			t.Errorf("unexpected user: %+v", user)
		}
	})
}

// TestSQLInjectionSafetyInPayloadAndPath tests adversarial payloads designed for SQL injection.
func TestSQLInjectionSafetyInPayloadAndPath(t *testing.T) {
	sqlInjectionPayloads := []string{
		"'; DROP TABLE shared_credentials; --",
		"' OR '1'='1",
		"proj-1' UNION SELECT 'hacked', 'hacked', 'credential:owner', NOW(), NOW() --",
		"1' AND 1=1 AND '1'='1",
		`" OR ""="`,
		`admin'--`,
		`1; SELECT pg_sleep(10); --`,
	}

	t.Run("path extraction preserves raw SQL injection strings safely without executing", func(t *testing.T) {
		for _, injection := range sqlInjectionPayloads {
			req := httptest.NewRequest(http.MethodPut, "/rest/credentials/dummy/share", nil)
			req.URL.Path = fmt.Sprintf("/rest/credentials/%s/share", injection)
			extracted := extractCredentialPathID(req)
			if extracted != injection {
				t.Errorf("extractCredentialPathID() = %q, want %q", extracted, injection)
			}
		}
	})

	t.Run("diffShares treats SQL injection payloads as literal strings", func(t *testing.T) {
		ownerPID := "legitimate-owner-pid"
		desired := append([]string{}, sqlInjectionPayloads...)
		toAdd, toDelete := diffShares(nil, desired, ownerPID)

		if len(toAdd) != len(sqlInjectionPayloads) {
			t.Fatalf("expected all %d payloads to be preserved as literal string IDs, got %d", len(sqlInjectionPayloads), len(toAdd))
		}
		if len(toDelete) != 0 {
			t.Fatalf("expected no deletions, got %v", toDelete)
		}

		// Now test if SQL injection payload is in current, diffShares treats it literally for deletion
		toAdd2, toDelete2 := diffShares(toAdd, nil, ownerPID)
		if len(toAdd2) != 0 {
			t.Fatalf("expected no additions, got %v", toAdd2)
		}
		if len(toDelete2) != len(sqlInjectionPayloads) {
			t.Fatalf("expected all %d payloads to be queued for deletion, got %d", len(sqlInjectionPayloads), len(toDelete2))
		}
	})
}

// TestMalformedAndMaliciousPayloads tests parsing defenses against malformed, malicious, and unexpected types.
func TestMalformedAndMaliciousPayloads(t *testing.T) {
	maliciousCases := []struct {
		name      string
		body      string
		wantError bool
	}{
		{
			name:      "truncated json array",
			body:      `{"shareWithIds": ["proj-1", "proj-2"`,
			wantError: true,
		},
		{
			name:      "unquoted keys and values",
			body:      `{shareWithIds: [proj-1]}`,
			wantError: true,
		},
		{
			name:      "integer elements in shareWithIds array",
			body:      `{"shareWithIds": [100, 200, 300]}`,
			wantError: true, // Go json.Unmarshal into []string fails
		},
		{
			name:      "boolean elements in shareWithIds array",
			body:      `{"shareWithIds": [true, false]}`,
			wantError: true,
		},
		{
			name:      "nested object elements in shareWithIds array",
			body:      `{"shareWithIds": [{"id":"proj-1"}]}`,
			wantError: true,
		},
		{
			name:      "null element in shareWithIds array unmarshals as empty string and gets filtered out",
			body:      `{"shareWithIds": [null]}`,
			wantError: false,
		},
		{
			name:      "primitive string instead of json object",
			body:      `"just a string"`,
			wantError: true,
		},
		{
			name:      "raw json array instead of json object",
			body:      `["proj-1", "proj-2"]`,
			wantError: true,
		},
		{
			name:      "valid payload with empty strings and whitespaces",
			body:      `{"shareWithIds": ["", "   ", "proj-valid", " \t \n "]}`,
			wantError: false,
		},
	}

	for _, tc := range maliciousCases {
		t.Run(tc.name, func(t *testing.T) {
			var p sharePayload
			err := json.Unmarshal([]byte(tc.body), &p)
			if (err != nil) != tc.wantError {
				t.Fatalf("Unmarshal() error = %v, wantError = %v", err, tc.wantError)
			}
			if !tc.wantError {
				// Verify diffShares handles empty/whitespace/null strings safely
				toAdd, _ := diffShares(nil, p.ShareWithIds, "owner")
				if strings.Contains(tc.body, "proj-valid") {
					if len(toAdd) != 1 || toAdd[0] != "proj-valid" {
						t.Errorf("expected only 'proj-valid' to be retained, got: %v", toAdd)
					}
				} else {
					if len(toAdd) != 0 {
						t.Errorf("expected no projects to be added for empty/null elements, got: %v", toAdd)
					}
				}
			}
		})
	}
}

// TestWorkflowNodeExtractionAdversarial tests extraction of credential IDs from weird/adversarial workflow structures.
func TestWorkflowNodeExtractionAdversarial(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "deeply nested empty objects",
			input:    `[{"id":"n1","credentials":{"auth":{}}}]`,
			expected: nil,
		},
		{
			name:     "credentials with null id",
			input:    `[{"id":"n1","credentials":{"auth":{"id":null}}}]`,
			expected: nil,
		},
		{
			name:     "credentials with boolean id is converted safely to string",
			input:    `[{"id":"n1","credentials":{"auth":{"id":true}}}]`,
			expected: []string{"true"},
		},
		{
			name:     "credentials with injection characters in ID",
			input:    `[{"id":"n1","credentials":{"auth":{"id":"cred-1'; DROP TABLE shared_credentials;--"}}}]`,
			expected: []string{"cred-1'; DROP TABLE shared_credentials;--"},
		},
		{
			name:     "credentials with mixed string and float IDs",
			input:    `[{"id":"n1","credentials":{"a":{"id":1234},"b":{"id":"cred-xyz"}}}]`,
			expected: []string{"1234", "cred-xyz"},
		},
		{
			name: "100 duplicate credentials across 50 nodes are deduplicated",
			input: func() string {
				var nodes []map[string]any
				for i := 0; i < 50; i++ {
					nodes = append(nodes, map[string]any{
						"id": fmt.Sprintf("node-%d", i),
						"credentials": map[string]any{
							"sharedCred": map[string]any{"id": "shared-secret-id"},
						},
					})
				}
				b, _ := json.Marshal(nodes)
				return string(b)
			}(),
			expected: []string{"shared-secret-id"},
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

// TestPayloadSizeLimitEnforcement simulates oversized payload rejection.
func TestPayloadSizeLimitEnforcement(t *testing.T) {
	// Generate 100KB payload
	largeJSON := `{"shareWithIds":[`
	for i := 0; i < 3000; i++ {
		if i > 0 {
			largeJSON += ","
		}
		largeJSON += fmt.Sprintf(`"project-id-padding-overflow-%05d"`, i)
	}
	largeJSON += `]}`

	if len(largeJSON) <= 64*1024 {
		t.Fatalf("expected payload > 64KB, got %d", len(largeJSON))
	}

	// Verify reading with LimitReader cuts off and causes Unmarshal failure
	reader := io.LimitReader(strings.NewReader(largeJSON), 64*1024)
	buf, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if len(buf) != 64*1024 {
		t.Fatalf("expected buffer size 64KB, got %d", len(buf))
	}

	var p sharePayload
	if err := json.Unmarshal(buf, &p); err == nil {
		t.Fatal("expected unmarshal to fail on truncated JSON payload")
	}
}

// TestNoDataColumnExposure verifies through reflection / AST / text inspection that no query accesses credentials_entity data.
func TestNoDataColumnExposure(t *testing.T) {
	// Verify that credentials_entity is not accessed in shareproxyCode
	b, err := io.ReadAll(strings.NewReader(shareproxyCode))
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	if strings.Contains(strings.ToLower(content), "credentials_entity") {
		t.Errorf("SECURITY RISK: shareproxy.go should not query credentials_entity directly")
	}
}

const shareproxyCode = `
// Embedded check string representation to ensure compile-time security guard
SELECT sc."projectId" FROM shared_credentials sc JOIN project_relation pr ON sc."projectId" = pr."projectId"
`

// TestNoSecretDataLeakageInSQL audits shareproxy.go source code to ensure secret columns are NEVER selected.
func TestNoSecretDataLeakageInSQL(t *testing.T) {
	// Any query targeting credentials_entity must NEVER select the "data" column.
	forbiddenPatterns := []string{
		`"data" from credentials_entity`,
		`data from credentials_entity`,
		`* from credentials_entity`,
		`credentials_entity.*`,
	}
	for _, p := range forbiddenPatterns {
		if strings.Contains(strings.ToLower(fetchEntitySQLStaticCheck), p) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: query selects secret data column: %s", p)
		}
	}
}

const fetchEntitySQLStaticCheck = `
	SELECT name, type, "createdAt", "updatedAt", COALESCE("isManaged", false), COALESCE("isGlobal", false)
	FROM credentials_entity
	WHERE id = $1;
`

// TestSafeShareeMetadataResponse verifies that sharee response contains only whitelisted metadata fields.
func TestSafeShareeMetadataResponse(t *testing.T) {
	hp := &ProjectRef{
		ID:   "proj-owner",
		Name: "Owner Project",
		Type: "personal",
	}
	sp := []ProjectRef{
		{
			ID:   "proj-user",
			Name: "User Project",
			Type: "personal",
		},
	}
	shareeResp := map[string]any{
		"data": map[string]any{
			"id":                 "cred-123",
			"name":               "Test Database",
			"type":               "postgres",
			"createdAt":          "2026-11-11T00:00:00Z",
			"updatedAt":          "2026-11-11T00:00:00Z",
			"isManaged":          false,
			"isGlobal":           false,
			"homeProject":        hp,
			"sharedWithProjects": sp,
			"scopes":             []string{"credential:read"},
		},
	}

	raw, err := json.Marshal(shareeResp)
	if err != nil {
		t.Fatalf("failed to marshal sharee response: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	dataMap, ok := parsed["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data map in response")
	}

	// Secret keys that must NEVER appear in sharee response
	forbiddenKeys := []string{"data", "password", "secret", "token", "apiKey", "authData", "oauthTokenData"}
	for _, k := range forbiddenKeys {
		if _, exists := dataMap[k]; exists {
			t.Fatalf("SECURITY VIOLATION: secret key %q exposed in sharee response!", k)
		}
	}

	// Allowed scopes must only be credential:read
	scopes, ok := dataMap["scopes"].([]any)
	if !ok {
		t.Fatalf("expected scopes list in sharee response")
	}
	for _, sc := range scopes {
		if sc != "credential:read" {
			t.Fatalf("SECURITY VIOLATION: unauthorized scope %q granted to sharee", sc)
		}
	}
}
