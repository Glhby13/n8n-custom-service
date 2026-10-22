package workflow

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func mustDecode(t *testing.T, s string) map[string]any {
	t.Helper()
	m, err := DecodeObject([]byte(s))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestCanonicalIsDeterministic(t *testing.T) {
	a := mustDecode(t, `{"b":1,"a":{"z":[3,2,1],"y":"<x>"},"n":1.50}`)
	b := mustDecode(t, `{"n":1.50,  "a":{"y":"<x>","z":[3,2,1]},"b":1}`)
	ca, err := Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := Canonical(b)
	if !bytes.Equal(ca, cb) {
		t.Fatalf("not deterministic:\n%s\n%s", ca, cb)
	}
	want := "{\n  \"a\": {\n    \"y\": \"<x>\",\n    \"z\": [\n      3,\n      2,\n      1\n    ]\n  },\n  \"b\": 1,\n  \"n\": 1.50\n}\n"
	if string(ca) != want {
		t.Fatalf("unexpected canonical form:\n%q\nwant\n%q", ca, want)
	}
	again, _ := CanonicalizeBytes(ca)
	if !bytes.Equal(again, ca) {
		t.Fatal("canonicalisation is not idempotent")
	}
	for i := 0; i < 50; i++ {
		c, _ := Canonical(mustDecode(t, `{"k3":1,"k1":2,"k2":{"b":1,"a":2}}`))
		d, _ := Canonical(mustDecode(t, `{"k2":{"a":2,"b":1},"k1":2,"k3":1}`))
		if !bytes.Equal(c, d) {
			t.Fatal("map ordering leaked into output")
		}
	}
}

func TestEqualIgnoresFormatting(t *testing.T) {
	if !Equal([]byte(`{"a":1,"b":[1,2]}`), []byte("{\n \"b\": [1, 2], \"a\": 1}\n")) {
		t.Fatal("semantically equal documents differ")
	}
	if Equal([]byte(`{"a":1}`), []byte(`{"a":2}`)) {
		t.Fatal("different documents compare equal")
	}
	if Equal([]byte(`not json`), []byte(`not json`)) {
		t.Fatal("invalid JSON must never compare equal")
	}
}

func TestDecodeObjectRejectsBadInput(t *testing.T) {
	for _, in := range []string{`{"a":1} {"b":2}`, `[1,2]`, `{"a":`, ``, `"str"`} {
		if _, err := DecodeObject([]byte(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestValidators(t *testing.T) {
	for _, ok := range []string{"123", "AbC_9-x", strings.Repeat("a", 64)} {
		if !ValidID(ok) {
			t.Errorf("ValidID(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", "a.json", "a b", strings.Repeat("a", 65), "%2e%2e"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q) = true", bad)
		}
	}
	if !ValidSHA(strings.Repeat("aB3", 13)+"f") || ValidSHA("abc123") || ValidSHA(strings.Repeat("g", 40)) || ValidSHA(strings.Repeat("a", 41)) {
		t.Error("ValidSHA misbehaves")
	}
	if FileName("123") != "123.json" {
		t.Error("FileName")
	}
}

func sampleSource(t *testing.T) Source {
	nodes := mustDecode(t, `{"n":[
	  {"id":"n1","name":"HTTP","type":"n8n-nodes-base.httpRequest","typeVersion":4,"position":[0,0],
	   "parameters":{"url":"https://x","headerParameters":{"parameters":[{"name":"Authorization","value":"Bearer abc"}]},"apiKey":"k-123","password":""},
	   "credentials":{"httpHeaderAuth":{"id":"7","name":"Header","data":"SHOULD-NOT-SURVIVE"}}},
	  {"id":"n2","name":"Set","type":"n8n-nodes-base.set","typeVersion":3,"position":[200,0],"parameters":{}}
	]}`)["n"]
	return Source{
		ID: "123", Name: "Example", Nodes: nodes,
		Connections: mustDecode(t, `{"HTTP":{"main":[[{"node":"Set","type":"main","index":0}]]}}`),
		Settings:    mustDecode(t, `{"executionOrder":"v1","unknownSetting":true}`),
		Meta:        mustDecode(t, `{"templateCredsSetupCompleted":true}`),
		Tags:        []string{"b", "a"},
	}
}

func TestBuildDefinitionWhitelistAndCredentials(t *testing.T) {
	def, err := BuildDefinition(sampleSource(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "name", "nodes", "connections", "settings", "meta", "tags", FormatKey} {
		if _, ok := def[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if len(def) != 8 {
		t.Errorf("unexpected keys: %v", def)
	}
	out, _ := Canonical(def)
	if strings.Contains(string(out), "SHOULD-NOT-SURVIVE") {
		t.Fatal("credential data leaked into definition")
	}
	if !strings.Contains(string(out), `"httpHeaderAuth": {`) || !strings.Contains(string(out), `"id": "7"`) {
		t.Fatal("credential reference was not kept")
	}
	if def["tags"].([]any)[0] != "a" {
		t.Error("tags not sorted")
	}
	if _, err := BuildDefinition(Source{ID: "../x", Nodes: []any{}}, nil); err == nil {
		t.Error("invalid id accepted")
	}
	if _, err := BuildDefinition(Source{ID: "1", Nodes: "x"}, nil); err == nil {
		t.Error("non-array nodes accepted")
	}
}

func TestRedactionIsConfigurable(t *testing.T) {
	def, _ := BuildDefinition(sampleSource(t), []string{"api_key", "value"})
	out, _ := Canonical(def)
	s := string(out)
	if strings.Contains(s, "k-123") || strings.Contains(s, "Bearer abc") {
		t.Fatalf("value not redacted:\n%s", s)
	}
	if !strings.Contains(s, RedactedMarker) {
		t.Fatal("marker missing")
	}
	if !strings.Contains(s, `"password": ""`) {
		t.Error("empty values must be left alone")
	}
	plain, _ := BuildDefinition(sampleSource(t), nil)
	p, _ := Canonical(plain)
	if !strings.Contains(string(p), "k-123") {
		t.Error("without REDACT_PARAMETER_KEYS parameters are stored as-is")
	}
}

func TestValidate(t *testing.T) {
	good := mustDecode(t, `{"id":"123","name":"x","nodes":[],"connections":{},"settings":{}}`)
	if err := Validate(good, "123"); err != nil {
		t.Fatal(err)
	}
	if err := Validate(good, "999"); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("id mismatch not detected: %v", err)
	}
	cases := []string{
		`{"name":"x","nodes":[],"connections":{}}`,
		`{"id":"123","nodes":[],"connections":{}}`,
		`{"id":"123","name":"x","nodes":{},"connections":{}}`,
		`{"id":"123","name":"x","nodes":[],"connections":[]}`,
		`{"id":"123","name":"x","nodes":[],"connections":{},"settings":"no"}`,
	}
	for _, c := range cases {
		if err := Validate(mustDecode(t, c), "123"); err == nil {
			t.Errorf("accepted invalid %s", c)
		}
	}
}

func TestRestoreBodyFiltersAndRefillsRedacted(t *testing.T) {
	def, _ := BuildDefinition(sampleSource(t), []string{"apiKey"})
	defJSON, _ := Canonical(def)
	stored := mustDecode(t, string(defJSON))
	stored["nodes"].([]any)[0].(map[string]any)["unknownNodeField"] = true

	current := map[string]any{"nodes": []any{map[string]any{"id": "n1", "name": "HTTP", "parameters": map[string]any{"apiKey": "k-live"}}}}
	body, err := RestoreBody(stored, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 4 {
		t.Fatalf("body keys: %v", body)
	}
	n1 := body["nodes"].([]any)[0].(map[string]any)
	if n1["parameters"].(map[string]any)["apiKey"] != "k-live" {
		t.Fatal("redacted value not refilled from current workflow")
	}
	if _, ok := n1["unknownNodeField"]; ok {
		t.Fatal("node keys rejected by n8n must be dropped")
	}
	if _, ok := body["settings"].(map[string]any)["unknownSetting"]; ok {
		t.Fatal("settings rejected by n8n must be dropped")
	}
	if body["settings"].(map[string]any)["executionOrder"] != "v1" {
		t.Fatal("allowed setting dropped")
	}
	if _, ok := stored["nodes"].([]any)[0].(map[string]any)["unknownNodeField"]; !ok {
		t.Fatal("RestoreBody must not mutate its input")
	}

	_, err = RestoreBody(stored, map[string]any{"nodes": []any{}})
	if !errors.Is(err, ErrUnrecoverableRedaction) {
		t.Fatalf("expected ErrUnrecoverableRedaction, got %v", err)
	}
}
