package workflow

import (
	"errors"
	"strings"
	"testing"
)

func codeSource(code string) Source {
	return Source{
		ID: "wf1", Name: "Code wf",
		Nodes: []any{map[string]any{
			"id": "c1", "name": "Config", "type": "n8n-nodes-base.code", "typeVersion": 2,
			"parameters": map[string]any{
				"jsCode":  code,
				"options": map[string]any{"query": "SELECT 1\nFROM dual", "single": "one line"},
				"list":    []any{"a\nb", "c"},
			},
		}},
		Connections: map[string]any{},
	}
}

func TestMultilineStringsStoredAsLines(t *testing.T) {
	code := "// header\nconst a = 1;\n\nreturn [{ json: { a } }];\n"
	def, err := BuildDefinition(codeSource(code), nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Canonical(def)
	s := string(out)
	if !strings.Contains(s, "\"jsCode\": {\n") || !strings.Contains(s, "\"const a = 1;\",\n") {
		t.Fatalf("code not stored one line per line:\n%s", s)
	}
	if !strings.Contains(s, `"single": "one line"`) {
		t.Fatal("single-line strings must stay plain")
	}

	// A one-character edit changes exactly one stored line.
	def2, _ := BuildDefinition(codeSource(strings.Replace(code, "const a = 1;", "const a = 12;", 1)), nil)
	out2, _ := Canonical(def2)
	a, b := strings.Split(s, "\n"), strings.Split(string(out2), "\n")
	if len(a) != len(b) {
		t.Fatalf("line count changed: %d vs %d", len(a), len(b))
	}
	changed := 0
	for i := range a {
		if a[i] != b[i] {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("expected exactly 1 changed line, got %d", changed)
	}
}

func TestLinesRoundTripIsLossless(t *testing.T) {
	for _, code := range []string{
		"a\nb", "a\nb\n", "\n", "\n\nx\n\n", "crlf\r\nline\r\n", "tabs\t\n  indented\n",
	} {
		def, _ := BuildDefinition(codeSource(code), nil)
		raw, _ := Canonical(def)
		stored, err := DecodeObject(raw)
		if err != nil {
			t.Fatal(err)
		}
		body, err := RestoreBody(stored, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		p := body["nodes"].([]any)[0].(map[string]any)["parameters"].(map[string]any)
		if p["jsCode"] != code {
			t.Errorf("round trip changed %q into %q", code, p["jsCode"])
		}
		if p["options"].(map[string]any)["query"] != "SELECT 1\nFROM dual" {
			t.Error("nested multi-line string not restored")
		}
		if p["list"].([]any)[0] != "a\nb" {
			t.Error("multi-line string inside array not restored")
		}
	}
}

func TestOldFormatStillRestores(t *testing.T) {
	old := mustDecode(t, `{"id":"wf1","name":"x","connections":{},"settings":{},
	  "nodes":[{"id":"c1","name":"Config","parameters":{"jsCode":"a\nb"}}]}`)
	body, err := RestoreBody(old, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if body["nodes"].([]any)[0].(map[string]any)["parameters"].(map[string]any)["jsCode"] != "a\nb" {
		t.Fatal("plain-string (old format) code must restore unchanged")
	}
}

func TestLinesKeyOnlyWhenExactShape(t *testing.T) {
	// An object that merely contains __lines__ next to other keys is left alone.
	v := joinLines(map[string]any{LinesKey: []any{"a"}, "other": 1}).(map[string]any)
	if _, ok := v[LinesKey]; !ok {
		t.Fatal("non-exact shape must not be joined")
	}
	if joinLines(map[string]any{LinesKey: []any{"a", 1}}).(map[string]any)[LinesKey] == nil {
		t.Fatal("non-string lines must not be joined")
	}
}

func TestRedactionStillWorksWithLines(t *testing.T) {
	src := codeSource("x")
	src.Nodes.([]any)[0].(map[string]any)["parameters"].(map[string]any)["password"] = "multi\nline secret"
	def, _ := BuildDefinition(src, []string{"password"})
	out, _ := Canonical(def)
	if strings.Contains(string(out), "secret") || !strings.Contains(string(out), `"password": "`+RedactedMarker+`"`) {
		t.Fatalf("redaction must apply before line splitting:\n%s", out)
	}
}

func TestNodeGroupsPersistedAndRestored(t *testing.T) {
	src := codeSource("x")
	src.NodeGroups = []any{map[string]any{"id": "g1", "name": "Frame", "nodeIds": []any{"c1"}}}
	def, _ := BuildDefinition(src, nil)
	if _, ok := def["nodeGroups"]; !ok {
		t.Fatal("nodeGroups not persisted")
	}
	body, _ := RestoreBody(def, map[string]any{})
	if _, ok := body["nodeGroups"]; !ok {
		t.Fatal("nodeGroups not restored via API body")
	}
	_, _, groups, err := VersionPayload(def, map[string]any{})
	if err != nil || len(groups) != 1 {
		t.Fatalf("VersionPayload groups %v %v", groups, err)
	}
	empty, _ := BuildDefinition(codeSource("x"), nil)
	if _, ok := empty["nodeGroups"]; ok {
		t.Fatal("empty nodeGroups must not be stored (avoids churn)")
	}
}

func TestVersionPayloadJoinsAndRefills(t *testing.T) {
	src := codeSource("a\nb")
	src.Nodes.([]any)[0].(map[string]any)["parameters"].(map[string]any)["apiKey"] = "k"
	def, _ := BuildDefinition(src, []string{"apiKey"})
	raw, _ := Canonical(def)
	stored, _ := DecodeObject(raw)
	cur := map[string]any{"nodes": []any{map[string]any{"id": "c1", "parameters": map[string]any{"apiKey": "live"}}}}
	nodes, _, _, err := VersionPayload(stored, cur)
	if err != nil {
		t.Fatal(err)
	}
	p := nodes[0].(map[string]any)["parameters"].(map[string]any)
	if p["jsCode"] != "a\nb" || p["apiKey"] != "live" {
		t.Fatalf("payload params %v", p)
	}
	if _, _, _, err := VersionPayload(stored, map[string]any{}); !errors.Is(err, ErrUnrecoverableRedaction) {
		t.Fatalf("expected unrecoverable redaction, got %v", err)
	}
}
