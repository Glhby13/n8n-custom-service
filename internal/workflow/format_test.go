package workflow

import (
	"strings"
	"testing"
)

func TestFormatVersionWritten(t *testing.T) {
	def, _ := BuildDefinition(codeSource("a\nb"), nil)
	if def[FormatKey] != FormatVersion {
		t.Fatalf("formatVersion missing: %v", def[FormatKey])
	}
	out, _ := Canonical(def)
	if !strings.Contains(string(out), `"formatVersion": 2`) {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(MigrationDescription(), "formatVersion 2") || FormatNotes[FormatVersion] == "" {
		t.Fatal("every format version needs a note")
	}
}

func TestSameContentIgnoresRepresentation(t *testing.T) {
	def, _ := BuildDefinition(codeSource("line 1\nline 2"), nil)
	// Old format: no formatVersion, code as one string, different key order/indent.
	old := `{"name":"Code wf","id":"wf1","connections":{},"settings":{},
	  "nodes":[{"parameters":{"jsCode":"line 1\nline 2","options":{"query":"SELECT 1\nFROM dual","single":"one line"},"list":["a\nb","c"]},
	  "id":"c1","name":"Config","type":"n8n-nodes-base.code","typeVersion":2}]}`
	if !SameContent([]byte(old), def) {
		t.Fatal("old-format file with identical content must count as same content")
	}
	changed := strings.Replace(old, "line 2", "line 3", 1)
	if SameContent([]byte(changed), def) {
		t.Fatal("a real code change must not count as a format migration")
	}
	renamed := strings.Replace(old, `"name":"Code wf"`, `"name":"Other"`, 1)
	if SameContent([]byte(renamed), def) {
		t.Fatal("a rename is a content change")
	}
	if SameContent([]byte("not json"), def) {
		t.Fatal("invalid stored JSON is never the same content")
	}
}

func TestOldFormatsStillRestore(t *testing.T) {
	old := mustDecode(t, `{"id":"wf1","name":"x","connections":{},"settings":{},
	  "nodes":[{"id":"c1","name":"Config","parameters":{"jsCode":"a\nb"}}]}`)
	v2, _ := BuildDefinition(codeSource("a\nb"), nil)
	for _, def := range []map[string]any{old, v2} {
		if err := Validate(def, "wf1"); err != nil {
			t.Fatal(err)
		}
		body, err := RestoreBody(def, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := body[FormatKey]; ok {
			t.Fatal("formatVersion must never be sent to n8n")
		}
	}
}
