package workflow

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// FormatKey is the field in <id>.json that records how the file is written.
const FormatKey = "formatVersion"

// FormatVersion is the current file format. Bump it (and add a FormatNotes entry) whenever the
// way files are written changes; the next reconciliation (pod start) then rewrites every
// published workflow once, as a commit labelled as a format migration. Every format must stay
// restorable by later versions of the service.
//
//	(none) 2026-10-20 first files: one string per Code node, "chore(n8n): publish workflow ..." subjects
//	2      2026-10-20 multi-line text as __lines__, nodeGroups, subject = workflow name, N8n-* trailers
const FormatVersion = 2

// FormatNotes describes each format version (used in the migration commit message).
var FormatNotes = map[int]string{
	2: "teks multi-baris per baris (__lines__), nodeGroups, judul commit = nama workflow, trailer N8n-*",
}

// MigrationDescription is the commit body text of a format-only commit.
func MigrationDescription() string {
	return fmt.Sprintf("Format file diperbarui ke formatVersion %d: %s. Isi workflow tidak berubah.",
		FormatVersion, FormatNotes[FormatVersion])
}

// SameContent reports whether two stored workflow files describe the same workflow, ignoring how
// they are written: formatVersion, multi-line text representation, key order and indentation.
// It is used to label a commit as a format migration; any real change makes it false.
func SameContent(stored []byte, def map[string]any) bool {
	old, err := DecodeObject(stored)
	if err != nil {
		return false
	}
	a, errA := Canonical(semantic(old))
	b, errB := Canonical(semantic(def))
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// semantic strips representation details from a stored definition.
func semantic(def map[string]any) map[string]any {
	out, _ := deepCopy(def).(map[string]any)
	delete(out, FormatKey)
	if nodes, ok := out["nodes"].([]any); ok {
		for _, n := range nodes {
			if node, ok := n.(map[string]any); ok {
				if params, has := node["parameters"]; has {
					node["parameters"] = joinLines(params)
				}
			}
		}
	}
	if groups, ok := out["nodeGroups"].([]any); ok && len(groups) == 0 {
		delete(out, "nodeGroups")
	}
	if tags, ok := out["tags"].([]any); ok {
		names := make([]string, 0, len(tags))
		for _, t := range tags {
			if s, ok := t.(string); ok {
				names = append(names, s)
			}
		}
		sort.Strings(names)
		out["tags"] = strings.Join(names, ",")
	}
	return out
}
