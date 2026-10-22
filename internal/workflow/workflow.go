// Package workflow turns an n8n workflow into the canonical JSON stored in Git, and a stored
// definition back into the body accepted by the n8n public API.
//
// Persisted (whitelist): id, name, nodes, connections, settings, meta, tags (names).
// Omitted on purpose: pinData, staticData, createdAt, updatedAt, versionId, activeVersion,
// shared, active, isArchived, triggerCount, authors.
// Node credentials are reduced to references {id, name}. Parameters whose key is listed in
// REDACT_PARAMETER_KEYS are replaced by RedactedMarker (best effort, see README).
package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// RedactedMarker replaces redacted node parameter values in Git.
const RedactedMarker = "__REDACTED__"

var (
	idPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	shaPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// ValidID reports whether id is a safe workflow ID (it is also the file name).
func ValidID(id string) bool { return idPattern.MatchString(id) }

// ValidSHA reports whether s is a full 40-hex commit SHA.
func ValidSHA(s string) bool { return shaPattern.MatchString(s) }

// FileName is the only Git path the service uses for a workflow.
func FileName(id string) string { return id + ".json" }

// Source is the published snapshot of a workflow as read from the n8n API.
type Source struct {
	ID          string
	Name        string
	Nodes       any
	Connections any
	NodeGroups  any // canvas frames; kept only when non-empty so old files do not churn
	Settings    any
	Meta        any
	Tags        []string
}

// DecodeObject parses one JSON object, keeping number text and rejecting trailing data.
func DecodeObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid JSON: unexpected trailing data")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("invalid JSON: top level must be an object")
	}
	return obj, nil
}

// Canonical serialises v deterministically: sorted keys, 2-space indent, no HTML escaping,
// newline at EOF.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeBytes re-serialises a JSON document canonically.
func CanonicalizeBytes(raw []byte) ([]byte, error) {
	obj, err := DecodeObject(raw)
	if err != nil {
		return nil, err
	}
	return Canonical(obj)
}

// Equal reports whether two JSON documents are identical after canonicalisation.
func Equal(a, b []byte) bool {
	ca, errA := CanonicalizeBytes(a)
	cb, errB := CanonicalizeBytes(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}

// BuildDefinition produces the whitelisted, sanitised definition stored in Git.
func BuildDefinition(src Source, redactKeys []string) (map[string]any, error) {
	if !ValidID(src.ID) {
		return nil, errors.New("invalid workflow id")
	}
	nodes, err := sanitizeNodes(src.Nodes, normalizeSet(redactKeys))
	if err != nil {
		return nil, err
	}
	conns, ok := deepCopy(src.Connections).(map[string]any)
	if !ok {
		conns = map[string]any{}
	}
	settings, ok := deepCopy(src.Settings).(map[string]any)
	if !ok {
		settings = map[string]any{}
	}
	def := map[string]any{
		"id":          src.ID,
		"name":        src.Name,
		"nodes":       nodes,
		"connections": conns,
		"settings":    settings,
		FormatKey:     FormatVersion,
	}
	if groups, ok := deepCopy(src.NodeGroups).([]any); ok && len(groups) > 0 {
		def["nodeGroups"] = groups
	}
	if meta, ok := deepCopy(src.Meta).(map[string]any); ok && len(meta) > 0 {
		def["meta"] = meta
	}
	if len(src.Tags) > 0 {
		tags := append([]string(nil), src.Tags...)
		sort.Strings(tags)
		out := make([]any, len(tags))
		for i, t := range tags {
			out[i] = t
		}
		def["tags"] = out
	}
	return def, nil
}

// Validate checks a definition read back from Git before anything is sent to n8n.
func Validate(def map[string]any, wantID string) error {
	id, _ := def["id"].(string)
	if id == "" {
		return errors.New("workflow JSON has no id")
	}
	if id != wantID {
		return fmt.Errorf("workflow id mismatch: file contains %q, requested %q", id, wantID)
	}
	if name, _ := def["name"].(string); strings.TrimSpace(name) == "" {
		return errors.New("workflow JSON has no name")
	}
	if _, ok := def["nodes"].([]any); !ok {
		return errors.New("workflow JSON: nodes must be an array")
	}
	if _, ok := def["connections"].(map[string]any); !ok {
		return errors.New("workflow JSON: connections must be an object")
	}
	if s, present := def["settings"]; present {
		if _, ok := s.(map[string]any); !ok {
			return errors.New("workflow JSON: settings must be an object")
		}
	}
	return nil
}

// deepCopy clones JSON-like values.
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}
		return out
	default:
		return v
	}
}
