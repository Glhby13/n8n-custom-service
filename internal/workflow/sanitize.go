package workflow

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Settings accepted by the n8n public API (workflowSettings schema, additionalProperties: false).
var allowedSettings = map[string]bool{
	"saveExecutionProgress": true, "saveManualExecutions": true, "saveDataErrorExecution": true,
	"saveDataSuccessExecution": true, "executionTimeout": true, "errorWorkflow": true, "timezone": true,
	"executionOrder": true, "callerPolicy": true, "callerIds": true, "timeSavedPerExecution": true,
	"redactionPolicy": true,
}

// Node keys accepted by the n8n public API (node schema, additionalProperties: false).
var allowedNodeKeys = map[string]bool{
	"id": true, "name": true, "webhookId": true, "disabled": true, "notesInFlow": true, "notes": true,
	"type": true, "typeVersion": true, "executeOnce": true, "alwaysOutputData": true, "retryOnFail": true,
	"maxTries": true, "waitBetweenTries": true, "continueOnFail": true, "onError": true, "position": true,
	"parameters": true, "credentials": true, "customTelemetryTags": true,
}

// ErrUnrecoverableRedaction means a historical version holds redacted values that cannot be refilled
// from the workflow currently in n8n, so restoring it would break the workflow.
var ErrUnrecoverableRedaction = errors.New("historical version contains redacted parameter values that cannot be restored")

// RestoreBody builds the PUT /workflows/{id} body (name, nodes, connections, settings) from a
// stored definition. current is the workflow as it is in n8n now; it refills redacted parameter
// values of nodes with the same id (or name). Keys n8n would reject are dropped.
func RestoreBody(def map[string]any, current map[string]any) (map[string]any, error) {
	nodes, _ := deepCopy(def["nodes"]).([]any)
	curNodes, _ := current["nodes"].([]any)
	var missing []string
	for _, n := range nodes {
		node, ok := n.(map[string]any)
		if !ok {
			return nil, errors.New("workflow JSON: node is not an object")
		}
		if params, has := node["parameters"]; has {
			node["parameters"] = joinLines(params)
		}
		if cur := findNode(curNodes, node); cur != nil {
			mergeRedacted(node, cur)
		}
		if containsMarker(node) {
			name, _ := node["name"].(string)
			missing = append(missing, name)
		}
		for k := range node {
			if !allowedNodeKeys[k] {
				delete(node, k)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%w (nodes: %s)", ErrUnrecoverableRedaction, strings.Join(missing, ", "))
	}
	settings := map[string]any{}
	if s, ok := def["settings"].(map[string]any); ok {
		for k, v := range s {
			if allowedSettings[k] {
				settings[k] = deepCopy(v)
			}
		}
	}
	body := map[string]any{
		"name":        def["name"],
		"nodes":       nodes,
		"connections": deepCopy(def["connections"]),
		"settings":    settings,
	}
	if groups, ok := def["nodeGroups"].([]any); ok {
		body["nodeGroups"] = deepCopy(groups)
	}
	return body, nil
}

// VersionPayload converts a stored definition into the node graph n8n's own editor expects
// from GET /rest/workflow-history/.../version/{id}: multi-line strings joined back and redacted
// values refilled from current (the workflow as it is in n8n now). Node keys are not filtered:
// the editor saves them through n8n's internal API, which accepts everything n8n produced.
func VersionPayload(def map[string]any, current map[string]any) (nodes []any, connections any, nodeGroups []any, err error) {
	nodes, _ = deepCopy(def["nodes"]).([]any)
	curNodes, _ := current["nodes"].([]any)
	var missing []string
	for _, n := range nodes {
		node, ok := n.(map[string]any)
		if !ok {
			return nil, nil, nil, errors.New("workflow JSON: node is not an object")
		}
		if params, has := node["parameters"]; has {
			node["parameters"] = joinLines(params)
		}
		if cur := findNode(curNodes, node); cur != nil {
			mergeRedacted(node, cur)
		}
		if containsMarker(node) {
			name, _ := node["name"].(string)
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, nil, nil, fmt.Errorf("%w (nodes: %s)", ErrUnrecoverableRedaction, strings.Join(missing, ", "))
	}
	nodeGroups, _ = deepCopy(def["nodeGroups"]).([]any)
	if nodeGroups == nil {
		nodeGroups = []any{}
	}
	conns := deepCopy(def["connections"])
	if conns == nil {
		conns = map[string]any{}
	}
	return nodes, conns, nodeGroups, nil
}

func findNode(nodes []any, want map[string]any) map[string]any {
	id, _ := want["id"].(string)
	name, _ := want["name"].(string)
	var byName map[string]any
	for _, n := range nodes {
		node, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if cid, _ := node["id"].(string); id != "" && cid == id {
			return node
		}
		if cname, _ := node["name"].(string); name != "" && cname == name {
			byName = node
		}
	}
	return byName
}

func isMarker(v any) bool {
	s, ok := v.(string)
	return ok && s == RedactedMarker
}

func mergeRedacted(dst, src any) {
	switch d := dst.(type) {
	case map[string]any:
		s, ok := src.(map[string]any)
		if !ok {
			return
		}
		for k, v := range d {
			if isMarker(v) {
				if sv, has := s[k]; has && !isMarker(sv) {
					d[k] = deepCopy(sv)
				}
				continue
			}
			mergeRedacted(v, s[k])
		}
	case []any:
		s, ok := src.([]any)
		if !ok {
			return
		}
		for i := range d {
			if i >= len(s) {
				break
			}
			if isMarker(d[i]) {
				if !isMarker(s[i]) {
					d[i] = deepCopy(s[i])
				}
				continue
			}
			mergeRedacted(d[i], s[i])
		}
	}
}

func containsMarker(v any) bool {
	switch t := v.(type) {
	case string:
		return t == RedactedMarker
	case map[string]any:
		for _, x := range t {
			if containsMarker(x) {
				return true
			}
		}
	case []any:
		for _, x := range t {
			if containsMarker(x) {
				return true
			}
		}
	}
	return false
}

func sanitizeNodes(raw any, redact map[string]bool) ([]any, error) {
	list, ok := deepCopy(raw).([]any)
	if !ok {
		return nil, errors.New("workflow has no nodes array")
	}
	for _, n := range list {
		node, ok := n.(map[string]any)
		if !ok {
			return nil, errors.New("workflow node is not an object")
		}
		if creds, ok := node["credentials"].(map[string]any); ok {
			clean := map[string]any{}
			for typ, c := range creds {
				ref := map[string]any{}
				if cm, ok := c.(map[string]any); ok {
					for _, k := range []string{"id", "name"} {
						if v, has := cm[k]; has {
							ref[k] = v
						}
					}
				}
				clean[typ] = ref
			}
			node["credentials"] = clean
		}
		if params, ok := node["parameters"]; ok {
			if len(redact) > 0 {
				params = redactValue(params, redact)
			}
			node["parameters"] = splitLines(params)
		}
	}
	return list, nil
}

func redactValue(v any, keys map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if keys[normalizeKey(k)] && !isEmpty(x) {
				t[k] = RedactedMarker
				continue
			}
			t[k] = redactValue(x, keys)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = redactValue(x, keys)
		}
		return t
	default:
		return v
	}
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}

func normalizeKey(k string) string {
	k = strings.ToLower(k)
	k = strings.ReplaceAll(k, "_", "")
	return strings.ReplaceAll(k, "-", "")
}

func normalizeSet(keys []string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		if k = normalizeKey(strings.TrimSpace(k)); k != "" {
			m[k] = true
		}
	}
	return m
}
