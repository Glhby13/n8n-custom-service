package workflow

import "strings"

// LinesKey marks a multi-line string stored as a list of lines: {"__lines__": ["a", "b"]}.
// n8n keeps code (Code node jsCode/pythonCode), SQL, HTML and prompts as one string with "\n";
// stored as-is the whole text sits on one JSON line, so a one-character change shows up in Git
// as the entire text changed. One JSON line per text line gives readable, line-level diffs.
// The transform is lossless: strings.Join(lines, "\n") restores the original string exactly
// (trailing newline and "\r" included). Files written before this format keep working, since
// plain strings are restored unchanged.
const LinesKey = "__lines__"

// splitLines converts every string containing "\n" inside v into {LinesKey: [...]}.
func splitLines(v any) any {
	switch t := v.(type) {
	case string:
		if !strings.Contains(t, "\n") {
			return t
		}
		parts := strings.Split(t, "\n")
		lines := make([]any, len(parts))
		for i, p := range parts {
			lines[i] = p
		}
		return map[string]any{LinesKey: lines}
	case map[string]any:
		for k, x := range t {
			t[k] = splitLines(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = splitLines(x)
		}
		return t
	default:
		return v
	}
}

// joinLines reverses splitLines.
func joinLines(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := linesValue(t); ok {
			return s
		}
		for k, x := range t {
			t[k] = joinLines(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = joinLines(x)
		}
		return t
	default:
		return v
	}
}

// linesValue reports whether m is exactly {LinesKey: [string...]} and returns the joined text.
func linesValue(m map[string]any) (string, bool) {
	if len(m) != 1 {
		return "", false
	}
	raw, ok := m[LinesKey].([]any)
	if !ok {
		return "", false
	}
	parts := make([]string, len(raw))
	for i, x := range raw {
		s, ok := x.(string)
		if !ok {
			return "", false
		}
		parts[i] = s
	}
	return strings.Join(parts, "\n"), true
}
