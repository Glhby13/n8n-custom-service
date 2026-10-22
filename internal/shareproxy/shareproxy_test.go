package shareproxy

import (
	"encoding/json"
	"testing"
)

func TestSharePayload(t *testing.T) {
	raw := `{"shareWithIds":["proj-1","proj-2"]}`
	var p sharePayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(p.ShareWithIds) != 2 || p.ShareWithIds[0] != "proj-1" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}
