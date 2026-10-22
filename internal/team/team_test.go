package team

import (
	"testing"
)

func TestParseTeams(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		count   int
	}{
		{
			name:    "empty string",
			input:   "",
			wantErr: false,
			count:   0,
		},
		{
			name:    "empty array",
			input:   "[]",
			wantErr: false,
			count:   0,
		},
		{
			name:    "valid team",
			input:   `[{"id":"team-dev","name":"Team Dev","members":["user@lab.local","user2@lab.local"]}]`,
			wantErr: false,
			count:   1,
		},
		{
			name:    "invalid json",
			input:   `invalid`,
			wantErr: true,
		},
		{
			name:    "missing id",
			input:   `[{"name":"Team Dev","members":["user@lab.local"]}]`,
			wantErr: true,
		},
		{
			name:    "no members",
			input:   `[{"id":"team-dev","name":"Team Dev","members":[]}]`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTeams(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTeams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != tt.count {
				t.Fatalf("ParseTeams() got %d teams, want %d", len(got), tt.count)
			}
			if tt.count > 0 {
				if got[0].ID != "team-dev" {
					t.Errorf("expected team id team-dev, got %s", got[0].ID)
				}
				if len(got[0].Members) != 2 {
					t.Errorf("expected 2 members, got %d", len(got[0].Members))
				}
			}
		})
	}
}

func TestFindTeamForUser(t *testing.T) {
	teams := []Team{
		{
			ID:      "team-alpha",
			Name:    "Alpha",
			Members: []string{"alice@lab.local", "bob@lab.local"},
		},
	}

	if tm := FindTeamForUser(teams, "Alice@lab.local"); tm == nil || tm.ID != "team-alpha" {
		t.Errorf("expected to find team-alpha for alice, got %v", tm)
	}
	if tm := FindTeamForUser(teams, "charlie@lab.local"); tm != nil {
		t.Errorf("expected nil for charlie, got %v", tm)
	}
}
