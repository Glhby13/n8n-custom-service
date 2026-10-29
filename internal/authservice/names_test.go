package authservice

import (
	"strings"
	"testing"
)

func TestIsPlaceholderName(t *testing.T) {
	const email = "agi.iskandar@btn.co.id"
	for _, tc := range []struct {
		name        string
		first, last string
		want        bool
	}{
		{"current placeholder", "agi.iskandar", "(AD)", true},
		{"legacy placeholder", "User", "Lab", true},
		{"empty", "", "", true},
		{"filled from the identity provider", "Agi 18146. Fazrillah", "FAZRILAH ISKANDAR", false},
		{"chosen by the user", "Agi", "I.", false},
		{"only the first half of the legacy placeholder", "User", "Smith", false},
		{"someone else's placeholder", "budi", "(AD)", false},
	} {
		if got := isPlaceholderName(email, tc.first, tc.last); got != tc.want {
			t.Errorf("%s: isPlaceholderName(%q, %q) = %v, want %v", tc.name, tc.first, tc.last, got, tc.want)
		}
	}
}

func TestInitialNames(t *testing.T) {
	if f, l := initialNames("agi.iskandar@btn.co.id", "", ""); f != "agi.iskandar" || l != "(AD)" {
		t.Errorf("transfer target without names: got %q %q", f, l)
	}
	if f, l := initialNames("a@x", "Agi 18146. Fazrillah", "FAZRILAH ISKANDAR"); f != "Agi 18146. Fazrillah" || l != "FAZRILAH ISKANDAR" {
		t.Errorf("sign-in with names: got %q %q", f, l)
	}
	if f, l := initialNames("a@x", "Only Given", ""); f != "Only Given" || l != "" {
		t.Errorf("only one name: got %q %q", f, l)
	}
	long := strings.Repeat("x", 40)
	if f, _ := initialNames("a@x", long, "y"); len([]rune(f)) != maxNameLen {
		t.Errorf("name not clipped to %d: %d", maxNameLen, len([]rune(f)))
	}
	if f, _ := initialNames(long+"@btn.co.id", "", ""); len([]rune(f)) != maxNameLen {
		t.Errorf("placeholder not clipped to %d: %d", maxNameLen, len([]rune(f)))
	}
}

func TestNamesToFill(t *testing.T) {
	const email = "agi.iskandar@btn.co.id"
	const idpFirst, idpLast = "Agi 18146. Fazrillah", "FAZRILAH ISKANDAR"
	for _, tc := range []struct {
		name                string
		curFirst, curLast   string
		idpFirst, idpLast   string
		wantFirst, wantLast string
		wantOK              bool
	}{
		{"legacy placeholder is filled", "User", "Lab", idpFirst, idpLast, idpFirst, idpLast, true},
		{"current placeholder is filled", "agi.iskandar", "(AD)", idpFirst, idpLast, idpFirst, idpLast, true},
		{"name changed by the user is kept", "Agi", "I.", idpFirst, idpLast, "", "", false},
		{"already filled is kept", idpFirst, idpLast, "Other", "Name", "", "", false},
		{"identity provider sent nothing: placeholder stays", "User", "Lab", "", "", "", "", false},
		{"identity provider sent only a first name", "User", "Lab", "Agi", "", "Agi", "", true},
		{"placeholder equal to what the provider sent: nothing to do", "User", "Lab", "User", "Lab", "", "", false},
	} {
		f, l, ok := namesToFill(email, tc.curFirst, tc.curLast, tc.idpFirst, tc.idpLast)
		if ok != tc.wantOK || f != tc.wantFirst || l != tc.wantLast {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, %v)", tc.name, f, l, ok, tc.wantFirst, tc.wantLast, tc.wantOK)
		}
	}
}
