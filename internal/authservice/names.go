package authservice

import (
	"fmt"
	"strings"
)

const (
	// n8n stores first and last name in varchar(32) columns.
	maxNameLen = 32
	// placeholderLast is the last name of an account created before its owner has ever signed in. The first name is the
	// local part of the e-mail address, so the account is still recognisable in n8n's user list.
	placeholderLast = "(AD)"
	// legacyPlaceholderFirst/Last are the names earlier versions gave such accounts ("User Lab"). They are still
	// recognised as a placeholder so those accounts are corrected at their next sign-in.
	legacyPlaceholderFirst = "User"
	legacyPlaceholderLast  = "Lab"
)

func clipName(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxNameLen {
		return strings.TrimSpace(string(r[:maxNameLen]))
	}
	return s
}

func placeholderFirst(email string) string {
	local, _, _ := strings.Cut(email, "@")
	return clipName(local)
}

// isPlaceholderName reports whether the stored names are one of the placeholders (current, legacy or empty).
func isPlaceholderName(email, first, last string) bool {
	first, last = strings.TrimSpace(first), strings.TrimSpace(last)
	switch {
	case first == "" && last == "":
		return true
	case first == legacyPlaceholderFirst && last == legacyPlaceholderLast:
		return true
	}
	return first == placeholderFirst(email) && last == placeholderLast
}

// initialNames returns the names for a new account: the identity provider's when it sent any, else the placeholder.
func initialNames(email, idpFirst, idpLast string) (string, string) {
	first, last := clipName(idpFirst), clipName(idpLast)
	if first == "" && last == "" {
		return placeholderFirst(email), placeholderLast
	}
	return first, last
}

// namesToFill decides whether an existing account's names should be replaced with the identity provider's. It does so
// only when the stored names are a placeholder and the provider sent at least one name; anything else (a name the user
// chose, or one filled in before) is left as is.
func namesToFill(email, curFirst, curLast, idpFirst, idpLast string) (first, last string, ok bool) {
	first, last = clipName(idpFirst), clipName(idpLast)
	if first == "" && last == "" {
		return "", "", false
	}
	if !isPlaceholderName(email, curFirst, curLast) {
		return "", "", false
	}
	if first == strings.TrimSpace(curFirst) && last == strings.TrimSpace(curLast) {
		return "", "", false
	}
	return first, last, true
}

// projectName is how n8n names a user's personal project.
func projectName(first, last, email string) string {
	return fmt.Sprintf("%s %s <%s>", first, last, email)
}
