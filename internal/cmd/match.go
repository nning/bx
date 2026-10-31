package cmd

import "strings"

// matchByName checks if the pattern (case-insensitive) matches the name as
// an exact or substring match. Returns (matched, isExact).
func matchByName(name, pattern string) (bool, bool) {
	nameLower := strings.ToLower(name)
	patternLower := strings.ToLower(pattern)
	if nameLower == patternLower {
		return true, true
	}
	return strings.Contains(nameLower, patternLower), false
}

// matchByURL checks if the pattern (case-insensitive) is a substring of any
// of the given decrypted URIs.
func matchByURL(uris []string, pattern string) bool {
	patternLower := strings.ToLower(pattern)
	for _, uri := range uris {
		if strings.Contains(strings.ToLower(uri), patternLower) {
			return true
		}
	}
	return false
}
