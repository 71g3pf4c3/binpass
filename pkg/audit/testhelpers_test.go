package audit

import "strings"

// hasFinding reports whether the report contains a finding of the given kind
// for the named entry.
func hasFinding(r *Report, name string, kind Kind) bool {
	for _, e := range r.Entries {
		if e.Name != name {
			continue
		}
		for _, f := range e.Findings {
			if f.Kind == kind {
				return true
			}
		}
	}
	return false
}

// hasAnyFinding reports whether the named entry has any findings.
func hasAnyFinding(r *Report, name string) bool {
	for _, e := range r.Entries {
		if e.Name == name {
			return len(e.Findings) > 0
		}
	}
	return false
}

// containsSubstring reports whether s contains substr.
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
