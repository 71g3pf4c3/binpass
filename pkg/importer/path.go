package importer

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// pathInvalidRe matches characters that are not allowed in store paths.
// Store paths use '/' as a separator and must not contain characters that
// are illegal in filenames on Linux, macOS, or Windows.
var pathInvalidRe = regexp.MustCompile(`[<>:"|?*\\]`)

// dotRunRe matches two or more consecutive dots, which no store path may
// contain: "a..b" is not traversal but is still refused by ValidatePath.
var dotRunRe = regexp.MustCompile(`\.{2,}`)

// NormalizePath converts a title and optional group from a foreign format into a
// valid store path.
//
// Rules:
//   - Group and title are joined with '/'.
//   - Whitespace is collapsed and trimmed.
//   - Characters invalid in filenames are replaced with '_'.
//   - The result is lowercased for consistency (matching pass conventions).
//   - Empty segments are dropped.
//   - The path is cleaned to prevent directory traversal.
func NormalizePath(group, title string) string {
	segments := splitPath(group, title)
	var parts []string
	for _, s := range segments {
		s = strings.Map(sanitizeRune, s)
		s = collapseWhitespace(s)
		// Any run of dots is collapsed to one, not just a segment that is
		// exactly "..". A title like "..00" is neither traversal nor a name
		// ValidatePath accepts, so leaving it alone produced a path this
		// function's own caller then rejected.
		s = dotRunRe.ReplaceAllString(s, ".")
		if s == "" || s == "." {
			continue
		}
		parts = append(parts, s)
	}
	result := path.Join(parts...)
	// path.Join cleans "../" but a single ".." that escapes the root is
	// still possible; strip it.
	result = strings.TrimPrefix(result, "../")
	result = strings.TrimPrefix(result, "..")
	return result
}

// ValidatePath reports whether p is a safe store path: non-empty, no traversal,
// no leading slash, and every segment is a valid filename.
func ValidatePath(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/") {
		return false
	}
	if strings.Contains(p, "..") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			return false
		}
	}
	return true
}

// DeduplicatePaths resolves duplicate paths by appending a numeric suffix.
// Returns a slice of deduplicated paths in the same order as input. The first
// occurrence keeps its original name; subsequent ones get "-2", "-3", etc.
func DeduplicatePaths(paths []string) []string {
	seen := make(map[string]int, len(paths))
	out := make([]string, len(paths))
	for i, p := range paths {
		n := seen[p]
		seen[p] = n + 1
		if n == 0 {
			out[i] = p
		} else {
			out[i] = fmt.Sprintf("%s-%d", p, n+1)
		}
	}
	return out
}

// splitPath splits a group and title into path segments.
func splitPath(group, title string) []string {
	group = strings.TrimSpace(group)
	title = strings.TrimSpace(title)
	var segments []string
	if group != "" {
		segments = append(segments, strings.Split(group, "/")...)
	}
	if title != "" {
		segments = append(segments, strings.Split(title, "/")...)
	}
	return segments
}

// sanitizeRune replaces characters that are not valid in store path segments.
func sanitizeRune(r rune) rune {
	if pathInvalidRe.MatchString(string(r)) {
		return '_'
	}
	return r
}

// collapseWhitespace trims and collapses internal whitespace in s.
func collapseWhitespace(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}
