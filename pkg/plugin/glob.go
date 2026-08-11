package plugin

import "strings"

// MatchPath reports whether an entry path is covered by a capability pattern.
//
// Patterns are matched segment by segment against the slash-separated entry
// path, which is how store entries are named:
//
//	**        every entry in the store
//	a/**      the entry "a" and everything beneath it
//	a/*       the direct children of "a", but not their children
//	a/b       exactly that entry
//	*.token   entries whose final segment ends in ".token"
//
// A single * never crosses a slash, so "a/*" cannot be talked into granting
// "a/b/c". This matters because capability patterns are a security boundary:
// a pattern that silently matches more than it appears to would hand out
// access its author never intended.
func MatchPath(pattern, name string) bool {
	if pattern == "" {
		return false
	}
	return matchSegments(splitPath(pattern), splitPath(name))
}

// MatchAny reports whether any pattern covers name.
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if MatchPath(p, name) {
			return true
		}
	}
	return false
}

// splitPath breaks a path into segments, discarding the empty segments that
// leading, trailing and doubled slashes produce.
func splitPath(p string) []string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// matchSegments matches pattern segments against name segments, with **
// consuming zero or more whole segments.
func matchSegments(pattern, name []string) bool {
	// An exhausted pattern matches only an exhausted name, except for a
	// trailing ** which has already been handled below.
	if len(pattern) == 0 {
		return len(name) == 0
	}

	if pattern[0] == "**" {
		rest := pattern[1:]
		// A trailing ** matches whatever is left, including nothing, so
		// "a/**" covers the entry "a" as well as the subtree under it.
		if len(rest) == 0 {
			return true
		}
		// Otherwise try every split point: ** may swallow any number of
		// leading segments before the rest of the pattern has to line up.
		for i := 0; i <= len(name); i++ {
			if matchSegments(rest, name[i:]) {
				return true
			}
		}
		return false
	}

	if len(name) == 0 {
		return false
	}
	if !matchSegment(pattern[0], name[0]) {
		return false
	}
	return matchSegments(pattern[1:], name[1:])
}

// matchSegment matches one path segment against one pattern segment, where *
// stands for any run of characters within that segment.
func matchSegment(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")
	// The leading and trailing literals are anchored; the ones between may
	// float, and are consumed left to right.
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	last := parts[len(parts)-1]
	middle := parts[1 : len(parts)-1]

	for _, lit := range middle {
		i := strings.Index(s, lit)
		if i < 0 {
			return false
		}
		s = s[i+len(lit):]
	}
	return strings.HasSuffix(s, last)
}
