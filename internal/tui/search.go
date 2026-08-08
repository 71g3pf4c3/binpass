package tui

import (
	"strings"
	"unicode"
)

// fuzzyMatch reports whether query fuzzy-matches s, returning a rank (lower
// is better) and true, or (0, false) if there is no match.
//
// The matching is character-by-character, case-insensitive, in order. A
// contiguous match scores better than a scattered one. An exact prefix match
// scores best of all.
func fuzzyMatch(s, query string) (rank int, ok bool) {
	if query == "" {
		return 0, true
	}
	sLower := strings.ToLower(s)
	qLower := strings.ToLower(query)

	// Exact full match — best possible quality.
	if sLower == qLower {
		return -1000, true
	}

	// Exact substring match — next best.
	if idx := strings.Index(sLower, qLower); idx >= 0 {
		// Prefix match is even better.
		if idx == 0 {
			return -500, true
		}
		return idx, true
	}

	// Fuzzy: each query character must appear in order.
	si, qi := 0, 0
	rank = 0
	lastMatchIdx := -1
	for si < len(sLower) && qi < len(qLower) {
		if sLower[si] == qLower[qi] {
			// Contiguous match is better.
			if lastMatchIdx >= 0 && si == lastMatchIdx+1 {
				rank--
			} else {
				rank += si
			}
			lastMatchIdx = si
			qi++
		}
		si++
	}
	if qi == len(qLower) {
		return rank, true
	}
	return 0, false
}

// fuzzyFilter returns the entries matching query, sorted by match quality.
// The sort is stable so that entries at the same rank keep their original
// order (which is already alphabetical from store.List).
func fuzzyFilter(entries []string, query string) []string {
	if query == "" {
		return entries
	}
	type scored struct {
		name string
		rank int
	}
	var matches []scored
	for _, e := range entries {
		if rank, ok := fuzzyMatch(e, query); ok {
			matches = append(matches, scored{name: e, rank: rank})
		}
	}
	// Sort by rank, stable.
	for i := 1; i < len(matches); i++ {
		j := i
		for j > 0 && matches[j].rank < matches[j-1].rank {
			matches[j], matches[j-1] = matches[j-1], matches[j]
			j--
		}
	}
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.name
	}
	return out
}

// isPrintable reports whether r is a printable rune suitable for search input.
func isPrintable(r rune) bool {
	return unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t'
}
