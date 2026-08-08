package tui

import (
	"testing"
)

func TestFuzzyMatchExact(t *testing.T) {
	rank, ok := fuzzyMatch("github.com/alice", "alice")
	if !ok {
		t.Fatal("expected match")
	}
	// Substring match (not prefix), so rank should be > -500.
	if rank < -500 {
		t.Errorf("rank = %d, want > -500 for non-prefix substring match", rank)
	}
}

func TestFuzzyMatchPrefix(t *testing.T) {
	rank, ok := fuzzyMatch("alice", "alice")
	if !ok {
		t.Fatal("expected match")
	}
	// Exact full match has rank -1000.
	if rank != -1000 {
		t.Errorf("rank = %d, want -1000 for exact match", rank)
	}
}

func TestFuzzyMatchSubstringPrefix(t *testing.T) {
	rank, ok := fuzzyMatch("alice/extra", "alice")
	if !ok {
		t.Fatal("expected match")
	}
	// Substring at index 0 (prefix) has rank -500.
	if rank != -500 {
		t.Errorf("rank = %d, want -500 for substring-prefix match", rank)
	}
}

func TestFuzzyMatchNoMatch(t *testing.T) {
	_, ok := fuzzyMatch("alice", "xyz")
	if ok {
		t.Error("expected no match")
	}
}

func TestFuzzyMatchFuzzy(t *testing.T) {
	_, ok := fuzzyMatch("github.com/alice", "gca")
	if !ok {
		t.Fatal("expected fuzzy match for 'gca' in 'github.com/alice'")
	}
}

func TestFuzzyFilter(t *testing.T) {
	entries := []string{
		"github.com/alice",
		"github.com/bob",
		"bank/tinkoff",
		"email/gmail",
	}

	tests := []struct {
		query string
		want  int
	}{
		{"", 4},
		{"alice", 1},
		{"github", 2},
		{"xyz", 0},
		{"g", 3}, // github.com/alice, github.com/bob, email/gmail
	}

	for _, tt := range tests {
		got := fuzzyFilter(entries, tt.query)
		if len(got) != tt.want {
			t.Errorf("fuzzyFilter(%q) = %d results, want %d", tt.query, len(got), tt.want)
		}
	}
}

func TestFuzzyFilterRanking(t *testing.T) {
	entries := []string{
		"alpha/bravo",
		"alpha/charlie",
		"alpha",
	}

	// "alpha" should match all three; "alpha" itself (prefix) should rank first.
	results := fuzzyFilter(entries, "alpha")
	if len(results) != 3 {
		t.Fatalf("fuzzyFilter('alpha') = %d results, want 3", len(results))
	}
	// The exact match "alpha" should come first (prefix rank 0).
	if results[0] != "alpha" {
		t.Errorf("first result = %q, want %q", results[0], "alpha")
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		r    rune
		want bool
	}{
		{'a', true},
		{'A', true},
		{'0', true},
		{'/', true},
		{'\n', false},
		{'\t', false},
		{0, false}, // null
	}
	for _, tt := range tests {
		if got := isPrintable(tt.r); got != tt.want {
			t.Errorf("isPrintable(%q) = %v, want %v", tt.r, got, tt.want)
		}
	}
}
