package tui

import (
	"testing"
)

func TestBuildTree(t *testing.T) {
	entries := []string{
		"github.com/alice",
		"github.com/bob",
		"bank/tinkoff",
		"email/gmail",
		"root-entry",
	}

	tree := buildTree(entries)
	root := tree

	// Root should have 3 top-level children: github.com/, bank/, email/, root-entry
	wantDirs := map[string]bool{"github.com": false, "bank": false, "email": false, "root-entry": false}
	for _, child := range root.children {
		if _, ok := wantDirs[child.name]; !ok {
			t.Errorf("unexpected top-level node %q", child.name)
			continue
		}
		wantDirs[child.name] = true
	}
	for name, found := range wantDirs {
		if !found {
			t.Errorf("missing top-level node %q", name)
		}
	}

	// github.com should have alice and bob.
	var gh *treeNode
	for _, child := range root.children {
		if child.name == "github.com" {
			gh = child
			break
		}
	}
	if gh == nil {
		t.Fatal("github.com node not found")
	}
	if len(gh.children) != 2 {
		t.Fatalf("github.com has %d children, want 2", len(gh.children))
	}
	if gh.children[0].name != "alice" || gh.children[1].name != "bob" {
		t.Errorf("github.com children = %v, want [alice bob]", nodeNames(gh.children))
	}

	// alice should be an entry.
	if !gh.children[0].entry {
		t.Error("alice should be an entry")
	}
	// github.com should be a directory.
	if gh.entry {
		t.Error("github.com should not be an entry")
	}
}

func TestBuildTreeEmpty(t *testing.T) {
	tree := buildTree(nil)
	if len(tree.children) != 0 {
		t.Errorf("empty store should have no children, got %d", len(tree.children))
	}
}

func TestFlattenCollapsed(t *testing.T) {
	entries := []string{
		"github.com/alice",
		"github.com/bob",
		"root-entry",
	}
	tree := buildTree(entries)
	// Nothing is expanded by default.
	flat := flatten(tree)

	// Should show: github.com/, root-entry (not alice, bob)
	names := flatNames(flat)
	want := []string{"github.com", "root-entry"}
	if len(names) != len(want) {
		t.Fatalf("flat = %v, want %v", names, want)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("flat[%d] = %q, want %q", i, names[i], n)
		}
	}
}

func TestFlattenExpanded(t *testing.T) {
	entries := []string{
		"github.com/alice",
		"github.com/bob",
		"root-entry",
	}
	tree := buildTree(entries)
	// Expand github.com.
	for _, child := range tree.children {
		if child.name == "github.com" {
			child.expanded = true
		}
	}
	flat := flatten(tree)

	names := flatNames(flat)
	want := []string{"github.com", "alice", "bob", "root-entry"}
	if len(names) != len(want) {
		t.Fatalf("flat = %v, want %v", names, want)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("flat[%d] = %q, want %q", i, names[i], n)
		}
	}
}

func TestCountEntries(t *testing.T) {
	entries := []string{
		"github.com/alice",
		"github.com/bob",
		"bank/tinkoff",
		"root",
	}
	tree := buildTree(entries)
	if got := countEntries(tree); got != 4 {
		t.Errorf("countEntries = %d, want 4", got)
	}
}

func TestDirectoriesFirstInSort(t *testing.T) {
	// Entries with both a file and a directory at the same level.
	entries := []string{
		"alpha",
		"bravo/sub",
		"charlie",
	}
	tree := buildTree(entries)
	// Directories should come before entries.
	if len(tree.children) < 3 {
		t.Fatalf("expected at least 3 children, got %d", len(tree.children))
	}
	// bravo/ (dir) should come before alpha, charlie (entries).
	first := tree.children[0]
	if first.entry {
		t.Errorf("first child %q should be a directory, not an entry", first.name)
	}
}

// flatNames extracts the names from a flat list.
func flatNames(items []flatItem) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.node.name
	}
	return out
}

// nodeNames extracts the names from a child list.
func nodeNames(children []*treeNode) []string {
	out := make([]string, len(children))
	for i, c := range children {
		out[i] = c.name
	}
	return out
}
