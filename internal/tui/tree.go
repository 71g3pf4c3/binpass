package tui

import "sort"

// treeNode represents a directory or an entry in the password store tree.
// Directories have children; entries are leaves. The tree is built from the
// flat list returned by store.List and is never re-sorted after construction.
type treeNode struct {
	// name is the display label — the last path segment.
	name string
	// path is the full store path (e.g. "github.com/alice"), empty for the root.
	path string
	// entry is true when this node is a password entry rather than a directory.
	entry bool
	// expanded is true when a directory's children are shown.
	expanded bool
	// children holds the sorted child nodes.
	children []*treeNode
}

// buildTree converts a flat list of entry paths into a hierarchical tree.
// Paths are split on "/"; intermediate directories are created as needed.
// The result is a root node whose children are the top-level items.
func buildTree(entries []string) *treeNode {
	root := &treeNode{name: "", path: ""}
	for _, full := range segments(entries) {
		insert(root, full, 0)
	}
	return root
}

// segments splits each entry path on "/" and returns the segments in the
// order the entries were given.
func segments(entries []string) [][]string {
	out := make([][]string, len(entries))
	for i, e := range entries {
		// Skip empty names that could appear from malformed entries.
		if e == "" {
			continue
		}
		parts := splitPath(e)
		out[i] = parts
	}
	return out
}

// splitPath splits s on "/", skipping empty segments so that "a//b" does not
// produce a blank intermediate node.
func splitPath(s string) []string {
	var out []string
	for _, p := range split(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// split is strings.Split on "/". Pulled out so that a future optimiser can
// replace it with a zero-alloc splitter if the store grows large.
func split(s string) []string {
	// Fast path: no slash.
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return append([]string{}, splitSlow(s)...)
		}
	}
	if s == "" {
		return nil
	}
	return []string{s}
}

func splitSlow(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// insert adds a path into the tree, creating intermediate directories.
// depth is the index into segs for the current level.
func insert(parent *treeNode, segs []string, depth int) {
	if depth >= len(segs) {
		return
	}

	name := segs[depth]
	isEntry := depth == len(segs)-1

	// Look for an existing child with this name.
	for _, child := range parent.children {
		if child.name == name {
			// If we are adding an entry and the existing node is a directory,
			// an entry and a directory can share a name in pass (a file
			// "foo.gpg" and a directory "foo/"), but this is rare. Prefer
			// the entry: it wins for display.
			if isEntry && !child.entry {
				child.entry = true
			}
			insert(child, segs, depth+1)
			return
		}
	}

	child := &treeNode{
		name:  name,
		path:  joinSegs(segs[:depth+1]),
		entry: isEntry,
		// Start collapsed so that a store with 2000 entries does not flood
		// the screen on open.
		expanded: false,
	}
	parent.children = append(parent.children, child)
	sort.Slice(parent.children, func(i, j int) bool {
		// Directories first, then entries, both alphabetically.
		if parent.children[i].entry != parent.children[j].entry {
			return !parent.children[i].entry
		}
		return parent.children[i].name < parent.children[j].name
	})
	insert(child, segs, depth+1)
}

// joinSegs joins path segments with "/".
func joinSegs(segs []string) string {
	if len(segs) == 0 {
		return ""
	}
	n := len(segs) - 1
	for _, s := range segs {
		n += len(s)
	}
	buf := make([]byte, 0, n)
	for i, s := range segs {
		if i > 0 {
			buf = append(buf, '/')
		}
		buf = append(buf, s...)
	}
	return string(buf)
}

// flatItem is a visible row in the tree view.
type flatItem struct {
	node  *treeNode
	depth int
}

// flatten returns the visible items of the tree, only descending into
// expanded directories.
func flatten(root *treeNode) []flatItem {
	var items []flatItem
	for _, child := range root.children {
		collectFlat(child, 0, &items)
	}
	return items
}

func collectFlat(n *treeNode, depth int, items *[]flatItem) {
	*items = append(*items, flatItem{node: n, depth: depth})
	if !n.entry && n.expanded {
		for _, child := range n.children {
			collectFlat(child, depth+1, items)
		}
	}
}

// expandAll sets every directory node to expanded.
func expandAll(root *treeNode) {
	walkDirs(root, func(n *treeNode) { n.expanded = true })
}

// collapseAll sets every directory node to collapsed.
func collapseAll(root *treeNode) {
	walkDirs(root, func(n *treeNode) { n.expanded = false })
}

func walkDirs(n *treeNode, fn func(*treeNode)) {
	if !n.entry {
		fn(n)
		for _, child := range n.children {
			walkDirs(child, fn)
		}
	}
}

// countEntries returns the total number of leaf entries under a node.
func countEntries(n *treeNode) int {
	if n.entry {
		return 1
	}
	count := 0
	for _, child := range n.children {
		count += countEntries(child)
	}
	return count
}
