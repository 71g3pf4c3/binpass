package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// treeNode is a node in the rendered password-store tree.
type treeNode struct {
	// name is the path segment.
	name string
	// children maps child segment to node.
	children map[string]*treeNode
}

// newTreeNode returns an empty tree node.
func newTreeNode(name string) *treeNode {
	return &treeNode{name: name, children: map[string]*treeNode{}}
}

// insert adds a slash-separated logical path into the tree.
func (n *treeNode) insert(path string) {
	cur := n
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		child, ok := cur.children[seg]
		if !ok {
			child = newTreeNode(seg)
			cur.children[seg] = child
		}
		cur = child
	}
}

// sortedChildren returns child nodes in name order, directories are those
// with their own children.
func (n *treeNode) sortedChildren() []*treeNode {
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*treeNode, 0, len(names))
	for _, name := range names {
		out = append(out, n.children[name])
	}
	return out
}

// renderTree writes a pass-style tree of names to w, rooted at heading.
func renderTree(w io.Writer, heading string, names []string) {
	root := newTreeNode("")
	for _, name := range names {
		root.insert(name)
	}
	if heading != "" {
		fmt.Fprintln(w, heading)
	}
	renderChildren(w, root, "")
}

// renderChildren writes the children of node with the given indent prefix,
// using the box-drawing style of the tree(1) utility as pass does.
func renderChildren(w io.Writer, node *treeNode, prefix string) {
	children := node.sortedChildren()
	for i, child := range children {
		last := i == len(children)-1
		branch := "├── "
		nextPrefix := prefix + "│   "
		if last {
			branch = "└── "
			nextPrefix = prefix + "    "
		}
		fmt.Fprintf(w, "%s%s%s\n", prefix, branch, child.name)
		renderChildren(w, child, nextPrefix)
	}
}

// filterByPrefix returns names under the given subfolder (inclusive) and
// whether the subfolder itself is an exact secret name.
func filterByPrefix(names []string, sub string) (matched []string, exact bool) {
	sub = strings.Trim(sub, "/")
	if sub == "" {
		return names, false
	}
	for _, n := range names {
		if n == sub {
			exact = true
			matched = append(matched, n)
			continue
		}
		if strings.HasPrefix(n, sub+"/") {
			matched = append(matched, n)
		}
	}
	return matched, exact
}
