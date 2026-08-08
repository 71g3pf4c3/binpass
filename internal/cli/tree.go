package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// pass renders listings by piping the store through tree(1) with -C. Two of
// tree's decisions have to be reproduced exactly, because passmenu, rofi-pass
// and QtPass all read this output:
//
//   - the glyphs depend on the locale codeset: UTF-8 gives box drawing
//     characters, anything else falls back to ASCII;
//   - the colours depend on TERM: without one, tree emits no escapes at all.
//
// Hardcoding either produces output that matches on the developer's machine
// and differs in a container, so both are detected at runtime.
const (
	// treeBranchUTF precedes every entry except the last of its level.
	treeBranchUTF = "├── "
	// treeLastUTF precedes the last entry of its level.
	treeLastUTF = "└── "
	// treeVerticalUTF continues a parent's line through deeper levels. The
	// two spaces are non-breaking, exactly as tree(1) emits them.
	treeVerticalUTF = "│\u00a0\u00a0 "
	// treeBranchASCII is the non-UTF-8 form of treeBranchUTF.
	treeBranchASCII = "|-- "
	// treeLastASCII is the non-UTF-8 form of treeLastUTF.
	treeLastASCII = "`-- "
	// treeVerticalASCII is the non-UTF-8 form of treeVerticalUTF.
	treeVerticalASCII = "|   "
	// treeIndent is the blank continuation under a finished branch.
	treeIndent = "    "
	// colourDir is tree's built-in colour for a directory.
	colourDir = "\033[01;34m"
	// colourFile is tree's built-in colour for a plain file.
	colourFile = "\033[00m"
	// colourReset ends a coloured span.
	colourReset = "\033[0m"
)

// style captures the glyph and colour decisions for one rendering.
type style struct {
	// branch precedes every entry except the last of its level.
	branch string
	// last precedes the last entry of its level.
	last string
	// vertical continues a parent's line through deeper levels.
	vertical string
	// colour reports whether escape sequences are emitted at all.
	colour bool
}

// detectStyle mirrors tree(1)'s own choices for the current environment.
func detectStyle(env func(string) string) style {
	s := style{
		branch:   treeBranchASCII,
		last:     treeLastASCII,
		vertical: treeVerticalASCII,
		colour:   env("TERM") != "",
	}
	if isUTF8(env) {
		s.branch, s.last, s.vertical = treeBranchUTF, treeLastUTF, treeVerticalUTF
	}
	return s
}

// isUTF8 reports whether the locale codeset is UTF-8, following the usual
// LC_ALL, LC_CTYPE, LANG precedence.
func isUTF8(env func(string) string) bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := env(key); v != "" {
			v = strings.ToUpper(v)
			return strings.Contains(v, "UTF-8") || strings.Contains(v, "UTF8")
		}
	}
	return false
}

// treeNode is one directory or entry in a rendered listing.
type treeNode struct {
	// name is the last path component.
	name string
	// children are the nodes below this one, nil for an entry.
	children map[string]*treeNode
}

// newTreeNode returns an empty node.
func newTreeNode(name string) *treeNode {
	return &treeNode{name: name, children: map[string]*treeNode{}}
}

// insert adds a slash-separated entry path under n.
func (n *treeNode) insert(path string) {
	parts := strings.Split(path, "/")
	cur := n
	for i, part := range parts {
		child, ok := cur.children[part]
		if !ok {
			child = newTreeNode(part)
			if i == len(parts)-1 {
				// A leaf has no children map, which is how the renderer
				// tells an entry from an empty directory.
				child.children = nil
			}
			cur.children[part] = child
		}
		cur = child
	}
}

// sortedChildren returns the children in the order tree(1) prints them.
func (n *treeNode) sortedChildren() []*treeNode {
	out := make([]*treeNode, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// renderTree writes the listing of names under the given heading, in the exact
// shape `pass ls` produces.
func renderTree(w io.Writer, heading string, names []string) error {
	return renderTreeStyled(w, heading, names, detectStyle(os.Getenv))
}

// renderTreeStyled is renderTree with an explicit style, so that the golden
// tests can pin one instead of depending on the environment.
func renderTreeStyled(w io.Writer, heading string, names []string, s style) error {
	root := newTreeNode("")
	for _, name := range names {
		root.insert(name)
	}
	// `pass find` prints no heading at all, having stripped tree's root line.
	if heading != "" {
		if _, err := fmt.Fprintln(w, heading); err != nil {
			return err
		}
	}
	return writeNodes(w, root, "", s)
}

// writeNodes renders the children of n, prefixing each line with prefix.
func writeNodes(w io.Writer, n *treeNode, prefix string, s style) error {
	children := n.sortedChildren()
	for i, child := range children {
		last := i == len(children)-1

		connector := s.branch
		if last {
			connector = s.last
		}
		name := child.name
		if s.colour {
			colour := colourFile
			if child.children != nil {
				colour = colourDir
			}
			name = colour + name + colourReset
		}
		if _, err := fmt.Fprintf(w, "%s%s%s\n", prefix, connector, name); err != nil {
			return err
		}

		if child.children == nil {
			continue
		}
		next := prefix + s.vertical
		if last {
			next = prefix + treeIndent
		}
		if err := writeNodes(w, child, next, s); err != nil {
			return err
		}
	}
	return nil
}
