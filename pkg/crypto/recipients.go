package crypto

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// findRecipientsFile locates the recipients file governing dir by walking from
// dir up to root, as pass does: the nearest file wins, so a subtree can be
// shared with a different set of people than its parent.
func findRecipientsFile(root, dir, name string) (string, error) {
	root = filepath.Clean(root)
	dir = filepath.Clean(dir)
	if !isWithin(root, dir) {
		return "", fmt.Errorf("crypto: %q is outside the store %q", dir, root)
	}
	for {
		candidate := filepath.Join(dir, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
		if dir == root {
			return "", fmt.Errorf("crypto: no %s found for %q", name, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("crypto: no %s found for %q", name, dir)
		}
		dir = parent
	}
}

// isWithin reports whether path is root or lies beneath it.
func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || !strings.HasPrefix(rel, "..")
}

// readRecipientsFile parses a recipients file: one recipient per line, blank
// lines and '#' comments ignored.
func readRecipientsFile(path string) ([]Recipient, error) {
	f, err := os.Open(path) //nolint:gosec // path is resolved within the store.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []Recipient
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, Recipient(line))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("crypto: %s lists no recipients", path)
	}
	return out, nil
}

// WriteRecipients writes recipients to path, one per line, with 0600 perms.
func WriteRecipients(path string, rcp []Recipient) error {
	if len(rcp) == 0 {
		return ErrNoRecipients
	}
	var sb strings.Builder
	for _, r := range rcp {
		sb.WriteString(r.String())
		sb.WriteString("\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(sb.String()), 0o600)
}
