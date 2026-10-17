package sopsfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// ErrUnsupported reports a file whose extension names no format binpass
// handles through sops.
var ErrUnsupported = errors.New("sopsfile: unsupported file type (want .yaml, .yml or .json)")

// ErrNoSops reports that the sops binary is not on PATH.
var ErrNoSops = errors.New("sopsfile: sops not on PATH")

// ErrIsGroup reports a key operation applied to a group.
var ErrIsGroup = errors.New("sopsfile: name is a group, not a key")

// ErrIsKey reports a group operation applied to a key.
var ErrIsKey = errors.New("sopsfile: name is a key, not a group")

// File is one sops-encrypted document addressed as a tree of keys.
//
// The decrypted document is cached after the first read and dropped after
// every write, so a session decrypts once per change rather than once per
// key; concurrent edits by another process are picked up on the next write.
type File struct {
	// path is the name as given, for messages. sops runs on abs from dir:
	// it finds .sops.yaml by walking up from its working directory, not
	// from the file, and matches path_regex against the file's path
	// relative to that config (verified on 3.13.3). Running from the
	// file's directory is what makes `binpass sops edit nixos/secrets/x.yaml`
	// from a repo root honour the rules next to the file.
	path   string
	abs    string
	dir    string
	format string
	sops   string

	mu  sync.Mutex
	doc map[string]any
}

// Open prepares path for editing. It validates the extension and locates
// sops, but does not decrypt: a missing file is an empty document until the
// first key is written.
func Open(path string) (*File, error) {
	var format string
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		format = "yaml"
	case ".json":
		format = "json"
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, path)
	}
	bin, err := exec.LookPath("sops")
	if err != nil {
		return nil, ErrNoSops
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return &File{path: path, abs: abs, dir: filepath.Dir(abs), format: format, sops: bin}, nil
}

// Path returns the file path as it was given to Open.
func (f *File) Path() string { return f.path }

// Dir returns the absolute directory holding the file.
func (f *File) Dir() string { return f.dir }

// List returns the key names under sub, sorted. Empty groups contribute
// nothing; a missing file lists nothing.
func (f *File) List(sub string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	segs, err := split(sub)
	if err != nil {
		return nil, err
	}
	v, ok := lookup(doc, segs)
	if !ok {
		return nil, fmt.Errorf("%w: %s", store.ErrNotFound, sub)
	}
	if _, isMap := v.(map[string]any); !isMap {
		return nil, fmt.Errorf("%w: %s", ErrIsKey, sub)
	}
	var out []string
	if err := leaves(strings.Join(segs, "/"), v, &out); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// Get returns the value of the key called name. String values are returned
// verbatim; any other scalar or list is rendered as its JSON text.
func (f *File) Get(name string) (*secret.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	v, err := f.key(doc, name)
	if err != nil {
		return nil, err
	}
	if s, ok := v.(string); ok {
		return secret.Parse([]byte(s)), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return secret.Parse(b), nil
}

// Set writes sec as the value of name, creating missing groups and, when
// the file itself does not exist yet, the file. The secret format always
// terminates the password line; see normalize for how that is undone so
// single-line tokens stay byte-identical for their consumers.
func (f *File) Set(name string, sec *secret.Secret) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return err
	}
	segs, err := split(name)
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		return fmt.Errorf("sopsfile: empty key name")
	}
	if err := checkParents(doc, segs); err != nil {
		return err
	}
	orig, exists := lookup(doc, segs)
	if _, isMap := orig.(map[string]any); exists && isMap {
		return fmt.Errorf("%w: %s", ErrIsGroup, name)
	}
	return f.write(segs, string(normalize(sec.Bytes(), orig, exists)))
}

// Remove deletes the key called name.
func (f *File) Remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return err
	}
	if _, err := f.key(doc, name); err != nil {
		return err
	}
	segs, _ := split(name)
	return f.unset(segs)
}

// RemoveDir deletes the group called name and every key beneath it.
func (f *File) RemoveDir(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return err
	}
	segs, err := split(name)
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		return fmt.Errorf("sopsfile: refusing to remove the whole document")
	}
	v, ok := lookup(doc, segs)
	if !ok {
		return fmt.Errorf("%w: %s", store.ErrNotFound, name)
	}
	if _, isMap := v.(map[string]any); !isMap {
		return fmt.Errorf("%w: %s", ErrIsKey, name)
	}
	return f.unset(segs)
}

// Move renames a key or a group. The destination must not exist.
func (f *File) Move(from, to string) error { return f.transfer(from, to, true) }

// Copy duplicates a key or a group. The destination must not exist.
func (f *File) Copy(from, to string) error { return f.transfer(from, to, false) }

// IsDir reports whether name is a group. The empty name is the document root.
func (f *File) IsDir(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return false
	}
	segs, err := split(name)
	if err != nil {
		return false
	}
	v, ok := lookup(doc, segs)
	if !ok {
		return false
	}
	_, isMap := v.(map[string]any)
	return isMap
}

// Exists reports whether name is a key.
func (f *File) Exists(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return false
	}
	_, err = f.key(doc, name)
	return err == nil
}

// Grep returns every key under sub with the lines of its value that satisfy
// match.
func (f *File) Grep(sub string, match func(string) bool) ([]store.Match, error) {
	names, err := f.List(sub)
	if err != nil {
		return nil, err
	}
	var out []store.Match
	for _, name := range names {
		sec, err := f.Get(name)
		if err != nil {
			return nil, err
		}
		var lines []string
		for _, line := range sec.Lines() {
			if match(line) {
				lines = append(lines, line)
			}
		}
		if len(lines) > 0 {
			out = append(out, store.Match{Name: name, Lines: lines})
		}
	}
	return out, nil
}

// transfer implements Move and Copy. The destination is written before the
// source is removed so an interrupted move loses nothing.
func (f *File) transfer(from, to string, remove bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return err
	}
	src, err := split(from)
	if err != nil {
		return err
	}
	dst, err := split(to)
	if err != nil {
		return err
	}
	if len(src) == 0 || len(dst) == 0 {
		return fmt.Errorf("sopsfile: empty name")
	}
	v, ok := lookup(doc, src)
	if !ok {
		return fmt.Errorf("%w: %s", store.ErrNotFound, from)
	}
	if _, exists := lookup(doc, dst); exists {
		return fmt.Errorf("%w: %s", store.ErrExists, to)
	}
	if isPrefix(src, dst) {
		return fmt.Errorf("sopsfile: cannot move %s into itself", from)
	}
	if err := checkParents(doc, dst); err != nil {
		return err
	}
	if err := f.write(dst, v); err != nil {
		return err
	}
	if !remove {
		return nil
	}
	return f.unset(src)
}

// key resolves name to a key's value, rejecting groups and missing names.
func (f *File) key(doc map[string]any, name string) (any, error) {
	segs, err := split(name)
	if err != nil {
		return nil, err
	}
	v, ok := lookup(doc, segs)
	if !ok || len(segs) == 0 {
		return nil, fmt.Errorf("%w: %s", store.ErrNotFound, name)
	}
	if _, isMap := v.(map[string]any); isMap {
		return nil, fmt.Errorf("%w: %s", ErrIsGroup, name)
	}
	return v, nil
}

// load returns the decrypted document, reading it on first use.
func (f *File) load() (map[string]any, error) {
	if f.doc != nil {
		return f.doc, nil
	}
	if !f.exists() {
		f.doc = map[string]any{}
		return f.doc, nil
	}
	out, err := f.run(nil, "decrypt", "--output-type", "json", f.abs)
	if err != nil {
		return nil, err
	}
	// UseNumber keeps integers as written; float64 would turn 10 into 1e+01
	// when a value is copied.
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("sopsfile: parsing decrypted %s: %w", f.path, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	f.doc = doc
	return doc, nil
}

func (f *File) exists() bool {
	_, err := os.Stat(f.abs)
	return err == nil
}

// write stores v at segs. On an existing file this is `sops set`, which
// leaves the data key and every other value untouched; a new file is
// encrypted from scratch so .sops.yaml creation rules pick its recipients.
func (f *File) write(segs []string, v any) error {
	f.doc = nil
	if f.exists() {
		p, err := sopsPath(segs)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = f.run(payload, "set", "--value-stdin", f.abs, p)
		return err
	}
	doc := map[string]any{}
	cur := doc
	for _, s := range segs[:len(segs)-1] {
		next := map[string]any{}
		cur[s] = next
		cur = next
	}
	cur[segs[len(segs)-1]] = v
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	out, err := f.run(body, "encrypt", "--filename-override", f.abs,
		"--input-type", "json", "--output-type", f.format)
	if err != nil {
		return err
	}
	return f.replace(out)
}

func (f *File) unset(segs []string) error {
	f.doc = nil
	p, err := sopsPath(segs)
	if err != nil {
		return err
	}
	_, err = f.run(nil, "unset", f.abs, p)
	return err
}

// replace writes ciphertext to the file through a temp file in the same
// directory so a crash never leaves a half-written document.
func (f *File) replace(ciphertext []byte) error {
	tmp, err := os.CreateTemp(f.dir, ".binpass-sops-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(ciphertext); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, f.abs); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// run executes sops with stdin and returns its stdout. Values only ever
// travel on stdin; args carry the file and the key path.
func (f *File) run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(f.sops, args...) //nolint:gosec // binary resolved by LookPath, args built here.
	cmd.Dir = f.dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("sops %s: %s", args[0], msg)
	}
	return out, nil
}

// sopsPath renders segs in sops's bracketed path syntax. sops splits the
// argument on '[' and strips one quote from each end of a component with
// no escaping at all, so segments are written verbatim and a '[' in a key
// name cannot be expressed.
func sopsPath(segs []string) (string, error) {
	var b strings.Builder
	for _, s := range segs {
		if strings.Contains(s, "[") {
			return "", fmt.Errorf("sopsfile: key %q contains '[' and cannot be addressed by sops", s)
		}
		b.WriteString(`["`)
		b.WriteString(s)
		b.WriteString(`"]`)
	}
	return b.String(), nil
}

// normalize undoes the line terminator the secret format imposes on the
// password line. An existing string keeps its own termination so an edit
// never flips it; a new value drops the terminator only when it is the sole
// newline, so key material that legitimately ends in a newline is kept.
func normalize(raw []byte, orig any, exists bool) []byte {
	if s, ok := orig.(string); exists && ok {
		if strings.HasSuffix(s, "\n") {
			return raw
		}
		return bytes.TrimSuffix(raw, []byte("\n"))
	}
	if n := len(raw); n > 0 && raw[n-1] == '\n' && bytes.IndexByte(raw, '\n') == n-1 {
		return raw[:n-1]
	}
	return raw
}

// split turns a "/"-joined name into its segments; the empty name is the root.
func split(name string) ([]string, error) {
	name = strings.Trim(name, "/")
	if name == "" {
		return nil, nil
	}
	segs := strings.Split(name, "/")
	for _, s := range segs {
		if s == "" {
			return nil, fmt.Errorf("sopsfile: invalid name %q", name)
		}
	}
	return segs, nil
}

// lookup walks segs down from the root; ok is false when any step is missing
// or passes through a non-group.
func lookup(doc map[string]any, segs []string) (any, bool) {
	var cur any = doc
	for _, s := range segs {
		m, isMap := cur.(map[string]any)
		if !isMap {
			return nil, false
		}
		v, ok := m[s]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// checkParents rejects a path whose ancestor is a key: sops set would
// silently replace that key with a group.
func checkParents(doc map[string]any, segs []string) error {
	for i := 1; i < len(segs); i++ {
		v, ok := lookup(doc, segs[:i])
		if !ok {
			return nil
		}
		if _, isMap := v.(map[string]any); !isMap {
			return fmt.Errorf("%w: %s", ErrIsKey, strings.Join(segs[:i], "/"))
		}
	}
	return nil
}

// leaves appends the name of every key beneath v to out.
func leaves(prefix string, v any, out *[]string) error {
	m, isMap := v.(map[string]any)
	if !isMap {
		*out = append(*out, prefix)
		return nil
	}
	for k, child := range m {
		if strings.Contains(k, "/") {
			return fmt.Errorf("sopsfile: key %q contains '/' and cannot be addressed", k)
		}
		name := k
		if prefix != "" {
			name = prefix + "/" + k
		}
		if err := leaves(name, child, out); err != nil {
			return err
		}
	}
	return nil
}

func isPrefix(prefix, path []string) bool {
	if len(prefix) > len(path) {
		return false
	}
	for i := range prefix {
		if prefix[i] != path[i] {
			return false
		}
	}
	return true
}
