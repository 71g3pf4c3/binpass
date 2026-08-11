package secretservice

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
)

// Root is the subtree of the password store that holds Secret Service items.
//
// Keeping them under one directory means a user can see exactly what
// programs have stored, back it up, and delete the lot, without picking
// items out of their own entries.
const Root = "secret-service"

// DefaultCollection is the collection clients get when they ask for the
// default alias. "login" is what gnome-keyring calls its own, and programs
// that hardcode a collection name overwhelmingly hardcode that one.
const DefaultCollection = "login"

// indexName is the encrypted index file, kept beside the collections.
//
// The leading dot keeps it out of `binpass ls`: it is machinery, not an
// entry, and listing it would put a file nobody can read among the
// passwords.
const indexName = ".index"

// ErrNotFound reports an item or collection that does not exist.
var ErrNotFound = errors.New("secretservice: not found")

// ErrLocked reports an operation needing a store that cannot be decrypted.
var ErrLocked = errors.New("secretservice: store is locked")

// Store is the persistence layer: items are entries in the password store,
// and the attribute index is one encrypted file beside them.
type Store struct {
	// pass is the underlying password store.
	pass PassStore
	// indexKey keys the attribute HMACs. It never leaves the process.
	indexKey []byte
	// cached is the index held in memory between operations.
	cached *Index
}

// PassStore is the part of pkg/store this package needs. Depending on an
// interface keeps the D-Bus layer testable without a real store on disk.
type PassStore interface {
	// Get decrypts the entry called name.
	Get(name string) (*secret.Secret, error)
	// Set encrypts a secret to the entry called name.
	Set(name string, sec *secret.Secret) error
	// List returns the entry names under sub.
	List(sub string) ([]string, error)
	// Remove deletes the entry called name.
	Remove(name string) error
	// Exists reports whether an entry exists.
	Exists(name string) bool
}

// NewStore returns a Store over a password store.
//
// The index key is derived from a caller-supplied seed rather than generated
// here, so that the same store produces the same blinded keys on every
// machine it is synchronised to. A key that differed per machine would make
// each one rebuild the whole index on first use and, worse, make an index
// synchronised from elsewhere silently match nothing.
func NewStore(pass PassStore, seed []byte) *Store {
	m := hmac.New(sha256.New, seed)
	m.Write([]byte("binpass secret-service attribute index v1"))
	return &Store{pass: pass, indexKey: m.Sum(nil)}
}

// itemPath returns the store path of an item.
func itemPath(collection, id string) string {
	return path.Join(Root, collection, id)
}

// Collections returns the collection names that exist.
func (s *Store) Collections() ([]string, error) {
	entries, err := s.pass.List(Root)
	if err != nil {
		// A store where nothing has been written yet has no directory, and
		// that is not an error: it is an empty keyring.
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		rel := strings.TrimPrefix(e, Root+"/")
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		if !seen[parts[0]] {
			seen[parts[0]] = true
			out = append(out, parts[0])
		}
	}
	sort.Strings(out)
	return out, nil
}

// Items returns every item in a collection.
func (s *Store) Items(collection string) ([]*Item, error) {
	entries, err := s.pass.List(path.Join(Root, collection))
	if err != nil {
		return nil, nil
	}
	var out []*Item
	for _, e := range entries {
		id := path.Base(e)
		if strings.HasPrefix(id, ".") {
			continue
		}
		it, err := s.Item(collection, id)
		if err != nil {
			continue
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Item reads one item.
func (s *Store) Item(collection, id string) (*Item, error) {
	sec, err := s.pass.Get(itemPath(collection, id))
	if err != nil {
		return nil, fmt.Errorf("%w: %s/%s", ErrNotFound, collection, id)
	}
	return ItemFromSecret(id, sec), nil
}

// CreateItem stores an item, assigning an ID when it has none, and updates
// the index.
//
// When replace is false and an item with the same attributes already exists,
// the existing one is returned untouched: the specification says a client
// asking to create a duplicate gets the original rather than a second copy.
func (s *Store) CreateItem(collection string, it *Item, replace bool) (*Item, error) {
	if existing, err := s.findByAttributes(collection, it.Attributes); err == nil && existing != nil {
		if !replace {
			return existing, nil
		}
		it.ID = existing.ID
		it.Created = existing.Created
	}

	if it.ID == "" {
		id, err := newID()
		if err != nil {
			return nil, err
		}
		it.ID = id
	}
	now := time.Now()
	if it.Created.IsZero() {
		it.Created = now
	}
	it.Modified = now

	if err := s.pass.Set(itemPath(collection, it.ID), it.ToSecret()); err != nil {
		return nil, fmt.Errorf("secretservice: storing item: %w", err)
	}

	ix, err := s.index()
	if err != nil {
		return nil, err
	}
	ix.Remove(it.ID)
	ix.Add(s.indexKey, it)
	if err := s.saveIndex(ix); err != nil {
		return nil, err
	}
	return it, nil
}

// DeleteItem removes an item and its index entries.
func (s *Store) DeleteItem(collection, id string) error {
	if err := s.pass.Remove(itemPath(collection, id)); err != nil {
		return fmt.Errorf("%w: %s/%s", ErrNotFound, collection, id)
	}
	ix, err := s.index()
	if err != nil {
		return err
	}
	ix.Remove(id)
	return s.saveIndex(ix)
}

// Search returns the items in a collection matching every attribute pair.
//
// The index answers the query; the items it names are then read and checked
// again. That second pass is not redundant: the index maps a hash, and two
// different pairs could in principle hash alike. Confirming against the
// decrypted attributes means a collision returns fewer results, never wrong
// ones.
func (s *Store) Search(collection string, query map[string]string) ([]*Item, error) {
	if len(query) == 0 {
		return s.Items(collection)
	}

	ix, err := s.index()
	if err != nil {
		return nil, err
	}

	var out []*Item
	for _, id := range ix.Search(s.indexKey, query) {
		it, err := s.Item(collection, id)
		if err != nil {
			// Indexed but missing: the entry was deleted by hand. Skipping
			// it here keeps searching usable, and `ss reindex` cleans up.
			continue
		}
		if it.Matches(query) {
			out = append(out, it)
		}
	}
	return out, nil
}

// findByAttributes returns an item with exactly these attributes, if one
// exists.
func (s *Store) findByAttributes(collection string, attrs map[string]string) (*Item, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	items, err := s.Search(collection, attrs)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		// Equal length plus Matches means the sets are equal: a client
		// updating "server=x, user=y" must not overwrite an item that
		// merely also carries those two among others.
		if len(it.Attributes) == len(attrs) {
			return it, nil
		}
	}
	return nil, nil
}

// Reindex rebuilds the index from the items on disk.
//
// Needed after a sync brings in items from another machine, and as the
// repair for an index that has drifted from the store for any other reason.
func (s *Store) Reindex() (int, error) {
	ix := NewIndex()
	collections, err := s.Collections()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, c := range collections {
		items, err := s.Items(c)
		if err != nil {
			return 0, err
		}
		for _, it := range items {
			ix.Add(s.indexKey, it)
			count++
		}
	}
	s.cached = ix
	return count, s.saveIndex(ix)
}

// index returns the index, reading it from the store on first use.
func (s *Store) index() (*Index, error) {
	if s.cached != nil {
		return s.cached, nil
	}
	name := path.Join(Root, indexName)
	if !s.pass.Exists(name) {
		s.cached = NewIndex()
		return s.cached, nil
	}
	sec, err := s.pass.Get(name)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the attribute index: %v", ErrLocked, err)
	}
	ix := NewIndex()
	if err := json.Unmarshal([]byte(sec.String()), ix); err != nil {
		// A damaged index is recoverable — the items are the truth — so say
		// what to run rather than failing the operation outright.
		return nil, fmt.Errorf("secretservice: attribute index is unreadable (%w); run `binpass ss reindex`", err)
	}
	s.cached = ix
	return ix, nil
}

// saveIndex writes the index back to the store.
func (s *Store) saveIndex(ix *Index) error {
	data, err := json.Marshal(ix)
	if err != nil {
		return err
	}
	s.cached = ix
	// Stored as an ordinary encrypted entry: the index is as sensitive as
	// the attribute names it indexes, which is the whole reason it exists.
	return s.pass.Set(path.Join(Root, indexName), secret.Parse(append(data, '\n')))
}

// newID returns a random item identifier.
//
// Random rather than sequential: an incrementing ID would publish how many
// items exist and in what order they were created, in the one part of the
// layout that stays visible outside the ciphertext — the file name.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secretservice: generating item id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
