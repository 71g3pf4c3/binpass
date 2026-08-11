package secretservice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"sort"
)

// blindLen is how much of the HMAC is kept. 16 bytes is 128 bits: far past
// the point where a collision could be found, and short enough that the
// index of a large store stays small.
const blindLen = 16

// Blind computes the lookup key for one attribute pair.
//
// The name and value are separated by a NUL so that the pairs ("ab", "c")
// and ("a", "bc") cannot produce the same key — without a separator they
// would hash the same bytes, and an attacker who could choose attribute
// names would decide what a search matches.
//
// The index key never leaves the machine: it is derived from the store's
// identity, so a provider holding the index sees base32 of a keyed hash and
// cannot compute the hash of a guess.
func Blind(indexKey []byte, name, value string) string {
	m := hmac.New(sha256.New, indexKey)
	m.Write([]byte(name))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString(m.Sum(nil)[:blindLen])
}

// Index maps blinded attribute pairs to the items carrying them.
//
// It exists so that a search costs one map lookup rather than decrypting
// every item in the store: with a few hundred items and a hardware token,
// the difference is between instant and unusable.
type Index struct {
	// Version allows the on-disk format to change without silently
	// misreading an older file.
	Version int `json:"version"`
	// Entries maps a blinded pair to the item IDs that carry it.
	Entries map[string][]string `json:"entries"`
}

// IndexVersion is the current on-disk index format.
const IndexVersion = 1

// NewIndex returns an empty index.
func NewIndex() *Index {
	return &Index{Version: IndexVersion, Entries: map[string][]string{}}
}

// Add records every attribute of an item.
func (ix *Index) Add(indexKey []byte, it *Item) {
	for k, v := range it.Attributes {
		b := Blind(indexKey, k, v)
		if !contains(ix.Entries[b], it.ID) {
			ix.Entries[b] = append(ix.Entries[b], it.ID)
			sort.Strings(ix.Entries[b])
		}
	}
}

// Remove drops an item from every pair it was recorded under.
func (ix *Index) Remove(id string) {
	for b, ids := range ix.Entries {
		out := ids[:0:0]
		for _, existing := range ids {
			if existing != id {
				out = append(out, existing)
			}
		}
		if len(out) == 0 {
			delete(ix.Entries, b)
			continue
		}
		ix.Entries[b] = out
	}
}

// Search returns the IDs of items carrying every pair in the query.
//
// An empty query returns nothing rather than everything: callers that want
// the whole collection ask the store for it, and having the two cases look
// alike here would make "match nothing" and "match all" one typo apart.
func (ix *Index) Search(indexKey []byte, query map[string]string) []string {
	if len(query) == 0 {
		return nil
	}

	// Intersect the candidate sets. Starting from the smallest keeps the
	// work proportional to the most selective attribute rather than to the
	// size of the store.
	var sets [][]string
	for k, v := range query {
		ids := ix.Entries[Blind(indexKey, k, v)]
		if len(ids) == 0 {
			// One attribute nobody carries means the whole query matches
			// nothing, whatever the others say.
			return nil
		}
		sets = append(sets, ids)
	}
	sort.Slice(sets, func(i, j int) bool { return len(sets[i]) < len(sets[j]) })

	out := append([]string(nil), sets[0]...)
	for _, s := range sets[1:] {
		out = intersect(out, s)
		if len(out) == 0 {
			return nil
		}
	}
	sort.Strings(out)
	return out
}

// MarshalJSON is the on-disk form. The index is written encrypted, so this
// is only ever the plaintext inside that file.
func (ix *Index) MarshalJSON() ([]byte, error) {
	type alias Index
	return json.Marshal((*alias)(ix))
}

// UnmarshalJSON reads the on-disk form, refusing a version it was not
// written to understand.
func (ix *Index) UnmarshalJSON(data []byte) error {
	type alias Index
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	if a.Version != IndexVersion {
		return fmt.Errorf("secretservice: index version %d, want %d (run `binpass ss reindex`)",
			a.Version, IndexVersion)
	}
	if a.Entries == nil {
		a.Entries = map[string][]string{}
	}
	*ix = Index(a)
	return nil
}

// intersect returns the values present in both sorted-or-not slices.
func intersect(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	out := a[:0:0]
	for _, s := range a {
		if set[s] {
			out = append(out, s)
		}
	}
	return out
}

// contains reports whether the slice already holds s.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
