// Package secretservice implements the org.freedesktop.secrets provider on
// top of the password store, so that programs which already speak Secret
// Service — Chrome, VS Code, NetworkManager, Evolution — read their secrets
// from the same store binpass manages, without knowing it exists.
//
// # Why the attributes are not stored in the clear
//
// A Secret Service item is a password plus a set of attributes:
// application, server, username, and so on. pass-secret-service writes those
// attributes in plaintext beside the ciphertext, which its README states
// outright. That means the full map of every account — every host you have
// an account with and under what name — sits unencrypted in whatever git
// host or cloud drive the store is synchronised to, even though the
// passwords themselves are encrypted.
//
// This implementation puts the attributes inside the encrypted file and
// keeps a separate index of keyed hashes for lookup. The specification is
// what makes that possible: SearchItems matches attribute pairs exactly,
// never by substring or prefix, so a deterministic HMAC is a complete search
// index rather than a compromise. What leaks is that two items share some
// attribute value, which is a great deal less than naming the values.
package secretservice

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
)

// attrPrefix marks an attribute line inside a stored item, keeping
// attributes in their own namespace so that an attribute called "label"
// cannot be mistaken for the item's label.
const attrPrefix = "attr."

// Item is one Secret Service item: a secret plus the attributes programs
// search it by.
type Item struct {
	// ID is the item's identifier, unique within its collection, and the
	// last element of its D-Bus object path.
	ID string
	// Label is the human-readable name shown by keyring browsers.
	Label string
	// Attributes are the searchable key/value pairs.
	Attributes map[string]string
	// Secret is the secret value itself.
	Secret string
	// Created is when the item was first stored.
	Created time.Time
	// Modified is when the secret or its attributes last changed.
	Modified time.Time
}

// ToSecret renders an item as a pass-format secret.
//
// The layout is deliberately one a human can read with `binpass show` and
// `pass show`: the secret on the first line, then ordinary `key: value`
// fields. An item written by a browser stays an entry you can inspect and
// edit by hand.
func (i *Item) ToSecret() *secret.Secret {
	var b strings.Builder
	b.WriteString(i.Secret)
	b.WriteString("\n")

	if i.Label != "" {
		fmt.Fprintf(&b, "label: %s\n", i.Label)
	}

	// Sorted, so that rewriting an unchanged item produces an identical file
	// and does not show up as a change to sync or to git.
	for _, k := range sortedKeys(i.Attributes) {
		fmt.Fprintf(&b, "%s%s: %s\n", attrPrefix, k, i.Attributes[k])
	}

	if !i.Created.IsZero() {
		fmt.Fprintf(&b, "created: %d\n", i.Created.Unix())
	}
	if !i.Modified.IsZero() {
		fmt.Fprintf(&b, "modified: %d\n", i.Modified.Unix())
	}
	return secret.Parse([]byte(b.String()))
}

// ItemFromSecret parses a stored entry back into an item.
//
// Anything that is not a recognised field is left alone rather than
// discarded: a user who adds a note to an item's file should still have it
// there after a program updates the secret.
func ItemFromSecret(id string, sec *secret.Secret) *Item {
	it := &Item{
		ID:         id,
		Attributes: map[string]string{},
		Secret:     sec.Password(),
	}
	for _, f := range sec.Fields() {
		switch {
		case f.Key == "label":
			it.Label = f.Value
		case strings.HasPrefix(f.Key, attrPrefix):
			it.Attributes[strings.TrimPrefix(f.Key, attrPrefix)] = f.Value
		case f.Key == "created":
			it.Created = parseUnix(f.Value)
		case f.Key == "modified":
			it.Modified = parseUnix(f.Value)
		}
	}
	return it
}

// Matches reports whether the item carries every attribute in query with the
// given value.
//
// The specification calls for exact matching on each pair, and an empty
// query matches everything: that is how a client asks for the contents of a
// collection.
func (i *Item) Matches(query map[string]string) bool {
	for k, v := range query {
		if i.Attributes[k] != v {
			return false
		}
	}
	return true
}

// parseUnix reads a Unix timestamp, returning the zero time when it is not
// one. A corrupt timestamp is not worth failing an item over.
func parseUnix(s string) time.Time {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// sortedKeys returns a map's keys in a stable order.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
