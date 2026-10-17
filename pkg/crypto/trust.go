package crypto

import (
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// RecipientSets records, per recipients file, the recipients that file
// listed when binpass last looked at it. Keys are store-relative paths, so
// the record survives a store that moves.
type RecipientSets map[string][]string

// RecipientChange reports how one recipients file changed between two
// observations.
type RecipientChange struct {
	// File is the recipients file, as keyed in the RecipientSets.
	File string
	// Added are recipients that will be able to read what is written from
	// now on but could not read what came before.
	Added []string
	// Removed are recipients the file no longer lists.
	Removed []string
}

// Empty reports whether the change carries nothing worth telling anyone.
func (c RecipientChange) Empty() bool { return len(c.Added) == 0 && len(c.Removed) == 0 }

// DiffRecipientSets reports how the recipient sets changed between two
// observations.
//
// The threat is a remote that can write to the store: adding a line to
// .gpg-id makes every later edit encrypt to the attacker as well, and pass's
// model trusts that file unconditionally. Diffing it against what was seen
// before is what turns a silent change into something a person can notice.
//
// A file seen for the first time reports nothing: there is no baseline, and
// warning about every file of a fresh store would teach the user to skip the
// warning that matters. A file that disappeared is reported as a full
// removal, because the parent directory's set silently takes over.
func DiffRecipientSets(before, after RecipientSets) []RecipientChange {
	var out []RecipientChange
	for file, now := range after {
		was, seen := before[file]
		if !seen {
			continue
		}
		c := RecipientChange{File: file}
		c.Added, c.Removed = diffStrings(was, now)
		if c.Empty() {
			continue
		}
		out = append(out, c)
	}
	for file, was := range before {
		if _, ok := after[file]; ok {
			continue
		}
		_, removed := diffStrings(was, nil)
		out = append(out, RecipientChange{File: file, Removed: removed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

// diffStrings reports what after adds and what it drops, both sorted so that
// a warning reads the same way twice.
func diffStrings(before, after []string) (added, removed []string) {
	was := make(map[string]bool, len(before))
	for _, s := range before {
		was[s] = true
	}
	now := make(map[string]bool, len(after))
	for _, s := range after {
		now[s] = true
		if !was[s] {
			added = append(added, s)
		}
	}
	for _, s := range before {
		if !now[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// AgePluginBinary returns the age-plugin executable a recipient string makes
// age run, or "" for a recipient that needs no plugin.
//
// Which binary runs is decided by a file inside the store, so a plugin
// recipient that arrives over a sync is store content choosing a program to
// execute. Naming the binary is the difference between a warning someone can
// act on and a line of bech32.
func AgePluginBinary(r string) string {
	s := strings.TrimSpace(r)
	if !strings.HasPrefix(s, "age1") {
		return ""
	}
	if _, err := age.ParseX25519Recipient(s); err == nil {
		return ""
	}
	name, _, err := plugin.ParseRecipient(s)
	if err != nil {
		return ""
	}
	return "age-plugin-" + name
}

// RecipientStrings renders recipients for the record, deduplicated and
// sorted so that reordering a file is not reported as a change.
func RecipientStrings(rcp []Recipient) []string {
	seen := make(map[string]bool, len(rcp))
	out := make([]string, 0, len(rcp))
	for _, r := range rcp {
		s := r.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
