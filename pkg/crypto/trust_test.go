package crypto_test

import (
	"testing"

	"filippo.io/age/plugin"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
)

// TestDiffRecipientSets covers the case the audit named: a remote that can
// write to the store adds its own key to .gpg-id, and the next edit encrypts
// to it. The diff is the only thing standing between that and silence.
func TestDiffRecipientSets(t *testing.T) {
	tests := []struct {
		name   string
		before crypto.RecipientSets
		after  crypto.RecipientSets
		want   []crypto.RecipientChange
	}{
		{
			name:   "first sight is silent",
			before: crypto.RecipientSets{},
			after:  crypto.RecipientSets{".gpg-id": {"alice"}},
		},
		{
			name:   "unchanged",
			before: crypto.RecipientSets{".gpg-id": {"alice", "bob"}},
			after:  crypto.RecipientSets{".gpg-id": {"alice", "bob"}},
		},
		{
			name:   "an extra recipient appears",
			before: crypto.RecipientSets{".gpg-id": {"alice"}},
			after:  crypto.RecipientSets{".gpg-id": {"alice", "mallory"}},
			want:   []crypto.RecipientChange{{File: ".gpg-id", Added: []string{"mallory"}}},
		},
		{
			name:   "a recipient is dropped",
			before: crypto.RecipientSets{"work/.gpg-id": {"alice", "bob"}},
			after:  crypto.RecipientSets{"work/.gpg-id": {"alice"}},
			want:   []crypto.RecipientChange{{File: "work/.gpg-id", Removed: []string{"bob"}}},
		},
		{
			name:   "the whole file is gone, so the parent set takes over",
			before: crypto.RecipientSets{"work/.gpg-id": {"bob"}},
			after:  crypto.RecipientSets{},
			want:   []crypto.RecipientChange{{File: "work/.gpg-id", Removed: []string{"bob"}}},
		},
		{
			name:   "reordering a file is not a change",
			before: crypto.RecipientSets{".age-recipients": {"alice", "bob"}},
			after:  crypto.RecipientSets{".age-recipients": {"bob", "alice"}},
		},
		{
			name: "every changed file is reported, in a stable order",
			before: crypto.RecipientSets{
				"b/.gpg-id": {"alice"},
				"a/.gpg-id": {"alice"},
			},
			after: crypto.RecipientSets{
				"b/.gpg-id": {"alice", "mallory"},
				"a/.gpg-id": {"mallory"},
			},
			want: []crypto.RecipientChange{
				{File: "a/.gpg-id", Added: []string{"mallory"}, Removed: []string{"alice"}},
				{File: "b/.gpg-id", Added: []string{"mallory"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := crypto.DiffRecipientSets(tt.before, tt.after)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestAgePluginBinary checks that a recipient which makes age exec a plugin
// is recognised as such, and that an ordinary one is not.
func TestAgePluginBinary(t *testing.T) {
	_, native := newIdentity(t)
	yubikey := plugin.EncodeRecipient("yubikey", []byte{1, 2, 3, 4})

	tests := []struct {
		name      string
		recipient string
		want      string
	}{
		{name: "native age recipient", recipient: native.String()},
		{name: "ssh recipient", recipient: "ssh-ed25519 AAAA user@host"},
		{name: "nonsense", recipient: "age1not-a-recipient"},
		{name: "plugin recipient", recipient: yubikey, want: "age-plugin-yubikey"},
		{name: "plugin recipient with whitespace", recipient: " " + yubikey + " ", want: "age-plugin-yubikey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, crypto.AgePluginBinary(tt.recipient))
		})
	}
}

// TestRecipientStrings checks the normalisation the record relies on: a file
// whose lines were reordered or repeated must not look like a change.
func TestRecipientStrings(t *testing.T) {
	got := crypto.RecipientStrings([]crypto.Recipient{"bob", "alice", "bob"})
	assert.Equal(t, []string{"alice", "bob"}, got)
}
