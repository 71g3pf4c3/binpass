package remote_test

import (
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/remote"
	"github.com/stretchr/testify/assert"
)

// TestTombContainersAreStoreContent is the regression that matters. Sync
// filtered files by a .gpg or .age extension, which store.luks and
// store.sparsebundle do not have — while their key files do. Syncing a
// closed LUKS store therefore uploaded the key and left the container
// behind: the key to a safe that never arrived, sitting on the provider by
// itself.
func TestTombContainersAreStoreContent(t *testing.T) {
	for _, name := range []string{
		"store.coffin.age",
		"store.luks",
		"store.luks.key.age",
		"store.sparsebundle",
		"store.sparsebundle.key.age",
	} {
		assert.True(t, remote.IsStoreContent(name),
			"%s is what a closed tomb leaves in the store; without it the store syncs as empty", name)
		assert.True(t, remote.IsTombContainer(name))
	}
}

func TestOrdinaryEntriesAreStoreContent(t *testing.T) {
	for _, name := range []string{
		"alice.age",
		"github.com/alice.gpg",
		"work/vpn.age",
		"a/b/c/deep.gpg",
		"name with spaces.age",
	} {
		assert.True(t, remote.IsStoreContent(name), "%s is an entry", name)
		assert.False(t, remote.IsTombContainer(name))
	}
}

func TestRecipientsFilesTravelWithTheStore(t *testing.T) {
	// These are setup rather than entries, but a store arriving without
	// them cannot encrypt anything, so they belong in the listing.
	for _, name := range []string{".gpg-id", ".age-recipients", ".gitattributes"} {
		assert.True(t, remote.IsStoreContent(name), "%s must travel with the store", name)
	}
}

func TestLocalStateIsNotStoreContent(t *testing.T) {
	for _, name := range []string{
		".git/config",
		".gitignore",
		"state.db",
		"notes.txt",
		"README.md",
		"entry.age.tmp",
		"",
		".hidden",
		"backup.age.bak",
	} {
		assert.False(t, remote.IsStoreContent(name),
			"%s is local state or not an entry; syncing it would put machine-specific files in the store", name)
	}
}

// TestBlockContainersAreIdentified: a LUKS image or a sparse bundle is one
// large opaque file that changes wholesale on every write. A transport that
// keeps every version of it grows without bound, so the CLI warns rather
// than letting a 1 GB image become a git repository.
func TestBlockContainersAreIdentified(t *testing.T) {
	assert.True(t, remote.IsBlockContainer("store.luks"))
	assert.True(t, remote.IsBlockContainer("store.sparsebundle"))

	// The coffin grows with its contents and is rewritten as a unit, which
	// git handles the same way it handles any binary file.
	assert.False(t, remote.IsBlockContainer("store.coffin.age"))
	// The key files are small and change only when the container is made.
	assert.False(t, remote.IsBlockContainer("store.luks.key.age"))
	assert.False(t, remote.IsBlockContainer("store.sparsebundle.key.age"))
	assert.False(t, remote.IsBlockContainer("alice.age"))
}

func TestStoreContentIgnoresTheDirectoryItIsIn(t *testing.T) {
	// A container is recognised by name wherever it appears: a store
	// synchronised into a subdirectory is still a store.
	assert.True(t, remote.IsStoreContent("sub/store.luks"))
	assert.True(t, remote.IsTombContainer("sub/store.luks"))
	assert.True(t, remote.IsBlockContainer("sub/store.sparsebundle"))
}
