package remote

import (
	"path"
	"path/filepath"
)

// Names of the tomb containers, repeated here rather than imported from
// pkg/tomb.
//
// pkg/tomb already depends on the store, and a transport importing it would
// tie the sync engine to the tomb implementation for the sake of two string
// constants. They are part of the on-disk layout either way: a file called
// store.luks in a password store is a tomb container on every machine that
// reads it.
const (
	coffinFileName = "store.coffin.age"
	luksImageName  = "store.luks"
	luksKeyName    = "store.luks.key.age"
	bundleName     = "store.sparsebundle"
	bundleKeyName  = "store.sparsebundle.key.age"
)

// storeDotfiles are the dotfiles that belong to the store rather than to one
// machine, and so travel with it.
var storeDotfiles = map[string]bool{
	".gpg-id":         true,
	".age-recipients": true,
	".gitattributes":  true,
}

// tombContainers are the files a closed tomb leaves in the store.
//
// A closed LUKS or sparse bundle store is *only* these files: the entries
// are inside the container. Leaving them out of a listing, as the extension
// check alone did, meant syncing such a store uploaded the key and left the
// container behind — the key to a safe that never arrived, stored with the
// provider on its own.
var tombContainers = map[string]bool{
	coffinFileName: true,
	luksImageName:  true,
	luksKeyName:    true,
	bundleName:     true,
	bundleKeyName:  true,
}

// IsStoreContent reports whether a store-relative path is content that sync
// owns: an encrypted entry, a recipients file, or a tomb container.
//
// Every transport asks this rather than testing extensions itself. Six
// copies of "does it end in .gpg or .age" is how the tomb containers came to
// be omitted from three of them and included in none.
func IsStoreContent(p string) bool {
	if p == "" {
		return false
	}
	base := path.Base(filepath.ToSlash(p))

	if tombContainers[base] {
		return true
	}
	if storeDotfiles[base] {
		return true
	}
	// Any other dotfile is local state: .git, .gpg-id.sig, editor droppings.
	if base[0] == '.' {
		return false
	}
	switch filepath.Ext(base) {
	case ".gpg", ".age":
		return true
	}
	return false
}

// IsTombContainer reports whether a path is a tomb container or its key.
func IsTombContainer(p string) bool {
	return tombContainers[path.Base(filepath.ToSlash(p))]
}

// IsBlockContainer reports whether a path is a container holding a
// filesystem image rather than an encrypted archive.
//
// These are the ones a file-by-file transport cannot carry usefully: a LUKS
// image or a sparse bundle is one large opaque file that changes wholesale
// on every write, so a transport that stores each version separately grows
// without bound.
func IsBlockContainer(p string) bool {
	base := path.Base(filepath.ToSlash(p))
	return base == luksImageName || base == bundleName
}
