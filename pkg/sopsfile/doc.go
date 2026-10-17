// Package sopsfile edits sops-encrypted YAML and JSON documents through the
// sops binary and exposes their nested keys as a store-like tree.
//
// Nested maps are groups and a key is addressed as "group/sub/key", the same
// addressing sops-nix uses for nested secrets. All cryptography stays in
// sops: binpass never reads a master key, and secret values only ever cross
// the process boundary on stdin or stdout, never in argv.
//
// Changes to an existing file go through `sops set` and `sops unset`, which
// keep the file's data key, master keys and every untouched value as they
// were, so a version-controlled secrets file shows a diff for the changed
// key only. A file that does not exist yet is created from its first key via
// `sops encrypt`, which applies the project's .sops.yaml creation rules.
package sopsfile
