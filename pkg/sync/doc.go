// Package sync implements the binpass synchronisation engine.
//
// The engine compares local and remote store snapshots against a shared base
// state and produces a list of sync actions: push, pull, conflict, or no-op.
// It uses version vectors (§8.1) to determine causal ordering and resolves
// conflicts according to the decision table in §8.5 of the architecture
// document.
//
// # Ciphertext-first design
//
// The engine operates on ciphertext hashes (blake3) and file metadata. It does
// not need to decrypt anything except for one special case: HOTP counter
// auto-merge (§8.5). The [Opener] interface provides decryption capability
// only for that case.
//
// # Conflict resolution
//
// When version vectors diverge and ciphertexts differ, the default is to
// preserve both copies. The remote version keeps its original path; the local
// version is saved as a conflict file:
//
//	github.com/alice.gpg                                   ← remote
//	github.com/alice.conflict-thinkpad-20260808T142233.gpg  ← local
//
// Conflict files are encrypted with the same recipients as the original (§10).
// No field-level auto-merge is performed: the risk of assembling a
// Frankenstein secret with a username from one version and a password from
// another is too high.
package sync
