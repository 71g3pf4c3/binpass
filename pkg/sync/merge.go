package sync

import (
	"fmt"
	"sort"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/71g3pf4c3/binpass/pkg/secret"
)

// ActionKind classifies the outcome of merging a single file.
type ActionKind string

const (
	// ActionNone means the file is already in sync; no work is needed.
	ActionNone ActionKind = "none"
	// ActionPush means the local version is newer and should be uploaded.
	ActionPush ActionKind = "push"
	// ActionPull means the remote version is newer and should be downloaded.
	ActionPull ActionKind = "pull"
	// ActionConflict means the local and remote versions have diverged and
	// both must be preserved. The remote version keeps the original path;
	// the local version is saved as a conflict file.
	ActionConflict ActionKind = "conflict"
	// ActionDelete means the file has been deleted on both sides (or should
	// be deleted on the side that still has it) and can be removed from the
	// base state.
	ActionDelete ActionKind = "delete"
	// ActionMergeHOTP means the only difference is the HOTP counter, which
	// can be auto-merged by taking the maximum. The merged counter is in
	// Action.MergedCounter.
	ActionMergeHOTP ActionKind = "merge_hotp"
)

// Action is the merge engine's decision for a single file path.
type Action struct {
	// Path is the store-relative path of the file.
	Path string
	// Kind is the action to take.
	Kind ActionKind
	// Reason is a human-readable explanation of why this action was chosen.
	Reason string
	// Local is the local file state, or nil if the file does not exist
	// locally.
	Local *FileState
	// Remote is the remote file state, or nil if the file does not exist
	// remotely.
	Remote *FileState
	// Base is the base file state from the last successful sync, or nil if
	// the file was not present in the base.
	Base *FileState
	// MergedVersion is the version vector to store after the action is
	// applied. For ActionNone with VV merge, it is the merged VV. For
	// ActionMergeHOTP, it is the merged VV with the winning counter.
	MergedVersion VersionVector
	// MergedCounter is the auto-merged HOTP counter (ActionMergeHOTP only).
	MergedCounter uint64
}

// Merge compares the local and remote snapshots against the shared base state
// and returns the actions needed to bring them in sync. The result is sorted
// by path for deterministic output.
//
// Decision table (§8.5)
//
// | Situation                       | Action         |
// |---------------------------------|----------------|
// | VV equal                        | none           |
// | Local dominates                 | push           |
// | Remote dominates                | pull           |
// | Diverge                         | conflict       |
// | Diverge, ciphertexts identical  | merge VV, none |
// | Diverge, both have HOTP         | auto-merge     |
// | Delete vs edit                  | edit wins      |
//
// # Delete vs edit
//
// If one side deleted the file (not present but was in base) and the other
// modified it, the edit wins: the file is restored on the deleting side.
// This matches the spec (§8.5): "побеждает edit + warning".
func Merge(local, remote, base Snapshot, opener Opener) []Action {
	// Collect all paths from all three snapshots.
	paths := make(map[string]struct{})
	for p := range local {
		paths[p] = struct{}{}
	}
	for p := range remote {
		paths[p] = struct{}{}
	}
	for p := range base {
		paths[p] = struct{}{}
	}

	var actions []Action
	for p := range paths {
		actions = append(actions, mergeFile(p, local[p], remote[p], base[p], opener))
	}

	// Sort by path for deterministic output.
	sort.Slice(actions, func(i, j int) bool {
		return actions[i].Path < actions[j].Path
	})
	return actions
}

// mergeFile classifies the relationship between the local, remote, and base
// versions of a single file and returns the appropriate action.
func mergeFile(path string, local, remote, base *FileState, opener Opener) Action {
	a := Action{Path: path, Local: local, Remote: remote, Base: base}

	// All three exist: compare version vectors.
	if local != nil && remote != nil && base != nil {
		return mergeExisting(a, local, remote, base, opener)
	}

	// New local file: push to remote.
	if local != nil && remote == nil && base == nil {
		a.Kind = ActionPush
		a.Reason = "new local file"
		a.MergedVersion = local.Version.Clone()
		return a
	}

	// New remote file: pull to local.
	if local == nil && remote != nil && base == nil {
		a.Kind = ActionPull
		a.Reason = "new remote file"
		a.MergedVersion = remote.Version.Clone()
		return a
	}

	// Local delete, remote unchanged: confirm delete.
	if local == nil && remote != nil && base != nil {
		if remote.Version.Equal(base.Version) {
			a.Kind = ActionDelete
			a.Reason = "deleted locally, remote unchanged"
			return a
		}
		// Delete vs edit: remote edited, edit wins.
		a.Kind = ActionPull
		a.Reason = "delete-vs-edit: remote edit wins, restoring locally"
		a.MergedVersion = remote.Version.Clone()
		return a
	}

	// Remote delete, local unchanged: confirm delete.
	if local != nil && remote == nil && base != nil {
		if local.Version.Equal(base.Version) {
			a.Kind = ActionDelete
			a.Reason = "deleted remotely, local unchanged"
			return a
		}
		// Delete vs edit: local edited, edit wins.
		a.Kind = ActionPush
		a.Reason = "delete-vs-edit: local edit wins, restoring on remote"
		a.MergedVersion = local.Version.Clone()
		return a
	}

	// Both deleted: clean up base.
	if local == nil && remote == nil && base != nil {
		a.Kind = ActionDelete
		a.Reason = "deleted on both sides"
		return a
	}

	// Should not happen (local and remote exist without base, or base exists
	// alone). If it does, treat the file as needing sync.
	if local != nil {
		a.Kind = ActionPush
		a.Reason = "orphan local file, no base"
		a.MergedVersion = local.Version.Clone()
		return a
	}
	if remote != nil {
		a.Kind = ActionPull
		a.Reason = "orphan remote file, no base"
		a.MergedVersion = remote.Version.Clone()
		return a
	}

	a.Kind = ActionDelete
	a.Reason = "stale base entry"
	return a
}

// mergeExisting handles the case where a file exists in all three snapshots.
func mergeExisting(a Action, local, remote, base *FileState, opener Opener) Action {
	// VVs equal: already in sync.
	if local.Version.Equal(remote.Version) {
		a.Kind = ActionNone
		a.Reason = "version vectors equal"
		a.MergedVersion = local.Version.Clone()
		return a
	}

	// Local dominates: push.
	if local.Version.Dominates(remote.Version) {
		a.Kind = ActionPush
		a.Reason = "local version dominates"
		a.MergedVersion = local.Version.Clone()
		return a
	}

	// Remote dominates: pull.
	if remote.Version.Dominates(local.Version) {
		a.Kind = ActionPull
		a.Reason = "remote version dominates"
		a.MergedVersion = remote.Version.Clone()
		return a
	}

	// VVs diverge. Check for special cases before declaring a conflict.

	// Special case 1: ciphertexts are identical despite divergent VVs.
	// This can happen when the same file is synced through two different
	// paths, or when a sync was interrupted before VVs were updated.
	if local.Hash == remote.Hash {
		a.Kind = ActionNone
		a.Reason = "divergent VVs but identical ciphertexts"
		a.MergedVersion = local.Version.Merge(remote.Version)
		return a
	}

	// Special case 2: HOTP counter auto-merge.
	if opener != nil {
		if resolved, ok := tryHOTPMerge(a, local, remote, opener); ok {
			return resolved
		}
	}

	// Default: conflict. Both copies are preserved.
	a.Kind = ActionConflict
	a.Reason = "version vectors diverge"
	a.MergedVersion = local.Version.Merge(remote.Version)
	return a
}

// tryHOTPMerge checks whether the only difference between the local and remote
// versions is the HOTP counter, and if so, returns an auto-merge action. It
// returns (action, true) if the merge was possible, or (zero, false) if not.
//
// This is the only place the sync engine reads plaintext (§8.5). The counter
// diverges on two devices as a normal consequence of generating codes
// independently; taking the maximum is always safe because counters only grow.
func tryHOTPMerge(a Action, local, remote *FileState, opener Opener) (Action, bool) {
	localSec, lErr := opener.Open(local.Path)
	if lErr != nil {
		return Action{}, false
	}
	remoteSec, rErr := opener.Open(remote.Path)
	if rErr != nil {
		return Action{}, false
	}

	localHOTP, localCounter, localOK := extractHOTP(localSec)
	remoteHOTP, remoteCounter, remoteOK := extractHOTP(remoteSec)
	if !localOK || !remoteOK {
		return Action{}, false
	}

	// Both have HOTP. Check if the counter is the only difference.
	// Replace the counter line in both secrets and compare the result.
	// If they are identical after normalising the counter, the only
	// difference IS the counter.
	localNormalised := normaliseCounter(localSec, localHOTP, remoteCounter)
	remoteNormalised := normaliseCounter(remoteSec, remoteHOTP, remoteCounter)
	if string(localNormalised) != string(remoteNormalised) {
		// Other fields differ too: not a HOTP-only diff.
		return Action{}, false
	}

	// Auto-merge: take max(counter).
	merged := max(localCounter, remoteCounter)
	a.Kind = ActionMergeHOTP
	a.Reason = fmt.Sprintf("HOTP counter auto-merge: local=%d remote=%d merged=%d",
		localCounter, remoteCounter, merged)
	a.MergedCounter = merged
	a.MergedVersion = local.Version.Merge(remote.Version)
	return a, true
}

// extractHOTP finds the first HOTP URI in the secret and returns the parsed
// config and its counter. It returns (config, counter, true) if found, or
// (nil, 0, false) if the secret has no HOTP entry.
func extractHOTP(sec *secret.Secret) (*otp.Config, uint64, bool) {
	uris := sec.OTPAll()
	for _, uri := range uris {
		cfg, err := otp.Parse(uri)
		if err != nil {
			continue
		}
		if cfg.Kind == otp.HOTP {
			return cfg, cfg.Counter, true
		}
	}
	return nil, 0, false
}

// normaliseCounter returns a copy of the secret with the HOTP counter replaced
// by targetCounter. This is used to check whether the counter is the only
// difference between two secrets.
func normaliseCounter(sec *secret.Secret, cfg *otp.Config, targetCounter uint64) []byte {
	// Build the old counter string and the new one.
	oldCounter := fmt.Sprintf("counter=%d", cfg.Counter)
	newCounter := fmt.Sprintf("counter=%d", targetCounter)
	// ReplaceLineContaining replaces the first occurrence of the old counter
	// parameter in the otpauth URI.
	replaced := sec.ReplaceLineContaining(oldCounter, newCounter)
	return replaced.Bytes()
}

// ConflictName builds the conflict file name for a local file that conflicts
// with the remote version. The remote version keeps the original path; the
// local version is renamed to include the device ID and a timestamp.
//
// Example: "github.com/alice.gpg" with device "thinkpad" at 2026-08-08T14:22:33
// becomes "github.com/alice.conflict-thinkpad-20260808T142233.gpg".
func ConflictName(path string, device DeviceID, timestamp string) string {
	// Find the extension: the last dot after the last slash. Without this,
	// "github.com/alice" would split on the dot in "github.com".
	slash := strings.LastIndex(path, "/")
	dot := strings.LastIndex(path, ".")
	if dot < 0 || dot < slash {
		return path + ".conflict-" + string(device) + "-" + timestamp
	}
	ext := path[dot:]
	base := path[:dot]
	return base + ".conflict-" + string(device) + "-" + timestamp + ext
}
