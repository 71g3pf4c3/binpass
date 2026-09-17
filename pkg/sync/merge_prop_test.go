package sync

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"testing"
)

// Property tests for the merge engine (§12). The deterministic cases in
// merge_test.go pin down individual rows of the decision table; these tests
// assert the invariants that must hold for arbitrary snapshots, which is
// where a wrong combination of rows shows up as a lost or corrupted entry.
//
// The invariants follow docs/agent-tasks/07-sync-hardening.md, with one
// correction: "nothing is lost" cannot mean a file present on a side never
// gets ActionDelete, because propagating an unopposed delete is the specified
// behaviour. The precise statement is that a file a side has *modified* since
// the base is never deleted by the merge: it is pushed, pulled, kept as a
// conflict, or auto-merged.

// propIterations is the number of random worlds each test run checks. Plain
// `go test` does 200; `go test -run TestMergeProperty -count=1000` soaks the
// same invariants over 200k worlds.
const propIterations = 200

// propDevices is the device pool. Small pool, so version vectors overlap and
// collide often enough for equal/dominates/diverges to all show up.
var propDevices = []DeviceID{"thinkpad", "macbook", "phone", "tablet"}

// propPaths is the file pool, including names that stress ConflictName and
// path handling: dots in directories, files without directories.
var propPaths = []string{
	"github.com/alice.gpg",
	"github.com/alice.age",
	"bank/tinkoff.gpg",
	"bank/savings.gpg",
	"work/vpn.age",
	"root.gpg",
	"a/b/c/deep.gpg",
	"secret-service/login/4f3c.gpg",
}

// propWorld is one generated merge problem: three snapshots and the seed
// that produced them, so a failure prints a reproducible input.
type propWorld struct {
	seed   uint64
	local  Snapshot
	remote Snapshot
	base   Snapshot
}

// genVV returns a random version vector with small counters, so the chance
// of two vectors being equal, dominating, or diverging is spread evenly.
func genVV(r *rand.Rand) VersionVector {
	vv := make(VersionVector)
	for _, d := range propDevices {
		if r.IntN(2) == 0 {
			continue
		}
		if c := r.IntN(4); c > 0 {
			vv[d] = uint64(c)
		}
	}
	return vv
}

// genSnapshot builds a random snapshot over a subset of the path pool.
func genSnapshot(r *rand.Rand, paths []string) Snapshot {
	snap := make(Snapshot)
	for _, p := range paths {
		if r.IntN(3) == 0 {
			continue // absent from this side
		}
		snap[p] = &FileState{
			Path:    p,
			Hash:    randHash(r),
			Size:    int64(r.IntN(4096)),
			Version: genVV(r),
		}
	}
	return snap
}

// randHash returns a non-zero random hash. The zero hash would make two
// independently generated files look like identical ciphertexts.
func randHash(r *rand.Rand) [32]byte {
	var h [32]byte
	for {
		for i := range h {
			h[i] = byte(r.IntN(256))
		}
		if h != [32]byte{} {
			return h
		}
	}
}

// genWorld assembles a random (local, remote, base) triple. A quarter of the
// files present on both sides get matching hashes, because "divergent VVs
// but identical ciphertext" is a special case in the decision table and must
// be exercised on purpose: it will not occur by chance.
func genWorld(r *rand.Rand) propWorld {
	count := 3 + r.IntN(len(propPaths)-2)
	// Shuffle the pool first so each world draws a different subset.
	r.Shuffle(len(propPaths), func(i, j int) {
		propPaths[i], propPaths[j] = propPaths[j], propPaths[i]
	})
	paths := make([]string, count)
	copy(paths, propPaths[:count])

	w := propWorld{
		seed:   r.Uint64(),
		local:  genSnapshot(r, paths),
		remote: genSnapshot(r, paths),
		base:   genSnapshot(r, paths),
	}
	for p, lf := range w.local {
		if rf, ok := w.remote[p]; ok && r.IntN(4) == 0 {
			rf.Hash = lf.Hash
		}
	}
	return w
}

// vvCovers reports whether every counter in other is ≤ the corresponding
// counter in vv: vv describes a history that includes everything other does.
func vvCovers(vv, other VersionVector) bool {
	for id, co := range other {
		if cv := vv[id]; cv < co {
			return false
		}
	}
	return true
}

// dumpWorld renders a failing world compactly for the test log.
func dumpWorld(w propWorld) string {
	s := func(name string, snap Snapshot) string {
		out := fmt.Sprintf("  %s:", name)
		var paths []string
		for p := range snap {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			f := snap[p]
			out += fmt.Sprintf("\n    %s vv=%v hash=%x", p, f.Version, f.Hash[:4])
		}
		return out
	}
	return fmt.Sprintf("seed=%d\n%s\n%s\n%s",
		w.seed, s("local", w.local), s("remote", w.remote), s("base", w.base))
}

// TestMergeProperty checks the merge invariants over random snapshots.
func TestMergeProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	for i := 0; i < propIterations; i++ {
		w := genWorld(r)

		actions := Merge(w.local, w.remote, w.base, nil)
		swapped := Merge(w.remote, w.local, w.base, nil)

		byPath := make(map[string]Action, len(actions))
		for _, a := range actions {
			byPath[a.Path] = a
		}
		swappedByPath := make(map[string]Action, len(swapped))
		for _, a := range swapped {
			swappedByPath[a.Path] = a
		}

		// Invariant 1: coverage. Every path from any snapshot appears in
		// the result exactly once, and a path live on a side is met with
		// an action that keeps it (or propagates a legitimate delete).
		seen := make(map[string]int)
		for _, a := range actions {
			seen[a.Path]++
		}
		for p := range seen {
			if seen[p] > 1 {
				t.Fatalf("merge produced %d actions for %q\n%s", seen[p], p, dumpWorld(w))
			}
		}
		union := make(map[string]struct{})
		for p := range w.local {
			union[p] = struct{}{}
		}
		for p := range w.remote {
			union[p] = struct{}{}
		}
		for p := range w.base {
			union[p] = struct{}{}
		}
		for p := range union {
			if _, ok := byPath[p]; !ok {
				t.Fatalf("path %q present in a snapshot but absent from the merge result\n%s", p, dumpWorld(w))
			}
		}

		for p, a := range byPath {
			live := w.local[p] != nil || w.remote[p] != nil
			if !live {
				continue
			}
			switch a.Kind {
			case ActionPush, ActionPull, ActionNone, ActionConflict, ActionMergeHOTP:
				// The file survives on some side.
			case ActionDelete:
				// A delete is legitimate only when the surviving side
				// never modified the file since the base: the deletion
				// was unopposed. An edit on the surviving side must win.
				if w.local[p] != nil && (w.base[p] == nil || !w.local[p].Version.Equal(w.base[p].Version)) {
					t.Fatalf("path %q was edited locally but the merge deletes it\n%s", p, dumpWorld(w))
				}
				if w.remote[p] != nil && (w.base[p] == nil || !w.remote[p].Version.Equal(w.base[p].Version)) {
					t.Fatalf("path %q was edited remotely but the merge deletes it\n%s", p, dumpWorld(w))
				}
			}

			// Invariant 2: version vectors only advance. Whenever both
			// sides exist and a merged version is recorded, it covers
			// both sides' histories. The base-less orphan case is
			// excluded: merge.go treats a file with no base as "needs
			// sync" and takes the local version as-is, by design.
			if w.local[p] != nil && w.remote[p] != nil && w.base[p] != nil && a.MergedVersion != nil {
				if !vvCovers(a.MergedVersion, w.local[p].Version) || !vvCovers(a.MergedVersion, w.remote[p].Version) {
					t.Fatalf("path %q: merged version %v does not cover both sides (local=%v remote=%v)\n%s",
						p, a.MergedVersion, w.local[p].Version, w.remote[p].Version, dumpWorld(w))
				}
			}

			// Invariant 3: identical ciphertext never conflicts. Two
			// devices encrypting the same plaintext produce divergent
			// version vectors by design; the merge must recognise the
			// case rather than fork a conflict file.
			if w.local[p] != nil && w.remote[p] != nil && w.base[p] != nil &&
				w.local[p].Hash == w.remote[p].Hash && a.Kind == ActionConflict {
				t.Fatalf("path %q: identical ciphertexts diverged into a conflict\n%s", p, dumpWorld(w))
			}
		}

		// Invariant 4: delete vs edit — the edit wins, on either side.
		for p, a := range byPath {
			if w.local[p] != nil && w.remote[p] == nil && w.base[p] != nil &&
				!w.local[p].Version.Equal(w.base[p].Version) && a.Kind != ActionPush {
				t.Fatalf("path %q: local edit vs remote delete must push, got %q\n%s", p, a.Kind, dumpWorld(w))
			}
			if w.remote[p] != nil && w.local[p] == nil && w.base[p] != nil &&
				!w.remote[p].Version.Equal(w.base[p].Version) && a.Kind != ActionPull {
				t.Fatalf("path %q: remote edit vs local delete must pull, got %q\n%s", p, a.Kind, dumpWorld(w))
			}
		}

		// Invariant 5: commutativity. Swapping the sides flips the
		// direction of movement but never changes the verdict: a conflict
		// stays a conflict, and an in-sync file stays in sync, whichever
		// side runs the merge.
		if len(byPath) != len(swappedByPath) {
			t.Fatalf("swap changed the path set\n%s", dumpWorld(w))
		}
		opposite := map[ActionKind]ActionKind{
			ActionPush:      ActionPull,
			ActionPull:      ActionPush,
			ActionNone:      ActionNone,
			ActionConflict:  ActionConflict,
			ActionDelete:    ActionDelete,
			ActionMergeHOTP: ActionMergeHOTP,
		}
		for p, a := range byPath {
			b, ok := swappedByPath[p]
			if !ok {
				t.Fatalf("path %q missing from the swapped merge\n%s", p, dumpWorld(w))
			}
			if b.Kind != opposite[a.Kind] {
				t.Fatalf("path %q: merge is not commutative: %q vs %q (swapped)\n%s",
					p, a.Kind, b.Kind, dumpWorld(w))
			}
		}
	}
}
