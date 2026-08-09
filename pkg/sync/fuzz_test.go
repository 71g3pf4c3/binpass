package sync_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/stretchr/testify/require"
)

// FuzzConflictName asserts that naming a conflict cannot move an entry out of
// the store. The name is built from a remote-supplied path and joined onto the
// store root before the local copy is written there.
func FuzzConflictName(f *testing.F) {
	seeds := []struct {
		path      string
		device    string
		timestamp string
	}{
		{"github.com/alice.gpg", "thinkpad", "20260808T142233"},
		{"alice.age", "phone", "20260808T142233"},
		{"no-extension", "dev", "20260808T142233"},
		{"github.com/alice", "dev", "20260808T142233"},
		{".hidden.age", "dev", "20260808T142233"},
		{"a/b/c.age", "../escape", "20260808T142233"},
		{"a.age", "dev/../..", "t"},
		{"", "", ""},
	}
	for _, s := range seeds {
		f.Add(s.path, s.device, s.timestamp)
	}

	root := filepath.Clean("/store")
	f.Fuzz(func(t *testing.T, path, device, timestamp string) {
		// Only paths that already passed validation reach ConflictName.
		if strings.ContainsAny(path, "\x00") || strings.HasPrefix(path, "/") {
			return
		}
		cleanJoined := filepath.Clean(filepath.Join(root, path))
		if cleanJoined != root && !strings.HasPrefix(cleanJoined, root+string(filepath.Separator)) {
			return
		}
		// A device ID is derived from the local hostname, so it carries no
		// separators; anything else is out of scope.
		if strings.ContainsAny(device, `/\`+"\x00") {
			return
		}

		name := sync.ConflictName(path, sync.DeviceID(device), timestamp)
		joined := filepath.Clean(filepath.Join(root, name))
		require.True(t,
			joined == root || strings.HasPrefix(joined, root+string(filepath.Separator)),
			"ConflictName(%q, %q, %q) = %q escapes to %q", path, device, timestamp, name, joined)
	})
}

// FuzzVersionVectorJSON asserts that a version vector survives a round trip
// through JSON. State arrives from state.db and, for some transports, from the
// other machine; a vector that changed under serialisation would silently
// rewrite the causal history the merge engine reasons about.
func FuzzVersionVectorJSON(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"thinkpad":1}`,
		`{"thinkpad":1,"phone":2}`,
		`{"":0}`,
		`{"a":18446744073709551615}`,
		`null`,
		`[]`,
		`{"a":-1}`,
		`{"a":1.5}`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		var vv sync.VersionVector
		if err := json.Unmarshal([]byte(in), &vv); err != nil {
			return
		}
		encoded, err := json.Marshal(vv)
		require.NoError(t, err, "a vector that parsed must serialise")

		var again sync.VersionVector
		require.NoError(t, json.Unmarshal(encoded, &again), "re-reading our own output must work")
		require.True(t, vv.Equal(again), "round trip changed %q: %v vs %v", in, vv, again)
	})
}
