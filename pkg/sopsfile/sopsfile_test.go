package sopsfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// workspace builds an isolated sops project: a fresh age identity, a
// .sops.yaml encrypting everything to it, and an environment that keeps
// sops away from the developer's real keys. The test runs inside it so
// sops finds the config the way it does for a user.
func workspace(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "key.txt")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))
	cfg := fmt.Sprintf("creation_rules:\n  - age: %s\n", id.Recipient())
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(cfg), 0o600))

	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)
	for _, v := range []string{"SOPS_AGE_KEY", "SOPS_AGE_KEY_CMD", "SOPS_AGE_RECIPIENTS",
		"SOPS_PGP_FP", "SOPS_KMS_ARN", "SOPS_GCP_KMS_IDS", "SOPS_AZURE_KEYVAULT_URLS"} {
		t.Setenv(v, "")
		require.NoError(t, os.Unsetenv(v))
	}
	t.Chdir(dir)
	return dir
}

// decrypt reads path with sops itself, independently of the package under
// test, so assertions prove sops still understands what was written.
func decrypt(t *testing.T, path string) map[string]any {
	t.Helper()
	out, err := exec.Command("sops", "decrypt", "--output-type", "json", path).Output()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	return doc
}

func open(t *testing.T, name string) *File {
	t.Helper()
	f, err := Open(name)
	require.NoError(t, err)
	return f
}

func TestOpen_Extension(t *testing.T) {
	for _, name := range []string{"s.env", "s", "s.txt"} {
		_, err := Open(name)
		assert.ErrorIs(t, err, ErrUnsupported, name)
	}
}

func TestFile_CreateListGet(t *testing.T) {
	workspace(t)
	for _, format := range []string{"secrets.yaml", "secrets.json"} {
		t.Run(format, func(t *testing.T) {
			f := open(t, format)
			names, err := f.List("")
			require.NoError(t, err)
			assert.Empty(t, names, "missing file lists nothing")
			assert.False(t, f.Exists("token"))
			_, err = f.Get("token")
			assert.ErrorIs(t, err, store.ErrNotFound)

			require.NoError(t, f.Set("db/password", secret.New("x", "")))
			require.NoError(t, f.Set("token", secret.New("y", "")))
			require.NoError(t, f.Set("db/user", secret.New("admin", "")))

			names, err = f.List("")
			require.NoError(t, err)
			assert.Equal(t, []string{"db/password", "db/user", "token"}, names)
			names, err = f.List("db")
			require.NoError(t, err)
			assert.Equal(t, []string{"db/password", "db/user"}, names)

			sec, err := f.Get("db/password")
			require.NoError(t, err)
			assert.Equal(t, "x", sec.String())
			assert.True(t, f.IsDir("db"))
			assert.True(t, f.IsDir(""))
			assert.False(t, f.IsDir("token"))
			assert.True(t, f.Exists("token"))
			assert.False(t, f.Exists("db"))

			_, err = f.Get("db")
			assert.ErrorIs(t, err, ErrIsGroup)
			_, err = f.List("token")
			assert.ErrorIs(t, err, ErrIsKey)
			assert.ErrorIs(t, f.Set("token/sub", secret.New("z", "")), ErrIsKey)
			assert.ErrorIs(t, f.Set("db", secret.New("z", "")), ErrIsGroup)

			assert.Equal(t, map[string]any{
				"db":    map[string]any{"password": "x", "user": "admin"},
				"token": "y",
			}, decrypt(t, format))
		})
	}
}

func TestFile_NewlineRoundTrip(t *testing.T) {
	workspace(t)
	tests := []struct {
		name  string
		seed  string // existing value, "" for a new key
		input []byte
		want  string
	}{
		{"new single line drops terminator", "", []byte("tok\n"), "tok"},
		{"new single line without terminator", "", []byte("tok"), "tok"},
		{"new multi-line keeps terminator", "", []byte("l1\nl2\n"), "l1\nl2\n"},
		{"new multi-line without terminator", "", []byte("l1\nl2"), "l1\nl2"},
		{"edit keeps missing terminator", "old", []byte("new\n"), "new"},
		{"edit keeps present terminator", "old\n", []byte("new\n"), "new\n"},
		{"edit to multi-line keeps missing terminator", "old", []byte("l1\nl2\n"), "l1\nl2"},
		{"empty value", "", []byte("\n"), ""},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := fmt.Sprintf("k%d", i)
			if tt.seed != "" {
				// Seed through sops directly: Set would normalize the seed.
				rawSet(t, "s.yaml", `["`+key+`"]`, tt.seed)
			}
			f := open(t, "s.yaml")
			require.NoError(t, f.Set(key, secret.Parse(tt.input)))
			assert.Equal(t, tt.want, decrypt(t, "s.yaml")[key])
			got, err := f.Get(key)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestFile_RemoveMoveCopy(t *testing.T) {
	workspace(t)
	f := open(t, "s.yaml")
	require.NoError(t, f.Set("a/x", secret.New("1", "")))
	require.NoError(t, f.Set("a/y", secret.New("2", "")))
	require.NoError(t, f.Set("c", secret.New("3", "")))

	assert.ErrorIs(t, f.Remove("a"), ErrIsGroup)
	assert.ErrorIs(t, f.RemoveDir("c"), ErrIsKey)
	assert.ErrorIs(t, f.Remove("nope"), store.ErrNotFound)
	assert.ErrorIs(t, f.RemoveDir("nope"), store.ErrNotFound)

	require.NoError(t, f.Move("a/x", "b/x"))
	assert.False(t, f.Exists("a/x"))
	got, err := f.Get("b/x")
	require.NoError(t, err)
	assert.Equal(t, "1", got.String())

	assert.ErrorIs(t, f.Move("a/y", "b/x"), store.ErrExists)
	assert.ErrorIs(t, f.Copy("nope", "z"), store.ErrNotFound)

	require.NoError(t, f.Copy("c", "d"))
	require.NoError(t, f.Move("b", "e"))
	names, err := f.List("")
	require.NoError(t, err)
	assert.Equal(t, []string{"a/y", "c", "d", "e/x"}, names)

	require.NoError(t, f.Remove("c"))
	require.NoError(t, f.RemoveDir("e"))
	names, err = f.List("")
	require.NoError(t, err)
	assert.Equal(t, []string{"a/y", "d"}, names)
	assert.Equal(t, map[string]any{"a": map[string]any{"y": "2"}, "d": "3"}, decrypt(t, "s.yaml"))
}

func TestFile_MoveIntoItself(t *testing.T) {
	workspace(t)
	f := open(t, "s.yaml")
	require.NoError(t, f.Set("g/k", secret.New("1", "")))
	err := f.Move("g", "g/sub")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "into itself")
	assert.True(t, f.Exists("g/k"))
}

func TestFile_NonStringAndOddKeys(t *testing.T) {
	workspace(t)
	f := open(t, "s.yaml")
	require.NoError(t, f.Set("seed", secret.New("s", "")))
	for _, kv := range [][2]any{{`["n"]`, 5}, {`["b"]`, true}, {`["a/b"]`, "slash"}} {
		rawSet(t, "s.yaml", kv[0].(string), kv[1])
	}

	_, err := f.List("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"a/b"`)

	require.NoError(t, exec.Command("sops", "unset", "s.yaml", `["a/b"]`).Run())
	f = open(t, "s.yaml")
	names, err := f.List("")
	require.NoError(t, err)
	assert.Equal(t, []string{"b", "n", "seed"}, names)
	for name, want := range map[string]string{"n": "5", "b": "true"} {
		got, err := f.Get(name)
		require.NoError(t, err)
		assert.Equal(t, want, got.String(), name)
	}

	require.NoError(t, f.Set("n", secret.New("six", "")))
	assert.Equal(t, "six", decrypt(t, "s.yaml")["n"])

	require.NoError(t, f.Set(`qu"ote\key]`, secret.New("q", "")))
	assert.Equal(t, "q", decrypt(t, "s.yaml")[`qu"ote\key]`])
	require.NoError(t, f.Remove(`qu"ote\key]`))
	assert.Nil(t, decrypt(t, "s.yaml")[`qu"ote\key]`])
	require.NoError(t, f.Set("sp ace/ü", secret.New("u", "")))
	got, err := f.Get("sp ace/ü")
	require.NoError(t, err)
	assert.Equal(t, "u", got.String())

	err = f.Set("br[acket", secret.New("x", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'['")
}

// rawSet writes v at path with sops itself, bypassing the package's
// normalization. The value goes over stdin like the package does.
func rawSet(t *testing.T, file, path string, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	require.NoError(t, err)
	cmd := exec.Command("sops", "set", "--value-stdin", file, path)
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestFile_Grep(t *testing.T) {
	workspace(t)
	f := open(t, "s.json")
	require.NoError(t, f.Set("a", secret.Parse([]byte("hello\nworld\n"))))
	require.NoError(t, f.Set("g/b", secret.New("other", "")))
	matches, err := f.Grep("", func(l string) bool { return l == "world" })
	require.NoError(t, err)
	assert.Equal(t, []store.Match{{Name: "a", Lines: []string{"world"}}}, matches)
}

func TestFile_SopsErrorSurfaces(t *testing.T) {
	dir := workspace(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("not: sops\n"), 0o600))
	f := open(t, "bad.yaml")
	_, err := f.List("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sops decrypt")
	assert.False(t, errors.Is(err, store.ErrNotFound))
}

// The sops-nix layout: .sops.yaml sits next to the secrets, its path_regex
// is anchored to names relative to it, and `make` runs from the repo root.
// sops only searches for the config upward from its cwd, so creating,
// reading and writing must all work when the file is named by a
// subdirectory-relative path from a cwd that has no config of its own.
func TestFile_RelativePathFromParentDir(t *testing.T) {
	root := workspace(t)
	require.NoError(t, os.Remove(filepath.Join(root, ".sops.yaml")))
	dir := filepath.Join(root, "nixos", "secrets")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	key, err := os.ReadFile(os.Getenv("SOPS_AGE_KEY_FILE"))
	require.NoError(t, err)
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(key)))
	require.NoError(t, err)
	cfg := fmt.Sprintf("creation_rules:\n  - path_regex: ^secrets\\.ya?ml$\n    age: %s\n", id.Recipient())
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(cfg), 0o600))

	f := open(t, filepath.Join("nixos", "secrets", "secrets.yaml"))
	require.NoError(t, f.Set("net/corp/gateway", secret.New("vpn.example", "")))
	require.NoError(t, f.Set("hosts-extra", secret.Parse([]byte("10.0.0.5 nas\n10.0.0.6 printer\n"))))
	got, err := Open(filepath.Join("nixos", "secrets", "secrets.yaml"))
	require.NoError(t, err)
	sec, err := got.Get("hosts-extra")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5 nas\n10.0.0.6 printer\n", string(sec.Bytes()))
	require.NoError(t, got.Remove("net/corp/gateway"))
	doc := decrypt(t, filepath.Join(dir, "secrets.yaml"))
	assert.Equal(t, "10.0.0.5 nas\n10.0.0.6 printer\n", doc["hosts-extra"])
	_, err = got.Get("net/corp/gateway")
	assert.ErrorIs(t, err, store.ErrNotFound)
}
