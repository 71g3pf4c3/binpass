package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShowDecryptMismatchNamesTriedIdentities reproduces the wrong-key
// situation end to end: the store is encrypted for identity A while the
// resolver is pointed at identity B. The error the user sees must say which
// identity file was tried and where the entry's recipients live, because
// age's own "incorrect identity for recipient block" turns a stale
// .age-recipients or a key migration into guesswork.
func TestShowDecryptMismatchNamesTriedIdentities(t *testing.T) {
	encryptor, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	wrong, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"),
		[]byte(encryptor.Recipient().String()+"\n"), 0o600))
	// The key file lives in a second temp dir: nothing here may touch the
	// developer's real identity locations.
	wrongPath := filepath.Join(t.TempDir(), "identities.age")
	require.NoError(t, os.WriteFile(wrongPath, []byte(wrong.String()+"\n"), 0o600))

	cfg := config.Default()
	cfg.Dir = dir
	cfg.Identity = wrongPath
	app := NewApp(cfg)
	app.Out, app.Err = &bytes.Buffer{}, &bytes.Buffer{}

	s, err := app.Store()
	require.NoError(t, err)
	require.NoError(t, s.Set("bank/tinkoff", secret.Parse([]byte("hunter2\n"))))

	err = app.runShow(context.Background(), showOpts{name: "bank/tinkoff"})
	require.Error(t, err)
	assert.ErrorContains(t, err, wrongPath,
		"the error must name the identity file that was tried")
	assert.ErrorContains(t, err, ".age-recipients",
		"the error must point at where the entry's recipients live")
	// Decorating must not break matching on the underlying failure, and no
	// key material may reach the message.
	assert.ErrorIs(t, err, age.ErrIncorrectIdentity)
	assert.NotContains(t, err.Error(), wrong.String())
	assert.NotContains(t, err.Error(), encryptor.String())
}

// TestDecryptHintLeavesOtherErrorsAlone pins the guard: only the
// recipient-mismatch failure is decorated, and only when identity files were
// actually recorded. Everything else passes through untouched, so GPG and
// age failures other than a mismatch keep their own diagnostics.
func TestDecryptHintLeavesOtherErrorsAlone(t *testing.T) {
	plain := errors.New("store: truncated entry")
	mismatch := age.ErrIncorrectIdentity

	a := &App{}
	assert.Same(t, plain, a.decryptHint(plain),
		"a non-mismatch error must come back untouched")
	assert.Same(t, mismatch, a.decryptHint(mismatch),
		"a mismatch with no recorded identity files has nothing to add")

	a.identityFiles = []string{"/keys/identities.age"}
	assert.Same(t, plain, a.decryptHint(plain),
		"recorded files must not widen the decoration to other errors")
}
