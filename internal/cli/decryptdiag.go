package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
)

// ageDiagnostics decorates the age backend so that a recipient-mismatch
// failure names the identity files that were tried. age's own error for this
// case says only "incorrect identity for recipient block": it names neither
// the identities nor the recipients file, which makes a wrong-key or stale
// .age-recipients situation guesswork to debug.
//
// It wraps the backend at App wiring rather than living inside crypto.Age,
// because the provenance (which files the resolver loaded) is known here,
// and pkg/crypto should not have to know where its keys came from.
type ageDiagnostics struct {
	crypto.Crypto
	app *App
}

// Decrypt decrypts through the wrapped backend, adding provenance to
// recipient-mismatch failures.
func (d ageDiagnostics) Decrypt(r io.Reader) ([]byte, error) {
	plaintext, err := d.Crypto.Decrypt(r)
	if err != nil {
		return nil, d.app.decryptHint(err)
	}
	return plaintext, nil
}

// decryptHint appends the identity provenance to err when err is age's
// recipient-mismatch failure. File paths are not secrets and are safe to
// show; key material never reaches the message.
func (a *App) decryptHint(err error) error {
	files := a.triedIdentityFiles()
	if !errors.Is(err, age.ErrIncorrectIdentity) || len(files) == 0 {
		return err
	}
	var sb strings.Builder
	sb.WriteString("none of the age identities loaded from:\n")
	for _, p := range files {
		sb.WriteString("  ")
		sb.WriteString(p)
		sb.WriteString("\n")
	}
	sb.WriteString("matched this entry's recipients, which live in the .age-recipients file next to the entry (or in the nearest directory above it).\n")
	sb.WriteString("Point binpass at the matching key with --identity or BINPASS_IDENTITY.")
	return fmt.Errorf("%w\n%s", err, sb.String())
}
