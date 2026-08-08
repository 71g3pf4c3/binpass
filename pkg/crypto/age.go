package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
)

// AgeRecipientsFile is the file listing age recipients, as used by passage.
const AgeRecipientsFile = ".age-recipients"

// AgeExt is the extension of age-encrypted entries.
const AgeExt = ".age"

// Age encrypts entries with age. Identities are resolved lazily so that a
// store can be listed and written to without unlocking anything.
type Age struct {
	// root is the store directory recipient lookups are confined to.
	root string
	// identities supplies decryption keys on demand.
	identities IdentityFunc
}

// IdentityFunc returns the identities to attempt decryption with. It is called
// only when a decryption actually happens, so that hardware tokens are not
// touched during read-only operations.
type IdentityFunc func() ([]age.Identity, error)

// NewAge returns an age backend rooted at the store directory. ids may be nil
// for encrypt-only use.
func NewAge(root string, ids IdentityFunc) *Age {
	return &Age{root: root, identities: ids}
}

// Ext returns ".age".
func (a *Age) Ext() string { return AgeExt }

// RecipientsFile returns ".age-recipients".
func (a *Age) RecipientsFile() string { return AgeRecipientsFile }

// Available always succeeds: age is compiled in.
func (a *Age) Available() error { return nil }

// ParseRecipients reads the nearest .age-recipients governing dir.
func (a *Age) ParseRecipients(dir string) ([]Recipient, error) {
	path, err := findRecipientsFile(a.root, dir, AgeRecipientsFile)
	if err != nil {
		return nil, err
	}
	return readRecipientsFile(path)
}

// Encrypt writes an age ciphertext for plaintext to w.
func (a *Age) Encrypt(w io.Writer, plaintext []byte, rcp []Recipient) error {
	recipients, err := ParseAgeRecipients(rcp)
	if err != nil {
		return err
	}
	wc, err := age.Encrypt(w, recipients...)
	if err != nil {
		return fmt.Errorf("crypto: age encrypt: %w", err)
	}
	if _, err := wc.Write(plaintext); err != nil {
		_ = wc.Close()
		return fmt.Errorf("crypto: age encrypt: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("crypto: age encrypt: %w", err)
	}
	return nil
}

// Decrypt reads an age ciphertext from r and returns its plaintext.
func (a *Age) Decrypt(r io.Reader) ([]byte, error) {
	if a.identities == nil {
		return nil, ErrNoIdentity
	}
	ids, err := a.identities()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, ErrNoIdentity
	}
	dr, err := age.Decrypt(r, ids...)
	if err != nil {
		return nil, fmt.Errorf("crypto: age decrypt: %w", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, dr); err != nil {
		return nil, fmt.Errorf("crypto: age decrypt: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseAgeRecipients converts recipient strings into age recipients. Both
// native age (age1...) and SSH public keys are accepted.
func ParseAgeRecipients(rcp []Recipient) ([]age.Recipient, error) {
	if len(rcp) == 0 {
		return nil, ErrNoRecipients
	}
	out := make([]age.Recipient, 0, len(rcp))
	for _, r := range rcp {
		parsed, err := ParseAgeRecipient(r.String())
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, nil
}

// ParseAgeRecipient parses one recipient string: a native age recipient, an
// age plugin recipient (age1<plugin>1...), or an SSH public key.
func ParseAgeRecipient(s string) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "ssh-"):
		r, err := agessh.ParseRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("crypto: %w", err)
		}
		return r, nil
	case strings.HasPrefix(s, "age1"):
		if r, err := age.ParseX25519Recipient(s); err == nil {
			return r, nil
		}
		// Not a native recipient: hand it to the matching age plugin binary.
		r, err := plugin.NewRecipient(s, pluginUI())
		if err != nil {
			return nil, fmt.Errorf("crypto: %w", err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf("crypto: unrecognised age recipient %q", s)
	}
}
