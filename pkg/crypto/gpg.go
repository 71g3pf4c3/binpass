package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// GPGRecipientsFile is the file listing GPG recipients, as used by pass.
const GPGRecipientsFile = ".gpg-id"

// GPGExt is the extension of GPG-encrypted entries.
const GPGExt = ".gpg"

// GPG encrypts entries by driving the external gpg binary.
//
// Shelling out rather than using a Go OpenPGP implementation is deliberate: it
// is what makes smartcards, gpg-agent, pinentry and the user's existing
// keyrings work, and it produces ciphertext pass can read unchanged.
type GPG struct {
	// root is the store directory recipient lookups are confined to.
	root string
	// binary is the gpg executable, "gpg" unless overridden.
	binary string
	// opts are extra flags from PASSWORD_STORE_GPG_OPTS.
	opts []string
}

// NewGPG returns a GPG backend rooted at the store directory. binary may be
// empty to use "gpg" (falling back to "gpg2").
func NewGPG(root, binary string, opts []string) *GPG {
	return &GPG{root: root, binary: binary, opts: opts}
}

// Ext returns ".gpg".
func (g *GPG) Ext() string { return GPGExt }

// RecipientsFile returns ".gpg-id".
func (g *GPG) RecipientsFile() string { return GPGRecipientsFile }

// Available reports whether a usable gpg binary is on PATH.
func (g *GPG) Available() error {
	_, _, err := g.resolve()
	return err
}

// resolve returns the path and invocation name of the gpg executable. Like
// pass, gpg2 is preferred when present, because its presence also decides
// whether --batch --use-agent is passed.
func (g *GPG) resolve() (path, name string, err error) {
	if g.binary != "" {
		p, err := exec.LookPath(g.binary)
		if err != nil {
			return "", "", fmt.Errorf("crypto: %q not found on PATH: %w", g.binary, err)
		}
		return p, g.binary, nil
	}
	for _, name := range []string{"gpg2", "gpg"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, name, nil
		}
	}
	return "", "", fmt.Errorf("crypto: gpg not found on PATH: %w", exec.ErrNotFound)
}

// ParseRecipients reads the nearest .gpg-id governing dir.
func (g *GPG) ParseRecipients(dir string) ([]Recipient, error) {
	path, err := findRecipientsFile(g.root, dir, GPGRecipientsFile)
	if err != nil {
		return nil, err
	}
	return readRecipientsFile(path)
}

// baseArgs mirrors pass's own GPG_OPTS, including the conditional
// --batch --use-agent: passing --batch unconditionally would suppress pinentry
// on setups where pass still prompts. PASSWORD_STORE_GPG_OPTS comes first,
// exactly as in pass.
func (g *GPG) baseArgs(name string) []string {
	args := append([]string{}, g.opts...)
	args = append(args, "--quiet", "--yes", "--compress-algo=none", "--no-encrypt-to")
	if os.Getenv("GPG_AGENT_INFO") != "" || name == "gpg2" {
		args = append(args, "--batch", "--use-agent")
	}
	return args
}

// Encrypt writes a binary OpenPGP ciphertext for plaintext to w.
func (g *GPG) Encrypt(w io.Writer, plaintext []byte, rcp []Recipient) error {
	if len(rcp) == 0 {
		return ErrNoRecipients
	}
	bin, name, err := g.resolve()
	if err != nil {
		return err
	}
	args := g.baseArgs(name)
	for _, r := range rcp {
		args = append(args, "--recipient", r.String())
	}
	args = append(args, "--encrypt", "--output", "-")

	out, err := g.run(bin, args, plaintext)
	if err != nil {
		return fmt.Errorf("crypto: gpg encrypt: %w", err)
	}
	_, err = w.Write(out)
	return err
}

// Decrypt reads an OpenPGP ciphertext from r and returns its plaintext.
func (g *GPG) Decrypt(r io.Reader) ([]byte, error) {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	bin, name, err := g.resolve()
	if err != nil {
		return nil, err
	}
	args := append(g.baseArgs(name), "--decrypt", "--output", "-")

	out, err := g.run(bin, args, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: gpg decrypt: %w", err)
	}
	return out, nil
}

// run executes gpg with stdin and returns stdout, surfacing gpg's own stderr
// in the error so that "no secret key" or a cancelled pinentry stay legible.
func (g *GPG) run(bin string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(context.Background(), bin, args...) //nolint:gosec // args are built from store recipients, never from a shell string.
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Env = gpgEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && msg != "" {
			return nil, errors.New(msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}
