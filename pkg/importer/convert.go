package importer

import (
	"fmt"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/secret"
)

// ToSecret converts an Entry into a pass-format secret. The first line is the
// password; subsequent lines carry structured fields, the OTP URI, and free-form
// notes, in that order.
func (e *Entry) ToSecret() *secret.Secret {
	var body strings.Builder

	// Structured fields first, for easy --field access.
	if e.Username != "" {
		body.WriteString("username: ")
		body.WriteString(e.Username)
		body.WriteString("\n")
	}
	if e.URL != "" {
		body.WriteString("url: ")
		body.WriteString(e.URL)
		body.WriteString("\n")
	}
	for _, f := range e.Fields {
		body.WriteString(f.Name)
		body.WriteString(": ")
		body.WriteString(f.Value)
		body.WriteString("\n")
	}
	if e.TOTPURI != "" {
		body.WriteString(e.TOTPURI)
		body.WriteString("\n")
	}
	if e.Notes != "" {
		// Notes come last because they may contain free-form text that
		// should not be misread as structured fields.
		if !strings.HasSuffix(e.Notes, "\n") {
			body.WriteString(e.Notes)
			body.WriteString("\n")
		} else {
			body.WriteString(e.Notes)
		}
	}

	return secret.New(e.Password, body.String())
}

// StorePath returns the path under which this entry should be stored, after
// normalisation and validation. If the entry already has an explicit Path,
// it is used directly; otherwise the path is derived from Group and Title.
func (e *Entry) StorePath() (string, error) {
	p := e.Path
	if p == "" {
		p = NormalizePath(e.Group, e.Title)
	}
	if !ValidatePath(p) {
		return "", fmt.Errorf("importer: invalid store path %q (from title %q, group %q)", p, e.Title, e.Group)
	}
	return p, nil
}

// AttachmentStorePath returns the store path for attachment i, using the
// gopass convention of "name.b64" (§1 of ARCHITECTURE.md).
func (e *Entry) AttachmentStorePath(i int) (string, error) {
	base, err := e.StorePath()
	if err != nil {
		return "", err
	}
	if i < 0 || i >= len(e.Attachments) {
		return "", fmt.Errorf("importer: attachment index %d out of range", i)
	}
	att := e.Attachments[i]
	name := att.Name
	if name == "" {
		name = fmt.Sprintf("attachment-%d", i+1)
	}
	return base + "/" + name + ".b64", nil
}
