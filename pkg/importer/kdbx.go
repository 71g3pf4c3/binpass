package importer

import (
	"bytes"
	"fmt"
	"io"
	"iter"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
)

// KeePassImporter reads KDBX (KeePass 2.x) databases.
//
// KDBX is a binary format, so Detect checks for the KDBX magic bytes and
// Import re-reads the file. The caller should re-open the file for Import.
//
// The database password is read from TTY/stdin, never from argv (§3 of the
// project rules). Pass the password via the Password field before calling
// Import.
type KeePassImporter struct {
	// Password is the database master password. It must be set before
	// calling Import. The caller is responsible for reading it from the
	// terminal.
	Password string
}

// Name returns the format name.
func (KeePassImporter) Name() string { return "KeePass" }

// Detect reports whether r looks like a KDBX file by checking the magic
// signature bytes. The KDBX 3.1 and 4.0 signatures both start with 0x03 0xd9
// 0xa2 0x96.
func (KeePassImporter) Detect(r io.Reader) bool {
	magic := make([]byte, 4)
	n, _ := io.ReadFull(r, magic)
	if n < 4 {
		return false
	}
	return bytes.Equal(magic, []byte{0x03, 0xd9, 0xa2, 0x96})
}

// Import decrypts the KDBX database and yields entries.
func (k *KeePassImporter) Import(r io.Reader) iter.Seq2[*Entry, error] {
	return func(yield func(*Entry, error) bool) {
		db := gokeepasslib.NewDatabase()
		db.Credentials = gokeepasslib.NewPasswordCredentials(k.Password)

		decoder := gokeepasslib.NewDecoder(r)
		if err := decoder.Decode(db); err != nil {
			yield(nil, fmt.Errorf("keepass: decode: %w", err))
			return
		}

		// Unlock protected (encrypted) fields like passwords.
		if err := db.UnlockProtectedEntries(); err != nil {
			yield(nil, fmt.Errorf("keepass: unlock: %w", err))
			return
		}

		if db.Content == nil || db.Content.Root == nil {
			return
		}

		for _, group := range db.Content.Root.Groups {
			if !k.yieldGroup(group, "", db, yield) {
				return
			}
		}
	}
}

// yieldGroup recursively walks a KeePass group and yields its entries.
// It returns false if iteration was stopped by the caller.
func (k *KeePassImporter) yieldGroup(g gokeepasslib.Group, parentPath string, db *gokeepasslib.Database, yield func(*Entry, error) bool) bool {
	groupPath := g.Name
	if parentPath != "" {
		groupPath = parentPath + "/" + groupPath
	}

	for i := range g.Entries {
		e := k.convertEntry(&g.Entries[i], groupPath, db)
		if !yield(e, nil) {
			return false
		}
	}

	for i := range g.Groups {
		if !k.yieldGroup(g.Groups[i], groupPath, db, yield) {
			return false
		}
	}
	return true
}

// convertEntry maps a KeePass entry to an Entry.
func (k *KeePassImporter) convertEntry(e *gokeepasslib.Entry, groupPath string, db *gokeepasslib.Database) *Entry {
	out := &Entry{
		Title:    e.GetTitle(),
		Username: e.GetContent("UserName"),
		Password: e.GetPassword(),
		URL:      e.GetContent("URL"),
		Notes:    e.GetContent("Notes"),
		Group:    groupPath,
	}

	// TOTP: KeePass has several TOTP plugins. Look for common field names.
	for _, field := range []string{"TimeOtp-Secret-Base32", "TOTP Seed", "otp"} {
		secret := e.GetContent(field)
		if secret != "" {
			if strings.HasPrefix(strings.ToLower(secret), "otpauth://") {
				out.TOTPURI = secret
			} else {
				// Raw base32 secret: wrap into otpauth:// URI.
				out.TOTPURI = fmt.Sprintf("otpauth://totp/%s:?secret=%s&issuer=%s",
					out.Title, secret, out.Title)
			}
			break
		}
	}

	// Custom string fields beyond the standard ones.
	standardFields := map[string]bool{
		"Title": true, "UserName": true, "Password": true,
		"URL": true, "Notes": true, "TOTP Seed": true,
		"TimeOtp-Secret-Base32": true, "otp": true,
	}
	for _, v := range e.Values {
		if standardFields[v.Key] {
			continue
		}
		if v.Value.Content != "" {
			out.Fields = append(out.Fields, Field{
				Name:  v.Key,
				Value: v.Value.Content,
			})
		}
	}

	// Attachments (binary references in KeePass terminology). The actual
	// binary data lives in the database's binary pool, not in the entry.
	for _, bin := range e.Binaries {
		actual := bin.Find(db)
		if actual == nil {
			continue
		}
		name := bin.Name
		if name == "" {
			name = "attachment"
		}
		data, err := actual.GetContentBytes()
		if err != nil {
			continue
		}
		out.Attachments = append(out.Attachments, Attachment{
			Name: name,
			Data: data,
		})
	}

	return out
}
