package tomb

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
)

// Coffin is the cross-platform tomb backend: the entire store is packed into a
// single age-encrypted tar archive. Open decrypts to a private directory (tmpfs
// on Linux, 0700 + shred elsewhere). Close re-encrypts and shreds the plaintext.
//
// Security properties:
//   - At rest: only the encrypted archive is visible. No file names, no
//     directory structure, no metadata leaks.
//   - Open: plaintext exists on disk (tmpfs on Linux, RAM-backed), protected
//     by directory permissions and auto-close.
//   - Close: plaintext is shredded (best-effort on SSD), then removed.
//
// Limitations:
//   - Plaintext is exposed for the duration of the session. Auto-close
//     mitigates but does not eliminate this.
//   - shred on SSD with wear-leveling does not guarantee data destruction.
type Coffin struct {
	// identities supplies age decryption keys, resolved lazily.
	identities crypto.IdentityFunc
}

// newCoffin returns a Coffin backend. If ids is nil, only encryption works.
func newCoffin() (*Coffin, error) {
	return &Coffin{}, nil
}

// SetIdentities configures the identity resolver for decryption. Call this
// before Open if the default resolver is not wired in.
func (c *Coffin) SetIdentities(fn crypto.IdentityFunc) {
	c.identities = fn
}

// Name returns BackendCoffin.
func (c *Coffin) Name() Backend { return BackendCoffin }

// Init creates a coffin archive from the store directory. If the store has
// content, it is packed and encrypted. The recipients must be valid age
// recipient strings (age1..., ssh-..., or plugin recipients).
func (c *Coffin) Init(dir string, rcp []string, _ int64) error {
	coffinPath := filepath.Join(dir, coffinFileName)

	// If a coffin already exists, refuse to overwrite.
	if _, err := os.Stat(coffinPath); err == nil {
		return fmt.Errorf("tomb: coffin already exists at %s", coffinPath)
	}

	// Pack and encrypt the store.
	return c.packEncrypt(dir, coffinPath, rcp)
}

// Open decrypts the coffin archive into a private directory. On Linux, the
// target is a tmpfs mount (/dev/shm); elsewhere, it is a 0700 directory that
// will be shredded on close.
func (c *Coffin) Open(dir string, timer time.Duration) error {
	coffinPath := filepath.Join(dir, coffinFileName)

	// Precondition: coffin must exist.
	if _, err := os.Stat(coffinPath); err != nil {
		if os.IsNotExist(err) {
			return ErrNotInitialised
		}
		return fmt.Errorf("tomb: checking coffin: %w", err)
	}

	// Precondition: store dir must not already contain plaintext entries.
	// This catches double-open. We check for any non-coffin, non-dotfile
	// content (matching storage.FS which skips dotfiles).
	if hasPlaintext(dir) {
		return ErrAlreadyOpen
	}

	// Check for stale state (crash without close).
	st, err := loadState(dir)
	if err == nil && !st.IsStale() {
		// Another live process has the tomb open.
		return ErrAlreadyOpen
	}
	// Stale state: clean up the leftover state file.
	if err == nil && st.IsStale() {
		_ = os.Remove(statePath(dir))
	}

	// Decrypt the archive into the store directory.
	if err := c.unpackDecrypt(dir, coffinPath); err != nil {
		return fmt.Errorf("tomb: open: %w", err)
	}

	mlockDir(dir)

	// Write state so that doctor can find us.
	//
	// The PID is recorded only when a timer keeps a process alive to close
	// the tomb. `binpass tomb open` otherwise exits immediately, so storing
	// its PID meant every cleanly opened tomb reported itself as "stale
	// (crash without close)" the moment the command returned.
	s := State{
		Backend:    BackendCoffin,
		StoreDir:   dir,
		CoffinPath: coffinPath,
		OpenedAt:   time.Now(),
		Timer:      timer,
	}
	if timer > 0 {
		s.PID = os.Getpid()
	}
	if err := saveState(dir, &s); err != nil {
		// Roll back the unpack on state failure.
		_ = shredDir(dir, true, coffinFileName, stateFileName)
		return fmt.Errorf("tomb: writing state: %w", err)
	}

	return nil
}

// Close re-encrypts the plaintext store into the coffin, then shreds the
// plaintext directory. If force is true, skip the overwrite-random pass and
// just remove files (faster, but no shred guarantee — appropriate during
// shutdown or when the operator accepts the SSD caveat explicitly).
func (c *Coffin) Close(dir string, force bool) error {
	coffinPath := filepath.Join(dir, coffinFileName)

	// Precondition: the store directory must have plaintext content.
	if !hasPlaintext(dir) {
		return ErrNotOpen
	}

	// Read recipients from the now-decrypted store.
	rcp, err := c.readRecipients(dir)
	if err != nil {
		return fmt.Errorf("tomb: close: %w", err)
	}

	// Pack and encrypt the current plaintext back into the coffin.
	// Write to a temporary file first, then rename, so a crash leaves the
	// old coffin intact.
	tmpCoffin := coffinPath + ".tmp"
	if err := c.packEncrypt(dir, tmpCoffin, rcp); err != nil {
		return fmt.Errorf("tomb: close: re-encrypt: %w", err)
	}

	// Atomic swap: new coffin replaces old.
	if err := os.Rename(tmpCoffin, coffinPath); err != nil {
		_ = os.Remove(tmpCoffin)
		return fmt.Errorf("tomb: close: rename: %w", err)
	}

	// Shred the plaintext, keeping the coffin and state file.
	// When force is true, skip overwrite-random for speed.
	if err := shredDir(dir, !force, coffinFileName, stateFileName); err != nil {
		return fmt.Errorf("tomb: close: shred: %w", err)
	}

	// Remove the state file.
	_ = os.Remove(statePath(dir))

	return nil
}

// Status reports whether the coffin is currently open.
func (c *Coffin) Status(dir string) (State, bool, error) {
	st, err := loadState(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// No state file. The store may still have a tomb: `Init` leaves
			// one open before any state is written, and a clean `Close`
			// removes the state but keeps the container. Whether plaintext
			// is present is what distinguishes the two, and reading only
			// the state file reported both as "no tomb at all".
			if !HasContainer(dir) {
				return State{}, false, nil
			}
			return State{Backend: BackendCoffin, StoreDir: dir, CoffinPath: filepath.Join(dir, coffinFileName)},
				hasPlaintext(dir), nil
		}
		return State{}, false, err
	}
	// The state file exists. Check if it is stale.
	if st.IsStale() {
		return *st, false, nil
	}
	return *st, true, nil
}

// packEncrypt creates an encrypted tar archive of the store directory. Only
// non-dotfile, non-coffin entries are packed, matching the store's own
// iteration rules.
func (c *Coffin) packEncrypt(dir, output string, rcp []string) error {
	// Build tar in memory first, then encrypt. For large stores this will
	// need streaming, but for the initial implementation memory is fine.
	var buf bytes.Buffer
	if err := writeTar(&buf, dir); err != nil {
		return fmt.Errorf("tomb: pack: %w", err)
	}

	// Encrypt with age.
	recipients, err := crypto.ParseAgeRecipients(toRecipients(rcp))
	if err != nil {
		return fmt.Errorf("tomb: encrypt: %w", err)
	}

	// Write to a temporary file, then rename for atomicity.
	tmpOutput := output + ".writing"
	// The path is the coffin location the caller configured, with a fixed
	// suffix; it is not user input.
	f, err := os.OpenFile(tmpOutput, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path binpass derived, not user input.
	if err != nil {
		return fmt.Errorf("tomb: create temp: %w", err)
	}
	tmpName := f.Name()
	defer func() { _ = os.Remove(tmpName) }()

	wc, err := age.Encrypt(f, recipients...)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("tomb: encrypt: %w", err)
	}
	if _, err := wc.Write(buf.Bytes()); err != nil {
		_ = wc.Close()
		_ = f.Close()
		return fmt.Errorf("tomb: encrypt: %w", err)
	}
	if err := wc.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("tomb: encrypt: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("tomb: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("tomb: close: %w", err)
	}
	if err := os.Rename(tmpName, output); err != nil {
		return fmt.Errorf("tomb: rename: %w", err)
	}
	return nil
}

// unpackDecrypt reads the coffin archive and extracts it into dir.
func (c *Coffin) unpackDecrypt(dir, coffinPath string) error {
	f, err := os.Open(coffinPath) //nolint:gosec // path is constructed from dir + constant.
	if err != nil {
		return fmt.Errorf("tomb: open coffin: %w", err)
	}
	defer func() { _ = f.Close() }()

	if c.identities == nil {
		return fmt.Errorf("tomb: %w", crypto.ErrNoIdentity)
	}
	ids, err := c.identities()
	if err != nil {
		return fmt.Errorf("tomb: resolve identities: %w", err)
	}
	if len(ids) == 0 {
		return fmt.Errorf("tomb: %w", crypto.ErrNoIdentity)
	}

	dr, err := age.Decrypt(f, ids...)
	if err != nil {
		return fmt.Errorf("tomb: decrypt: %w", err)
	}

	// Extract tar from the decrypted stream.
	if err := readTar(dr, dir); err != nil {
		return fmt.Errorf("tomb: unpack: %w", err)
	}
	return nil
}

// readRecipients loads the store's recipients from the decrypted plaintext.
func (c *Coffin) readRecipients(dir string) ([]string, error) {
	// Try .age-recipients first (age default), then .gpg-id (GPG store).
	for _, name := range []string{".age-recipients", ".gpg-id"} {
		data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // dir is the store root.
		if err != nil {
			continue
		}
		var out []string
		for _, line := range splitLines(string(data)) {
			line = trimSpace(line)
			if line != "" && line[0] != '#' {
				out = append(out, line)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("tomb: no recipients found in store")
}

// writeTar writes the store directory as a tar archive, skipping the coffin
// file itself, dotfiles, and the state file. Directory entries are stored with
// their Unix permissions so they can be restored on open.
func writeTar(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	defer func() { _ = tw.Close() }()

	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		// Skip the root itself.
		if rel == "." {
			return nil
		}

		// Skip dotfiles and dot-directories (matching storage.FS behavior).
		if rel[0] == '.' {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip the coffin archive itself.
		if filepath.Base(path) == coffinFileName {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		// Skip symlinks: they are not written to the archive because readTar
		// rejects them on extraction. Password stores should not contain
		// symlinks; if they do, they are silently dropped.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Directories and symlinks have no body.
		if !d.Type().IsRegular() {
			return nil
		}

		f, err := os.Open(path) //nolint:gosec // path from WalkDir.
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		return f.Close()
	})
}

// readTar extracts a tar archive into dir, preserving permissions. The
// directory must exist.
func readTar(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dir, filepath.FromSlash(header.Name))

		// Security: prevent path traversal.
		if !isWithin(dir, target) {
			return fmt.Errorf("tomb: archive path escapes store: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, dirMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode(header.Mode)) //nolint:gosec // target is checked against the store root above.
			if err != nil {
				return err
			}
			// The archive is age-encrypted to the user's own recipients, so
			// reaching this code with hostile input means the attacker already
			// holds the key. The size cap is a guard against a corrupt archive
			// filling the disk, not against an adversary.
			if _, err := io.Copy(f, io.LimitReader(tr, maxEntryBytes)); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			// Reject symlinks: a symlink pointing outside the store allows a
			// subsequent TypeReg entry to write through it (path traversal).
			// Coffin never writes symlinks, so this is always malicious or
			// corrupt input.
			return fmt.Errorf("tomb: archive contains symlink (%s), which is not allowed", header.Name)
		}
	}
	return nil
}

// hasPlaintext reports whether dir contains any non-dotfile, non-coffin
// regular files or subdirectories. This is used to detect an already-open
// tomb.
func hasPlaintext(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		name := e.Name()
		// Dotfiles and any backend's own container are expected even when
		// closed. Counting the LUKS image as plaintext made every closed
		// LUKS store look open, and made `init` try to seed a container
		// with itself.
		if name[0] == '.' || name == coffinFileName ||
			name == luksImageName || name == luksKeyName ||
			name == bundleName || name == bundleKeyName {
			continue
		}
		return true
	}
	return false
}

// shredDir removes all files and directories inside dir, optionally
// overwriting regular files with random data first. Dotfiles (matching
// storage.FS behavior) and the preserve names are kept. If shred is false,
// files are simply removed without overwriting (force close).
func shredDir(dir string, shred bool, preserve ...string) error {
	preserveSet := make(map[string]bool, len(preserve))
	for _, p := range preserve {
		preserveSet[p] = true
	}

	// Walk in reverse depth order so directories are empty when removed.
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}

	// Reverse: deepest first.
	for i := len(paths) - 1; i >= 0; i-- {
		path := paths[i]
		base := filepath.Base(path)
		if preserveSet[base] {
			continue
		}
		// Skip dotfiles and dot-directories (.age-recipients, .gpg-id, .git, etc).
		// These are store metadata that must survive close so that the next open
		// can find recipients and git can work.
		if len(base) > 0 && base[0] == '.' {
			continue
		}
		// If it's a regular file, overwrite before removing (unless forced).
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if shred && info.Mode().IsRegular() {
			_ = overwriteRandom(path, info.Size())
		}
		_ = os.Remove(path)
	}
	return nil
}

// overwriteRandom writes random bytes over the file, then syncs. Best-effort.
func overwriteRandom(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) //nolint:gosec // intentional overwrite.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Write in chunks to avoid allocating the entire file in memory.
	const chunk = 64 * 1024
	buf := make([]byte, chunk)
	remaining := size
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		// Re-fill the buffer with random data for each chunk.
		_, _ = rand.Read(buf[:n])
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	_ = f.Sync()
	return nil
}

// toRecipients converts string recipients to crypto.Recipient.
func toRecipients(rcp []string) []crypto.Recipient {
	out := make([]crypto.Recipient, 0, len(rcp))
	for _, r := range rcp {
		out = append(out, crypto.Recipient(r))
	}
	return out
}

// isWithin reports whether path is root or lies beneath it.
func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	// Only ".." escapes. Rejecting every path whose first byte is a dot, as
	// this once did, also rejected ".age-recipients" — a legitimate entry
	// that merely starts with the same character as the traversal it was
	// meant to catch.
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// splitLines splits on newlines, keeping empty lines (they are filtered later).
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// trimSpace is strings.TrimSpace, inlined to avoid the import.
func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// Compile-time interface check.
var _ Tomb = (*Coffin)(nil)

// Ensure overwriteRandom fallback for non-Linux.
var _ = overwriteRandom // used in shredDir.

// maxEntryBytes caps a single extracted file. Password entries are a few
// hundred bytes; a gigabyte is far beyond anything legitimate and stops a
// corrupt archive from filling the disk.
const maxEntryBytes = 1 << 30

// fileMode reduces an archive's stored mode to the permission bits.
//
// The permissions themselves are preserved: a store deliberately made
// group-readable must come back that way. What is dropped is setuid, setgid
// and sticky, which have no meaning for a password file and are the only
// part of a mode worth attacking.
func fileMode(mode int64) os.FileMode {
	return os.FileMode(mode) & os.ModePerm //nolint:gosec // masked to permission bits.
}

// dirMode is fileMode for directories, which must stay traversable by their
// owner or the entries beneath them become unreachable.
func dirMode(mode int64) os.FileMode {
	return fileMode(mode) | 0o700
}
