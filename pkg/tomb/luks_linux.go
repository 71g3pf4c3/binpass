//go:build linux

package tomb

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
)

// luksKeySize is the size of the generated key file in bytes. LUKS accepts a
// key file of any length; 64 random bytes is well past the point where the
// key stops being the weakest part of the system.
const luksKeySize = 64

// luksMinSize is the smallest container worth creating. cryptsetup needs room
// for its header, and a filesystem needs room for its own metadata, so a
// container below this fails in ways that are tedious to diagnose.
const luksMinSize = 16 << 20

// LUKS manages a dm-crypt container via the external cryptsetup binary. The
// plaintext exists only in the kernel's dm-crypt mapping and never touches
// disk, which is the one thing the coffin backend cannot offer.
//
// The container's key file is itself encrypted to the store's age recipients.
// That is what makes hardware tokens work here without any LUKS-specific
// support: unlocking the tomb is an ordinary age decryption, and whether the
// identity lives in a file or on a YubiKey is not this code's concern.
//
// Requires root, or a polkit policy granting the user access to cryptsetup,
// losetup and mount.
type LUKS struct {
	// identities supplies age decryption keys for the key file.
	identities crypto.IdentityFunc
	// runner executes an external command; replaced in tests.
	runner commandRunner
}

// commandRunner executes an external command with optional stdin, returning
// its combined output. It exists so that argument construction and error
// handling can be tested without root, a loop device, or cryptsetup.
type commandRunner func(name string, stdin []byte, args ...string) ([]byte, error)

// newLUKS returns a LUKS backend. It checks that cryptsetup is available.
func newLUKS() (*LUKS, error) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		return nil, fmt.Errorf("tomb: cryptsetup not found on PATH: %w", err)
	}
	return &LUKS{runner: execRunner}, nil
}

// SetIdentities configures the identity resolver used to decrypt the key
// file. Call this before Open.
func (l *LUKS) SetIdentities(fn crypto.IdentityFunc) { l.identities = fn }

// Name returns BackendLUKS.
func (l *LUKS) Name() Backend { return BackendLUKS }

// execRunner runs a command for real, feeding it stdin when given.
//
// The key file is passed this way rather than as a path or an argument:
// a temporary file would put the decrypted key on disk, and an argument would
// publish it in /proc to every process on the machine.
func execRunner(name string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...) //nolint:gosec // callers pass fixed binaries and arguments built here.
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// run executes a command through the configured runner.
func (l *LUKS) run(name string, stdin []byte, args ...string) ([]byte, error) {
	runner := l.runner
	if runner == nil {
		runner = execRunner
	}
	out, err := runner(name, stdin, args...)
	if err != nil {
		return out, classifyLUKSError(name, out, err)
	}
	return out, nil
}

// classifyLUKSError turns an exit status into something a user can act on.
//
// cryptsetup reports permission problems, a missing dm-crypt module, and a
// wrong key all as exit status 1 with the detail on stderr. Passing that
// through unread leaves the user with "exit status 1" and no idea whether to
// reach for sudo or for modprobe.
func classifyLUKSError(name string, out []byte, err error) error {
	text := strings.ToLower(string(out))
	switch {
	case strings.Contains(text, "permission denied"),
		strings.Contains(text, "are you root"),
		strings.Contains(text, "operation not permitted"),
		strings.Contains(text, "requires superuser privilege"):
		return fmt.Errorf("%w: %s needs root or a polkit rule: %s", ErrNeedRoot, name, firstLine(out))
	case strings.Contains(text, "device-mapper"),
		strings.Contains(text, "failed to open /dev/mapper/control"),
		strings.Contains(text, "dm-crypt"):
		return fmt.Errorf("tomb: the kernel has no usable dm-crypt (try: modprobe dm_crypt): %s", firstLine(out))
	case strings.Contains(text, "no key available"),
		strings.Contains(text, "no usable keyslot"):
		return fmt.Errorf("tomb: the key file does not unlock this container: %s", firstLine(out))
	}
	if len(out) == 0 {
		return fmt.Errorf("tomb: %s: %w", name, err)
	}
	return fmt.Errorf("tomb: %s: %w: %s", name, err, firstLine(out))
}

// firstLine returns the first non-empty line of command output, which is
// where cryptsetup puts the actual reason.
func firstLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}

// mapperName derives the dm-crypt mapper name for a store.
//
// It is derived from the store path rather than fixed, so that two stores
// open at once do not collide on /dev/mapper, and stable, so that a crashed
// tomb can still be found and closed.
func mapperName(storeDir string) string {
	return "binpass-" + storeHash(storeDir)
}

// luksFormatArgs builds the cryptsetup invocation that creates the container.
func luksFormatArgs(image string) []string {
	return []string{
		"luksFormat",
		"--type", "luks2",
		"--batch-mode",
		"--key-file", "-",
		image,
	}
}

// luksOpenArgs builds the cryptsetup invocation that unlocks the container.
func luksOpenArgs(image, mapper string) []string {
	return []string{"open", "--key-file", "-", image, mapper}
}

// luksCloseArgs builds the cryptsetup invocation that locks the container.
func luksCloseArgs(mapper string) []string {
	return []string{"close", mapper}
}

// mkfsArgs builds the mkfs invocation for a freshly formatted container.
func mkfsArgs(mapper string) []string {
	return []string{"-q", "-m", "0", "/dev/mapper/" + mapper}
}

// mountArgs builds the mount invocation for an unlocked container.
func mountArgs(mapper, dir string) []string {
	return []string{"/dev/mapper/" + mapper, dir}
}

// Init creates a LUKS container and an age-encrypted key file.
//
// The store's existing entries are moved into the container, so that after
// Init the plaintext lives inside it rather than beside it.
func (l *LUKS) Init(dir string, rcp []string, size int64) error {
	image := filepath.Join(dir, luksImageName)
	keyPath := filepath.Join(dir, luksKeyName)

	if _, err := os.Stat(image); err == nil {
		return fmt.Errorf("tomb: LUKS container already exists at %s", image)
	}
	if size < luksMinSize {
		return fmt.Errorf("tomb: container size %d is too small; use at least %d bytes (16M)", size, luksMinSize)
	}
	if len(rcp) == 0 {
		return errors.New("tomb: no recipients to encrypt the container key to")
	}

	key := make([]byte, luksKeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("tomb: generate container key: %w", err)
	}

	// Encrypt the key before creating anything: a container whose key was
	// never written is unopenable, and cleaning that up is worse than
	// failing before it exists.
	if err := writeEncryptedKey(keyPath, key, rcp); err != nil {
		return err
	}

	// Sparse: the file reports its full size but occupies only what is
	// written, so --size=10G does not cost 10G up front.
	if err := createSparseFile(image, size); err != nil {
		_ = os.Remove(keyPath)
		return err
	}

	cleanup := func(err error) error {
		_ = os.Remove(image)
		_ = os.Remove(keyPath)
		return err
	}

	if _, err := l.run("cryptsetup", key, luksFormatArgs(image)...); err != nil {
		return cleanup(err)
	}

	mapper := mapperName(dir)
	if _, err := l.run("cryptsetup", key, luksOpenArgs(image, mapper)...); err != nil {
		return cleanup(err)
	}
	// From here on the container is unlocked and must be locked again
	// whatever happens, or the mapping outlives the command that made it.
	defer func() { _, _ = l.run("cryptsetup", nil, luksCloseArgs(mapper)...) }()

	if _, err := l.run("mkfs.ext4", nil, mkfsArgs(mapper)...); err != nil {
		return cleanup(err)
	}

	// Move whatever the store already holds into the container, so that
	// Init does not silently leave a second copy of every entry outside it.
	if hasPlaintext(dir) {
		if err := l.seedContainer(dir, mapper); err != nil {
			return cleanup(err)
		}
	}
	return nil
}

// seedContainer mounts the new container, copies the store's existing entries
// into it, and shreds the originals.
func (l *LUKS) seedContainer(dir, mapper string) error {
	mnt, err := os.MkdirTemp("", "binpass-luks-seed-")
	if err != nil {
		return fmt.Errorf("tomb: temp mount point: %w", err)
	}
	defer func() { _ = os.Remove(mnt) }()

	if _, err := l.run("mount", nil, mountArgs(mapper, mnt)...); err != nil {
		return err
	}
	mounted := true
	defer func() {
		if mounted {
			_, _ = l.run("umount", nil, mnt)
		}
	}()

	if err := copyTree(dir, mnt, luksImageName, luksKeyName); err != nil {
		return fmt.Errorf("tomb: seed container: %w", err)
	}
	if _, err := l.run("umount", nil, mnt); err != nil {
		return err
	}
	mounted = false

	// The entries are inside the container now; the copies outside it are
	// exactly what the tomb exists to remove.
	return shredDir(dir, true, luksImageName, luksKeyName)
}

// Open decrypts the key file, unlocks the container, and mounts it at dir.
func (l *LUKS) Open(dir string, timer time.Duration) error {
	image := filepath.Join(dir, luksImageName)
	keyPath := filepath.Join(dir, luksKeyName)

	if _, err := os.Stat(image); err != nil {
		if os.IsNotExist(err) {
			return ErrNotInitialised
		}
		return fmt.Errorf("tomb: checking container: %w", err)
	}

	if st, err := loadState(dir); err == nil && !st.IsStale() {
		return ErrAlreadyOpen
	}

	key, err := l.readEncryptedKey(keyPath)
	if err != nil {
		return err
	}
	// The key is in memory for as long as cryptsetup needs it and no longer.
	defer zero(key)

	mapper := mapperName(dir)
	if _, err := l.run("cryptsetup", key, luksOpenArgs(image, mapper)...); err != nil {
		return err
	}
	if _, err := l.run("mount", nil, mountArgs(mapper, dir)...); err != nil {
		_, _ = l.run("cryptsetup", nil, luksCloseArgs(mapper)...)
		return err
	}

	st := &State{
		Backend:    BackendLUKS,
		StoreDir:   dir,
		MountPoint: dir,
		MapperName: mapper,
		OpenedAt:   time.Now(),
		Timer:      timer,
	}
	// Only a timer keeps a process alive to close the tomb later. Recording
	// the PID otherwise made every cleanly opened tomb report itself as
	// "stale (crash without close)" the moment the command returned, which
	// is the same bug coffin already had.
	if timer > 0 {
		st.PID = os.Getpid()
	}
	if err := saveState(dir, st); err != nil {
		_, _ = l.run("umount", nil, dir)
		_, _ = l.run("cryptsetup", nil, luksCloseArgs(mapper)...)
		return err
	}
	return nil
}

// Close unmounts the container and locks it again.
func (l *LUKS) Close(dir string, _ bool) error {
	mapper := mapperName(dir)
	if st, err := loadState(dir); err == nil && st.MapperName != "" {
		mapper = st.MapperName
	}

	if !l.isMapped(mapper) {
		return ErrNotOpen
	}

	// Unmounting can fail because the user's shell is sitting in the
	// directory. Reporting that plainly beats leaving the mapping locked
	// open while claiming success.
	if _, err := l.run("umount", nil, dir); err != nil {
		return err
	}
	if _, err := l.run("cryptsetup", nil, luksCloseArgs(mapper)...); err != nil {
		return err
	}
	return RemoveState(dir)
}

// isMapped reports whether the dm-crypt mapping exists.
//
// This is the authoritative answer for LUKS: the state file records what
// binpass did, but the kernel records what is actually open, and after a
// crash those disagree.
func (l *LUKS) isMapped(mapper string) bool {
	_, err := os.Stat("/dev/mapper/" + mapper)
	return err == nil
}

// Status reports the current state.
func (l *LUKS) Status(dir string) (State, bool, error) {
	mapped := l.isMapped(mapperName(dir))

	st, err := loadState(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if _, serr := os.Stat(filepath.Join(dir, luksImageName)); serr != nil {
				return State{}, false, nil
			}
			// A container with no state file: either never opened, or
			// opened by something that did not record it. The kernel
			// decides which.
			return State{Backend: BackendLUKS, StoreDir: dir, MapperName: mapperName(dir)}, mapped, nil
		}
		return State{}, false, err
	}

	// A mapping the kernel does not have is not open, whatever the state
	// file says; a mapping it does have is open even if the process that
	// made it is gone, and the caller needs to know so it can be closed.
	if !mapped {
		return *st, false, nil
	}
	return *st, true, nil
}

// writeEncryptedKey encrypts the container key to the store's recipients.
func writeEncryptedKey(path string, key []byte, rcp []string) error {
	recipients, err := crypto.ParseAgeRecipients(toRecipients(rcp))
	if err != nil {
		return fmt.Errorf("tomb: container key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path binpass derived, not user input.
	if err != nil {
		return fmt.Errorf("tomb: create key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	w, err := age.Encrypt(f, recipients...)
	if err != nil {
		return fmt.Errorf("tomb: encrypt container key: %w", err)
	}
	if _, err := w.Write(key); err != nil {
		_ = w.Close()
		return fmt.Errorf("tomb: encrypt container key: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("tomb: encrypt container key: %w", err)
	}
	return f.Sync()
}

// readEncryptedKey decrypts the container key.
func (l *LUKS) readEncryptedKey(path string) ([]byte, error) {
	if l.identities == nil {
		return nil, fmt.Errorf("tomb: %w", crypto.ErrNoIdentity)
	}
	ids, err := l.identities()
	if err != nil {
		return nil, fmt.Errorf("tomb: resolve identities: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("tomb: %w", crypto.ErrNoIdentity)
	}

	f, err := os.Open(path) //nolint:gosec // path is constructed from dir + constant.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("tomb: container key file is missing: %s", path)
		}
		return nil, fmt.Errorf("tomb: open key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	r, err := age.Decrypt(f, ids...)
	if err != nil {
		return nil, fmt.Errorf("tomb: decrypt container key: %w", err)
	}
	key, err := io.ReadAll(io.LimitReader(r, luksKeySize*2))
	if err != nil {
		return nil, fmt.Errorf("tomb: read container key: %w", err)
	}
	if len(key) == 0 {
		return nil, errors.New("tomb: container key file is empty")
	}
	return key, nil
}

// createSparseFile creates a file that reports size bytes but occupies only
// the blocks actually written.
func createSparseFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path binpass derived, not user input.
	if err != nil {
		return fmt.Errorf("tomb: create container: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := f.Truncate(size); err != nil {
		return fmt.Errorf("tomb: size container: %w", err)
	}
	return nil
}

// copyTree copies the contents of src into dst, skipping the named entries.
func copyTree(src, dst string, skip ...string) error {
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipSet[s] = true
	}

	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if skipSet[rel] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		target := filepath.Join(dst, rel)
		// A symlink in the store could otherwise walk the copy out of the
		// container and write wherever it points.
		if !isWithin(dst, target) {
			return fmt.Errorf("tomb: refusing to copy %q outside the container", rel)
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			// Sockets and devices have no business in a password store,
			// and copying them into the container would be a way to smuggle
			// something odd past the next reader.
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // walking the store binpass was pointed at.
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600) //nolint:gosec // target checked against the container root above.
	})
}

// zero overwrites a key in memory once it is no longer needed. It is not a
// guarantee — Go may have copied the slice — but leaving the key sitting in a
// live buffer for the rest of the process is worse.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Compile-time interface check.
var _ Tomb = (*LUKS)(nil)
