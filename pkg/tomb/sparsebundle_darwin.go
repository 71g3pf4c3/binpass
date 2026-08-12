//go:build darwin

package tomb

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
)

// bundleMinSize is the smallest sparse bundle worth creating. APFS needs
// room for its own metadata, and a smaller image fails inside hdiutil with a
// message that does not mention size.
const bundleMinSize = 16 << 20

// SparseBundle manages an encrypted APFS sparse bundle through hdiutil.
//
// By protection it sits between the other two backends: like LUKS, the
// plaintext lives in a filesystem the kernel mounts rather than in a
// directory that has to be shredded afterwards; unlike LUKS, it needs no
// root, because macOS lets an ordinary user attach a disk image.
//
// The image's passphrase is random and never seen by the user. It is stored
// age-encrypted beside the bundle, so unlocking the tomb is an ordinary age
// decryption and a hardware token that already unlocks the store unlocks the
// bundle too — the same arrangement the LUKS backend uses, for the same
// reason.
type SparseBundle struct {
	// identities supplies age decryption keys for the passphrase file.
	identities crypto.IdentityFunc
	// runner executes an external command; replaced in tests.
	runner commandRunner
}

// newSparseBundle returns a SparseBundle backend. It checks that hdiutil is
// available, which it is on every macOS install.
func newSparseBundle() (*SparseBundle, error) {
	if _, err := exec.LookPath("hdiutil"); err != nil {
		return nil, fmt.Errorf("tomb: hdiutil not found: %w", err)
	}
	return &SparseBundle{runner: execRunner}, nil
}

// SetIdentities configures the identity resolver used to decrypt the
// passphrase. Call this before Open.
func (s *SparseBundle) SetIdentities(fn crypto.IdentityFunc) { s.identities = fn }

// Name returns BackendSparseBundle.
func (s *SparseBundle) Name() Backend { return BackendSparseBundle }

// run executes a command through the configured runner.
func (s *SparseBundle) run(name string, stdin []byte, args ...string) ([]byte, error) {
	runner := s.runner
	if runner == nil {
		runner = execRunner
	}
	out, err := runner(name, stdin, args...)
	if err != nil {
		return out, classifyHdiutilError(out, err)
	}
	return out, nil
}

// Init creates an encrypted sparse bundle and moves the store into it.
func (s *SparseBundle) Init(dir string, rcp []string, size int64) error {
	image := bundlePath(dir)
	keyPath := bundleKeyPath(dir)

	if _, err := os.Stat(image); err == nil {
		return fmt.Errorf("tomb: sparse bundle already exists at %s", image)
	}
	if size < bundleMinSize {
		return fmt.Errorf("tomb: container size %d is too small; use at least %d bytes (16M)", size, bundleMinSize)
	}
	if len(rcp) == 0 {
		return errors.New("tomb: no recipients to encrypt the bundle passphrase to")
	}

	pass, err := randomPassphrase()
	if err != nil {
		return err
	}
	defer zero(pass)

	// Encrypt the passphrase before creating anything: a bundle whose
	// passphrase was never stored cannot be opened by anyone, including its
	// owner.
	if err := writeEncryptedKey(keyPath, pass, rcp); err != nil {
		return err
	}

	cleanup := func(err error) error {
		_ = os.RemoveAll(image)
		_ = os.Remove(keyPath)
		return err
	}

	// hdiutil takes megabytes; rounding up means --size=17M does not become
	// a bundle too small to hold anything.
	megabytes := (size + (1 << 20) - 1) / (1 << 20)
	if _, err := s.run("hdiutil", pass, createArgs(image, megabytes)...); err != nil {
		return cleanup(err)
	}

	if hasPlaintext(dir) {
		if err := s.seedBundle(dir, pass); err != nil {
			return cleanup(err)
		}
	}
	return nil
}

// seedBundle mounts a fresh bundle, copies the store's entries into it, and
// shreds the originals.
func (s *SparseBundle) seedBundle(dir string, pass []byte) error {
	mnt, err := os.MkdirTemp("", "binpass-bundle-seed-")
	if err != nil {
		return fmt.Errorf("tomb: temp mount point: %w", err)
	}
	defer func() { _ = os.Remove(mnt) }()

	if _, err := s.run("hdiutil", pass, attachArgs(bundlePath(dir), mnt)...); err != nil {
		return err
	}
	attached := true
	defer func() {
		if attached {
			_, _ = s.run("hdiutil", nil, detachArgs(mnt, true)...)
		}
	}()

	if err := copyTree(dir, mnt, bundleName, bundleKeyName); err != nil {
		return fmt.Errorf("tomb: seed bundle: %w", err)
	}
	if _, err := s.run("hdiutil", nil, detachArgs(mnt, false)...); err != nil {
		return err
	}
	attached = false

	return shredDir(dir, true, bundleName, bundleKeyName)
}

// Open decrypts the passphrase and attaches the bundle at dir.
func (s *SparseBundle) Open(dir string, timer time.Duration) error {
	image := bundlePath(dir)
	if _, err := os.Stat(image); err != nil {
		if os.IsNotExist(err) {
			return ErrNotInitialised
		}
		return fmt.Errorf("tomb: checking bundle: %w", err)
	}

	if st, err := loadState(dir); err == nil && !st.IsStale() && s.isAttached(dir) {
		return ErrAlreadyOpen
	}

	pass, err := s.readPassphrase(bundleKeyPath(dir))
	if err != nil {
		return err
	}
	defer zero(pass)

	if _, err := s.run("hdiutil", pass, attachArgs(image, dir)...); err != nil {
		return err
	}

	st := &State{
		Backend:    BackendSparseBundle,
		StoreDir:   dir,
		MountPoint: dir,
		OpenedAt:   time.Now(),
		Timer:      timer,
	}
	// Only a timer keeps a process alive to close the tomb later. Recording
	// the PID otherwise makes every cleanly opened tomb report itself as a
	// crash the moment the command returns.
	if timer > 0 {
		st.PID = os.Getpid()
	}
	if err := saveState(dir, st); err != nil {
		_, _ = s.run("hdiutil", nil, detachArgs(dir, true)...)
		return err
	}
	return nil
}

// Close detaches the bundle.
func (s *SparseBundle) Close(dir string, force bool) error {
	if !s.isAttached(dir) {
		return ErrNotOpen
	}
	if _, err := s.run("hdiutil", nil, detachArgs(dir, force)...); err != nil {
		return err
	}
	return RemoveState(dir)
}

// Status reports the current state.
func (s *SparseBundle) Status(dir string) (State, bool, error) {
	attached := s.isAttached(dir)

	st, err := loadState(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if _, serr := os.Stat(bundlePath(dir)); serr != nil {
				return State{}, false, nil
			}
			return State{Backend: BackendSparseBundle, StoreDir: dir, MountPoint: dir}, attached, nil
		}
		return State{}, false, err
	}
	// What the kernel has mounted is the truth: after a crash the state file
	// and reality disagree, and only one of them can unmount anything.
	return *st, attached, nil
}

// isAttached reports whether the bundle is currently mounted at dir.
//
// A mounted image contains the store's entries, so the presence of
// plaintext is what distinguishes attached from detached — the same test
// the coffin backend uses, and one that does not need to parse hdiutil's
// output.
func (s *SparseBundle) isAttached(dir string) bool {
	if _, err := os.Stat(bundlePath(dir)); err != nil {
		return false
	}
	return hasPlaintext(dir)
}

// readPassphrase decrypts the bundle's stored passphrase.
func (s *SparseBundle) readPassphrase(path string) ([]byte, error) {
	if s.identities == nil {
		return nil, fmt.Errorf("tomb: %w", crypto.ErrNoIdentity)
	}
	ids, err := s.identities()
	if err != nil {
		return nil, fmt.Errorf("tomb: resolve identities: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("tomb: %w", crypto.ErrNoIdentity)
	}
	return readEncryptedKey(path, ids)
}

// Compile-time interface checks.
var (
	_ Tomb          = (*SparseBundle)(nil)
	_ IdentityAware = (*SparseBundle)(nil)
)
