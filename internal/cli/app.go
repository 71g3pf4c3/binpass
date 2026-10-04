// Package cli implements the binpass command line, which is byte-compatible
// with pass(1) for the commands pass provides.
//
// Commands hold no business logic: they parse flags, call into pkg/store, and
// format output. Everything that could be tested without a terminal lives
// under pkg/.
package cli

import (
	"fmt"
	"io"
	"os"
	"sync"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/audit"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/identity"
	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// App carries the state shared by all commands.
type App struct {
	// Cfg is the resolved configuration.
	Cfg config.Config
	// Out is where command output goes.
	Out io.Writer
	// Err is where diagnostics go.
	Err io.Writer
	// In is where interactive input is read from.
	In io.Reader
	// Version is the binpass version, which plugins are told so that they
	// can adapt to the binary they were launched by.
	Version string

	// storeOnce guards lazy store construction.
	storeOnce sync.Once
	// cachedStore is the store built on first use.
	cachedStore *store.Store
	// storeErr is the error from building the store, if any.
	storeErr error

	// gpgBackend and ageBackend are the crypto backends the store was
	// wired with, recorded so that a reencrypt can target exactly the
	// backend a fresh insert would use. They are set under storeOnce and
	// are therefore only safe to read after a successful Store call.
	gpgBackend crypto.Crypto
	// ageBackend is the age backend including its decrypt diagnostics
	// wrapper, which is harmless for encryption and keeps error messages
	// uniform.
	ageBackend crypto.Crypto

	// guardOnce guards lazy guard construction.
	guardOnce sync.Once
	// cachedGuard enforces plugin capabilities on store access.
	cachedGuard *plugin.Guard

	// hibpClient stands in for the HIBP breach database in tests; nil
	// means the real one, which talks to the network and has no place in
	// there.
	hibpClient audit.HIBPChecker

	// identityMu guards identityFiles, which decrypts on any goroutine can
	// grow through the lazy identity resolution.
	identityMu sync.Mutex
	// identityFiles records where the identities handed to age were loaded
	// from, so a failed decrypt can name the files that were tried instead
	// of age's opaque "incorrect identity for recipient block".
	identityFiles []string
}

// Guard returns the capability guard for this invocation.
//
// It is unrestricted for a binpass the user ran themselves, and carries a
// plugin's grant when binpass was invoked through BINPASS_BIN by a plugin
// that declared one. Commands consult it before touching the store.
func (a *App) Guard() *plugin.Guard {
	a.guardOnce.Do(func() {
		caps, name, restricted := plugin.ActiveCapabilities(os.Getenv)
		a.cachedGuard = plugin.NewGuard(name, caps, restricted)
	})
	return a.cachedGuard
}

// NewApp returns an App bound to the process streams.
func NewApp(cfg config.Config) *App {
	return &App{Cfg: cfg, Out: os.Stdout, Err: os.Stderr, In: os.Stdin}
}

// Store returns the password store, building it on first use so that commands
// like `version` and `help` work with no store present.
func (a *App) Store() (*store.Store, error) {
	a.storeOnce.Do(func() {
		a.cachedStore, a.storeErr = a.newStore()
	})
	return a.cachedStore, a.storeErr
}

// newStore wires the crypto backends and the store together.
func (a *App) newStore() (*store.Store, error) {
	gpg := crypto.NewGPG(a.Cfg.Dir, a.Cfg.GPGBinary, a.Cfg.GPGOpts)
	ageBackend := crypto.NewAge(a.Cfg.Dir, a.identities)
	// Only the age backend is wrapped: gpg reports its own failures, while
	// age's recipient-mismatch error names neither the identities tried nor
	// the recipients file, and that is exactly what a key migration turns
	// into guesswork.
	diag := ageDiagnostics{Crypto: ageBackend, app: a}

	// Lookup order decides which file wins when an entry exists in both
	// formats; pass's own .gpg comes first for compatibility.
	backends := []crypto.Crypto{gpg, diag}

	var def crypto.Crypto = diag
	if a.Cfg.Default == config.BackendGPG {
		def = gpg
	}
	a.gpgBackend = gpg
	a.ageBackend = diag
	return store.New(store.Options{
		Dir:      a.Cfg.Dir,
		Backends: backends,
		Default:  def,
		Umask:    a.Cfg.Umask,
	})
}

// cryptoFor returns the backend instance the store writes with, so a bulk
// reencrypt targets exactly what a fresh insert would use instead of a
// second, subtly different construction. It must be called after Store,
// which builds and records the backends; a nil result means Store failed or
// was never called, which every caller checks first.
func (a *App) cryptoFor(kind config.Backend) (crypto.Crypto, error) {
	switch kind {
	case config.BackendAge:
		return a.ageBackend, nil
	case config.BackendGPG:
		return a.gpgBackend, nil
	}
	return nil, fmt.Errorf("unknown backend %q", string(kind))
}

// identities resolves age identities on demand, so that no key file is read
// and no hardware token is woken until a decryption needs one. The files the
// keys came from are recorded, never the key material itself.
func (a *App) identities() ([]age.Identity, error) {
	r := identity.NewResolver(a.Cfg.Identity)
	r.PluginUI = identity.TerminalUI()
	sources, err := r.LoadSources()
	if err != nil {
		return nil, err
	}
	ids := make([]age.Identity, 0, len(sources))
	files := make([]string, 0, len(sources))
	for _, s := range sources {
		ids = append(ids, s.Identities...)
		files = append(files, s.Path)
	}
	a.identityMu.Lock()
	a.identityFiles = files
	a.identityMu.Unlock()
	return ids, nil
}

// triedIdentityFiles returns the paths the identities for the last decryption
// were loaded from.
func (a *App) triedIdentityFiles() []string {
	a.identityMu.Lock()
	defer a.identityMu.Unlock()
	return a.identityFiles
}

// requireStore returns the store, refusing to continue when it has not been
// initialised, with the same wording pass uses.
func (a *App) requireStore() (*store.Store, error) {
	s, err := a.Store()
	if err != nil {
		return nil, err
	}
	if !s.Initialised() {
		return nil, fmt.Errorf("Error: password store is empty. Try \"binpass init\".") //nolint:revive,staticcheck // pass's exact wording, capital and all.
	}
	return s, nil
}

// printf writes to the command's output stream.
func (a *App) printf(format string, args ...any) {
	fmt.Fprintf(a.Out, format, args...)
}
