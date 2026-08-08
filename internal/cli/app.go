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
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/identity"
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

	// storeOnce guards lazy store construction.
	storeOnce sync.Once
	// cachedStore is the store built on first use.
	cachedStore *store.Store
	// storeErr is the error from building the store, if any.
	storeErr error
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

	// Lookup order decides which file wins when an entry exists in both
	// formats; pass's own .gpg comes first for compatibility.
	backends := []crypto.Crypto{gpg, ageBackend}

	var def crypto.Crypto = ageBackend
	if a.Cfg.Default == config.BackendGPG {
		def = gpg
	}
	return store.New(store.Options{
		Dir:      a.Cfg.Dir,
		Backends: backends,
		Default:  def,
		Umask:    a.Cfg.Umask,
	})
}

// identities resolves age identities on demand, so that no key file is read
// and no hardware token is woken until a decryption needs one.
func (a *App) identities() ([]age.Identity, error) {
	r := identity.NewResolver(a.Cfg.Identity)
	r.PluginUI = identity.TerminalUI()
	return r.Load()
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
