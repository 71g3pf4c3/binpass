package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/71g3pf4c3/binpass/internal/config"
	"golang.org/x/term"
)

// rcloneBackends maps the binpass remote types that need OAuth to the
// rclone backend that implements it.
var rcloneBackends = map[string]string{
	"gdrive": "drive",
	"yandex": "yandex",
}

// rcloneSetup is the machinery behind ensureRcloneAuth, with every command
// execution as a function so the flow is testable without a browser.
type rcloneSetup struct {
	// listRemotes runs `rclone listremotes` and returns the remote names,
	// colon and all, one per line.
	listRemotes func() ([]string, error)
	// auth runs `rclone config create <name> <backend>`, which performs
	// the OAuth dance on a terminal: browser, redirect, token into
	// rclone's own config.
	auth func(backend, name string) error
	// interactive reports whether the user can be walked through a
	// browser flow on this machine.
	interactive func() bool
}

// ensureRcloneAuth makes sure the rclone remote backing a gdrive or yandex
// remote exists before it is saved. rclone already knows how to do OAuth —
// its client, its browser flow, its token store in rclone.conf — and the
// sync reads that same config, so driving rclone is one source of truth for
// the token instead of binpass growing its own OAuth client, app
// registration and refresh logic next to rclone's.
//
// Missing rclone or a broken invocation is not an error here: the remote is
// still saved, and the next sync surfaces rclone's own diagnostics, which
// say more about what is missing than a second-hand guess would.
func (a *App) ensureRcloneAuth(rc config.RemoteConfig) error {
	backend, needs := rcloneBackends[rc.Type]
	if !needs {
		return nil
	}
	name, _, found := strings.Cut(rc.URL, ":")
	if !found || name == "" {
		return nil // no rclone remote named in the URL; the sync will say so
	}

	interactive := func() bool {
		f, ok := a.In.(interface{ Fd() uintptr })
		return ok && term.IsTerminal(int(f.Fd()))
	}
	setup := rcloneSetup{
		listRemotes: func() ([]string, error) { return rcloneListRemotes() },
		auth: func(backend, name string) error {
			// Wired to the process streams: rclone opens the browser
			// itself and prints where it is waiting.
			cmd := exec.Command("rclone", "config", "create", name, backend) //nolint:gosec // fixed program, fixed arguments.
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return cmd.Run()
		},
		interactive: interactive,
	}
	return setup.ensure(backend, name, a.Out, a.Err)
}

// ensure checks and, if need be, performs the OAuth handshake. It reports
// errors only from the handshake itself; a remote that already exists, a
// headless machine, an absent rclone — all are handled, not failed.
func (s rcloneSetup) ensure(backend, name string, out, errOut io.Writer) error {
	remotes, err := s.listRemotes()
	if err != nil {
		return nil // rclone will complain with better words at sync time
	}
	for _, r := range remotes {
		if strings.TrimSuffix(r, ":") == name {
			return nil // already authorised; nothing to do
		}
	}

	if !s.interactive() {
		fmt.Fprintf(out, "The rclone remote %q is not authorised yet, and this machine has no terminal to run a browser flow on.\n", name)
		fmt.Fprintf(out, "Authorise on a machine with a browser:\n\n")
		fmt.Fprintf(out, "  rclone authorize %q\n\n", backend)
		fmt.Fprintf(out, "It prints a token in JSON braces. Then finish here:\n\n")
		fmt.Fprintf(out, "  rclone config create %s %s token='<paste the token here>'\n", name, backend)
		fmt.Fprintf(out, "\nThe remote is saved; `binpass sync` will work once the token is in place.\n")
		return nil
	}

	fmt.Fprintf(out, "The rclone remote %q is not authorised yet. rclone will open a browser for %s OAuth.\n", name, backend)
	if err := s.auth(backend, name); err != nil {
		fmt.Fprintf(errOut, "Authorisation did not complete; the remote is saved anyway.\n")
		return fmt.Errorf("remote add: rclone OAuth for %q: %w", name, err)
	}
	fmt.Fprintf(out, "Token saved in rclone's own config.\n")
	return nil
}

// rcloneListRemotes runs `rclone listremotes` and returns its lines.
func rcloneListRemotes() ([]string, error) {
	out, err := exec.Command("rclone", "listremotes").Output() //nolint:gosec // fixed program, no arguments.
	if err != nil {
		return nil, err
	}
	var remotes []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			remotes = append(remotes, line)
		}
	}
	return remotes, nil
}
