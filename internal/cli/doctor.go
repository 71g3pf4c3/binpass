package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/identity"
	"github.com/71g3pf4c3/binpass/pkg/tomb"
	"github.com/71g3pf4c3/binpass/pkg/typer"
	"github.com/spf13/cobra"
)

// newDoctorCmd builds `binpass doctor`, which runs health checks and prints
// a diagnostic report.
func newDoctorCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks and show diagnostics",
		Long: `Run health checks for the password store environment:

  - Typing: which tool would be picked in this session, and why
  - Clipboard: which backend detects in this session, and why the others do not
  - Identities: which age identity files load, and whether they match the store
  - Store: backend mix and the recipients files
  - Tomb watcher capabilities (D-Bus screen lock, suspend, timer)
  - Stale state detection (crash recovery)

This is a read-only diagnostic command; it does not modify the store,
decrypt any entry, or touch a hardware token. Everything it prints is
derived without secrets: paths, counts and tool names only.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runDoctor()
		},
	}
}

// runDoctor prints one section per integration. Every section is
// self-contained: a failing one prints FAIL and the report continues,
// because a doctor that stopped at the first problem would hide the rest
// of the picture.
func (a *App) runDoctor() error {
	a.doctorTyping()
	a.doctorClipboard()
	a.doctorIdentities()
	a.doctorStore()
	a.doctorTomb()
	return nil
}

// doctorTyping reports which typing backend `binpass type` and the menu
// would use in this session: the autodetected pick with its reasons, and
// the override from typer.tool / BINPASS_TYPER_TOOL when one is set.
func (a *App) doctorTyping() {
	reports, picked := typer.Report()

	verdict, summary := "OK", picked
	if picked == "" {
		verdict = "FAIL"
		summary = "no typing tool works in this session (install wtype, xdotool or ydotool)"
	}

	explicit := a.Cfg.TyperTool != "" && a.Cfg.TyperTool != typer.ToolAuto
	if explicit {
		name, err := typer.ParseTool(a.Cfg.TyperTool)
		switch {
		case err != nil:
			verdict, summary = "FAIL", fmt.Sprintf("configured tool %q is unknown", a.Cfg.TyperTool)
		case !toolInstalled(reports, name):
			verdict, summary = "FAIL", fmt.Sprintf("configured tool %s is not on PATH", name)
		default:
			verdict, summary = "OK", name+" (tool override)"
		}
	}

	a.printf("[typing] %s: %s\n", verdict, summary)
	for _, r := range reports {
		a.printf("  %s: %s\n", r.Name, toolReason(r, r.Name == picked))
	}
	switch {
	case a.Cfg.TyperTool == "":
		a.printf("  tool override: none\n")
	case !explicit:
		a.printf("  tool override: auto (session detection)\n")
	default:
		a.printf("  tool override: %s\n", a.Cfg.TyperTool)
		if verdict == "OK" && picked != "" && picked != a.Cfg.TyperTool {
			a.printf("  autodetection would pick: %s\n", picked)
		}
	}
	if picked == "ydotool" {
		// Presence on PATH is all doctor can check; whether the daemon
		// answers only a real keystroke would prove.
		a.printf("  note: ydotool needs its daemon running; doctor cannot verify it\n")
	}
}

// toolReason explains one typing backend's state: the positive form for
// the tool autodetection picked, and the blocking reasons for the rest.
func toolReason(r typer.ToolReport, selected bool) string {
	if selected {
		gate := "no session gate"
		if r.RequiresEnv != "" {
			gate = r.RequiresEnv + " set"
		}
		return fmt.Sprintf("selected (%s, on PATH)", gate)
	}
	var why []string
	if r.RequiresEnv != "" && !r.EnvSet {
		why = append(why, r.RequiresEnv+" not set")
	}
	if !r.Installed {
		why = append(why, "not on PATH")
	}
	if len(why) == 0 {
		return "available"
	}
	return strings.Join(why, ", ")
}

// toolInstalled reports whether the named backend is on PATH, according to
// a Report taken in the same session.
func toolInstalled(reports []typer.ToolReport, name string) bool {
	for _, r := range reports {
		if r.Name == name {
			return r.Installed
		}
	}
	return false
}

// doctorClipboard reports which clipboard backend `binpass show --clip`
// would detect in this session, and what keeps each of the others down.
func (a *App) doctorClipboard() {
	reports := clip.Reports(a.Cfg.XSelection)
	detected := ""
	for _, r := range reports {
		if r.Available {
			detected = r.Name
			break
		}
	}

	verdict, summary := "OK", detected
	if detected == "" {
		verdict = "FAIL"
		summary = "no clipboard backend works in this session (install wl-clipboard, xclip, xsel or pbcopy)"
	}

	a.printf("[clipboard] %s: %s\n", verdict, summary)
	for _, r := range reports {
		if r.Available {
			if r.Name == detected {
				a.printf("  %s: detected\n", r.Name)
			} else {
				a.printf("  %s: available\n", r.Name)
			}
			continue
		}
		a.printf("  %s: unavailable (%s)\n", r.Name, strings.Join(r.Missing, ", "))
	}
}

// doctorIdentities reports which age identity sources load, how many
// identities each yields, and whether those identities decrypt a probe
// encrypted to the store's recipients — proving the key and the store
// match without decrypting a single entry.
//
// Plugin identities are counted but never probed: unwrapping with one
// means running the age-plugin binary and touching a hardware token, which
// a read-only doctor must not do.
func (a *App) doctorIdentities() {
	r := identity.NewResolver(a.Cfg.Identity)
	sources, err := r.LoadSources()
	if err != nil {
		a.printf("[identities] FAIL: %s\n", indentDetail(err.Error()))
		return
	}

	verdict := "OK"
	probe, probeOK := a.identityProbe(sources)
	if !probeOK {
		verdict = "FAIL"
	}

	total := 0
	for _, s := range sources {
		total += len(s.Identities)
	}
	summary := plural(total, "identity") + " from " + plural(len(sources), "source")
	if !probeOK {
		// A FAIL verdict must not read as "identities loaded, all
		// good": the probe is what failed, and the line says so.
		summary = "the identity probe failed"
	}
	a.printf("[identities] %s: %s\n", verdict, summary)
	for _, s := range sources {
		note := string(s.Kind)
		if r.Explicit != "" {
			note += ", explicit"
		}
		a.printf("  %s: %s (%s)\n", s.Path, plural(len(s.Identities), "identity"), note)
	}
	a.printf("  %s\n", probe)
}

// probePlaintext is what the identity probe encrypts and decrypts. It is a
// constant, not a secret: its only job is to make the age round trip real.
const probePlaintext = "binpass doctor probe"

// identityProbe encrypts a constant to the store's age recipients and
// checks the loaded identities can decrypt it. It returns the line to
// print and whether the outcome is a failure. Skipping is not failing: a
// store without age recipients or an identity set of plugins only leaves
// the question open rather than answered badly.
func (a *App) identityProbe(sources []identity.Source) (string, bool) {
	var ids []age.Identity
	pluginIDs := 0
	for _, s := range sources {
		for _, id := range s.Identities {
			if _, ok := id.(*age.X25519Identity); ok {
				ids = append(ids, id)
			} else {
				pluginIDs++
			}
		}
	}
	if len(ids) == 0 {
		return "probe: skipped (only plugin identities; hardware tokens are not touched)", true
	}

	backend := crypto.NewAge(a.Cfg.Dir, nil)
	rcp, err := backend.ParseRecipients(a.Cfg.Dir)
	if err != nil {
		return "probe: skipped (no .age-recipients in the store)", true
	}
	parsed, err := crypto.ParseAgeRecipients(rcp)
	if err != nil {
		return fmt.Sprintf("probe: FAIL (cannot use the store's .age-recipients: %v)", err), false
	}

	// Plugin recipients are filtered out: encrypting to one runs the
	// plugin binary, which doctor does not do.
	var statics []age.Recipient
	for _, rc := range parsed {
		if _, ok := rc.(*plugin.Recipient); ok {
			continue
		}
		statics = append(statics, rc)
	}
	if len(statics) == 0 {
		return "probe: skipped (only plugin recipients in .age-recipients)", true
	}

	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, statics...)
	if err != nil {
		return fmt.Sprintf("probe: FAIL (encrypting to the store's recipients: %v)", err), false
	}
	if _, err := w.Write([]byte(probePlaintext)); err != nil {
		return fmt.Sprintf("probe: FAIL (encrypting to the store's recipients: %v)", err), false
	}
	if err := w.Close(); err != nil {
		return fmt.Sprintf("probe: FAIL (encrypting to the store's recipients: %v)", err), false
	}

	dr, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), ids...)
	if err != nil {
		if errors.Is(err, age.ErrIncorrectIdentity) {
			line := fmt.Sprintf("probe: FAIL (none of the %d probed identities decrypt data "+
				"encrypted to the store's .age-recipients; the key and the store do not match)", len(ids))
			if pluginIDs > 0 {
				line += fmt.Sprintf(" (%d plugin identities were not probed)", pluginIDs)
			}
			return line, false
		}
		return fmt.Sprintf("probe: FAIL (%v)", err), false
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		return fmt.Sprintf("probe: FAIL (%v)", err), false
	}
	if string(plain) != probePlaintext {
		return "probe: FAIL (the probe decrypted to the wrong plaintext)", false
	}
	return "probe: OK (an identity decrypts data encrypted to the store's recipients)", true
}

// doctorStore reports the store's shape: how many entries each crypto
// backend holds, and which recipients files are present.
func (a *App) doctorStore() {
	dir := a.Cfg.Dir
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		a.printf("[store] FAIL: store directory %s does not exist\n", dir)
		return
	}

	ageEntries, gpgEntries := 0, 0
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a doctor reports what it can read, not what it cannot.
		}
		switch filepath.Ext(d.Name()) {
		case crypto.AgeExt:
			ageEntries++
		case crypto.GPGExt:
			gpgEntries++
		}
		return nil
	})
	recipients, hasAgeRcp := countRecipients(filepath.Join(dir, crypto.AgeRecipientsFile))
	_, hasGpgID := os.Stat(filepath.Join(dir, crypto.GPGRecipientsFile))

	if !hasAgeRcp && hasGpgID != nil {
		a.printf("[store] FAIL: not initialised (no .age-recipients and no .gpg-id at the store root)\n")
	} else {
		a.printf("[store] OK: initialised\n")
	}
	a.printf("  entries: %s, %s\n", plural(ageEntries, ".age entry"), plural(gpgEntries, ".gpg entry"))
	if hasAgeRcp {
		a.printf("  .age-recipients: present, %s\n", plural(recipients, "recipient"))
	} else {
		a.printf("  .age-recipients: absent\n")
	}
	if hasGpgID == nil {
		a.printf("  .gpg-id: present\n")
	} else {
		a.printf("  .gpg-id: absent\n")
	}
}

// doctorTomb reports the tomb watcher's capabilities and state. It keeps
// the wording the original doctor had: it is informational, not a verdict.
func (a *App) doctorTomb() {
	fmt.Fprintf(a.Out, "[tomb] %s\n", tomb.DoctorCheck())

	st, err := tomb.SelectBackend(tomb.BackendCoffin)
	if err != nil {
		fmt.Fprintf(a.Err, "[tomb] error selecting backend: %v\n", err)
		return
	}
	state, isOpen, err := st.Status(a.Cfg.Dir)
	if err != nil {
		fmt.Fprintf(a.Err, "[tomb] error reading state: %v\n", err)
		return
	}
	if state.Backend == "" {
		fmt.Fprintf(a.Out, "[tomb] not initialised\n")
		return
	}
	if state.IsStale() {
		fmt.Fprintf(a.Out, "[tomb] stale state detected (PID %d is dead, tomb was not closed cleanly)\n", state.PID)
	} else if isOpen {
		fmt.Fprintf(a.Out, "[tomb] open (backend: %s, PID: %d)\n", state.Backend, state.PID)
	} else {
		fmt.Fprintf(a.Out, "[tomb] closed (backend: %s)\n", state.Backend)
	}
}

// countRecipients counts the recipient lines in an age recipients file:
// blank lines and '#' comments ignored, as readRecipientsFile does, but
// without failing on a line that does not parse — that is the probe's job.
func countRecipients(path string) (n int, ok bool) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is built from the store root.
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n, true
}

// indentDetail shifts every line but the first two spaces right, so a
// multi-line diagnostic (the resolver's "searched:" list) stays readable
// under its section header.
func indentDetail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := 1; i < len(lines); i++ {
		lines[i] = "  " + lines[i]
	}
	return strings.Join(lines, "\n")
}

// plural renders "1 identity" and "2 identities" from n and the singular.
// Words ending in y switch to ies, which covers every noun doctor prints.
func plural(n int, singular string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	if strings.HasSuffix(singular, "y") {
		singular = strings.TrimSuffix(singular, "y") + "ie"
	}
	return fmt.Sprintf("%d %ss", n, singular)
}
