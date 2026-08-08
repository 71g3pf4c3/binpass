package identity

import (
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// PluginUI drives the prompts an age plugin raises: PIN entry, touch requests
// and progress messages. A nil value means "use the terminal".
type PluginUI = *plugin.ClientUI

// TerminalUI returns a PluginUI that prompts on the terminal and writes all
// messages to stderr, keeping a piped secret on stdout clean.
func TerminalUI() PluginUI {
	toStderr := func(format string, v ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", v...)
	}
	return plugin.NewTerminalUI(toStderr, toStderr)
}

// newPluginIdentity resolves an AGE-PLUGIN-* line to an identity served by the
// corresponding age-plugin-* binary on PATH. The binary is not executed here:
// it is spawned only when a decryption needs it, so listing a store never
// makes a YubiKey blink.
func newPluginIdentity(line string, ui PluginUI) (age.Identity, error) {
	if ui == nil {
		ui = TerminalUI()
	}
	id, err := plugin.NewIdentity(line, ui)
	if err != nil {
		return nil, err
	}
	return id, nil
}
