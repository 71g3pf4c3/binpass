package crypto

import (
	"fmt"
	"os"
	"sync"

	"filippo.io/age/plugin"
)

// pluginUIOnce guards lazy construction of the shared plugin UI.
var pluginUIOnce sync.Once

// sharedPluginUI is the terminal UI age plugins prompt through.
var sharedPluginUI *plugin.ClientUI

// pluginUI returns the terminal UI used to drive age-plugin-* binaries.
// Prompts and progress messages go to stderr so that piping a secret into
// another program stays clean.
func pluginUI() *plugin.ClientUI {
	pluginUIOnce.Do(func() {
		toStderr := func(format string, v ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", v...)
		}
		sharedPluginUI = plugin.NewTerminalUI(toStderr, toStderr)
	})
	return sharedPluginUI
}
