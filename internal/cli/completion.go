package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newCompletionCmd builds `binpass completion`.
func newCompletionCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion bash|zsh|fish|powershell",
		Short: "Generate a shell completion script",
		Long: `Generate a shell completion script for binpass.

Entry names are completed from the store, so tab-completion works on the
password tree itself, not just on flags. Listing the store needs no key, so
completion never triggers a decryption or a hardware token prompt.

  bash:  source <(binpass completion bash)
  zsh:   binpass completion zsh > "${fpath[1]}/_binpass"
  fish:  binpass completion fish > ~/.config/fish/completions/binpass.fish
  pwsh:  binpass completion powershell | Out-String | Invoke-Expression`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(app.Out, true)
			case "zsh":
				return root.GenZshCompletion(app.Out)
			case "fish":
				return root.GenFishCompletion(app.Out, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(app.Out)
			default:
				return fmt.Errorf("binpass: unsupported shell %q", args[0])
			}
		},
	}
	return cmd
}

// completeEntries completes an argument with entry names from the store. It
// is deliberately silent on error: a broken or locked store should produce no
// suggestions rather than an error message in the middle of the command line.
func (a *App) completeEntries(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	s, err := a.Store()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names, err := s.List("")
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return filterPrefix(names, toComplete), cobra.ShellCompDirectiveNoFileComp
}

// completeRootArg completes the bare `binpass <tab>` position, where both a
// plugin command and an entry name are valid.
//
// Plugins are offered first and described as such, so that a plugin does not
// look like a password that has mysteriously appeared in the store.
func (a *App) completeRootArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, c := range a.pluginSource().Candidates(builtinNames(cmd.Root())) {
		if c.Usable() {
			out = append(out, c.Name+"\tplugin")
		}
	}
	entries, directive := a.completeEntriesAndDirs(cmd, args, toComplete)
	return append(out, entries...), directive
}

// completeEntriesAndDirs completes with entries and the subfolders holding
// them, for commands like mv, cp and ls that accept either.
func (a *App) completeEntriesAndDirs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	names, directive := a.completeEntries(cmd, nil, toComplete)
	if len(args) > 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	seen := map[string]bool{}
	out := append([]string{}, names...)
	for _, n := range names {
		for i, c := range n {
			if c == '/' {
				if dir := n[:i]; !seen[dir] {
					seen[dir] = true
					out = append(out, dir+"/")
				}
			}
		}
	}
	return filterPrefix(out, toComplete), directive
}

// filterPrefix keeps the candidates matching what the user has typed. Cobra
// filters too, but doing it here keeps the emitted list small for large stores.
func filterPrefix(candidates []string, prefix string) []string {
	if prefix == "" {
		return candidates
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if len(c) >= len(prefix) && c[:len(prefix)] == prefix {
			out = append(out, c)
		}
	}
	return out
}
