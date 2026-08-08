package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// newListCmd builds `binpass ls`.
func newListCmd(app *App) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:     "ls [subfolder]",
		Aliases: []string{"list"},
		Short:   "List passwords",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sub string
			if len(args) > 0 {
				sub = args[0]
			}
			if format != "tree" {
				return app.runListFormatted(sub, format)
			}
			return app.runList(cmd.Context(), sub)
		},
	}
	// The default stays the tree pass prints; plain and json exist so that
	// scripts and pickers never have to parse box-drawing characters.
	cmd.Flags().StringVar(&format, "format", "tree", "output format: tree|plain|json")
	return cmd
}

// runListFormatted prints entry names in a machine-readable shape.
func (a *App) runListFormatted(sub, format string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	names, err := s.List(sub)
	if err != nil {
		return err
	}
	switch format {
	case "plain":
		for _, n := range names {
			fmt.Fprintln(a.Out, n)
		}
		return nil
	case "json":
		if names == nil {
			names = []string{}
		}
		enc := json.NewEncoder(a.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(names)
	default:
		return fmt.Errorf("binpass: unknown format %q", format)
	}
}

// runList prints the tree of entries under sub.
func (a *App) runList(_ context.Context, sub string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	names, err := s.List(sub)
	if err != nil {
		return err
	}

	heading := "Password Store"
	if sub != "" {
		heading = strings.TrimSuffix(sub, "/")
		// Names are printed relative to the listed subfolder, as tree(1)
		// descends into it rather than repeating the path.
		prefix := heading + "/"
		for i, n := range names {
			names[i] = strings.TrimPrefix(n, prefix)
		}
	}
	return renderTree(a.Out, heading, names)
}

// newFindCmd builds `binpass find`.
func newFindCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:     "find pass-names...",
		Aliases: []string{"search"},
		Short:   "List passwords that match pass-names",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runFind(cmd.Context(), args)
		},
	}
}

// runFind prints the entries whose path matches any of the terms. pass renders
// this as a pruned tree preceded by the search terms.
func (a *App) runFind(_ context.Context, terms []string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	names, err := s.Find(terms)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Search Terms: %s\n", strings.Join(terms, ","))
	return renderTree(a.Out, "", names)
}
