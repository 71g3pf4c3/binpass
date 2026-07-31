// Command binpassd is the binpass synchronisation server: authentication,
// end-to-end-encrypted vault storage, and multi-device sync over gRPC + REST.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/71g3pf4c3/binpass/server/config"
	"github.com/71g3pf4c3/binpass/server/internal/app"
)

// Build metadata, injected via -ldflags.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds the binpassd cobra command tree.
func newRootCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:           "binpassd",
		Short:         "binpass synchronisation server",
		Long:          "binpassd is the binpass sync server: auth, E2E-encrypted vault storage, and multi-device sync over gRPC + REST.",
		Version:       fmt.Sprintf("%s (commit %s, built %s)", version, commit, buildDate),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := config.NewViper(configPath)
			if err := bindFlags(v, cmd.Flags()); err != nil {
				return err
			}

			cfg, err := config.LoadFromViper(v)
			if err != nil {
				fmt.Fprintln(os.Stderr, "binpassd: config:", err)
				return err
			}
			cfg.App.Version = version

			if err := app.Run(cfg); err != nil {
				fmt.Fprintln(os.Stderr, "binpassd:", err)
				return err
			}
			return nil
		},
	}

	cmd.SetVersionTemplate("binpassd {{.Version}}\n")

	f := cmd.Flags()
	f.StringVarP(&configPath, "config", "c", "", "path to config.yaml")
	f.String("http-port", "", "HTTP/REST listen port")
	f.String("grpc-port", "", "gRPC listen port")
	f.String("blob-driver", "", "blob store driver (fs or s3)")
	f.String("blob-fs-path", "", "blob directory for the fs driver")
	f.String("log-level", "", "log level (debug, info, warn, error)")
	f.String("log-format", "", "log format (json or text)")

	return cmd
}

// flagToKey maps a command-line flag name to its config (viper) key.
var flagToKey = map[string]string{
	"http-port":    "http.port",
	"grpc-port":    "grpc.port",
	"blob-driver":  "blob.driver",
	"blob-fs-path": "blob.fs_path",
	"log-level":    "log.level",
	"log-format":   "log.format",
}

// bindFlags binds the explicitly-set command-line flags into viper so that
// flags take precedence over ENV and the config file.
func bindFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	var bindErr error
	flags.Visit(func(f *pflag.Flag) {
		key, ok := flagToKey[f.Name]
		if !ok {
			return
		}
		if err := v.BindPFlag(key, f); err != nil {
			bindErr = err
		}
	})
	return bindErr
}
