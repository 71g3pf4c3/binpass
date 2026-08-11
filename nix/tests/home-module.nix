# Evaluate the home-manager module against the real option system.
#
# A module is a program, and one that only runs inside someone else's
# configuration is one nobody finds out is broken until they try it. This
# builds the module's outputs — the config file, the environment, the tomb
# unit — and asserts on them, without needing home-manager as a flake input.
{
  lib,
  runCommand,
  binpass ? null,
  module,
  overlay,
  pkgs,
}:
let
  # A minimal stand-in for the parts of home-manager the module touches. The
  # real thing brings a large dependency tree for what amounts to a handful of
  # option declarations.
  stubModule =
    { lib, ... }:
    {
      options = {
        assertions = lib.mkOption {
          type = lib.types.listOf lib.types.unspecified;
          default = [ ];
        };
        home.packages = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
        };
        home.sessionVariables = lib.mkOption {
          type = lib.types.attrsOf (
            lib.types.oneOf [
              lib.types.str
              lib.types.int
              lib.types.path
            ]
          );
          default = { };
        };
        xdg.configFile = lib.mkOption {
          type = lib.types.attrsOf (
            lib.types.submodule {
              options = {
                source = lib.mkOption {
                  type = lib.types.path;
                };
                text = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                };
              };
            }
          );
          default = { };
        };
        programs.bash.enable = lib.mkEnableOption "bash";
        programs.zsh.enable = lib.mkEnableOption "zsh";
        programs.fish.enable = lib.mkEnableOption "fish";
        programs.password-store.enable = lib.mkEnableOption "password-store";
        systemd.user.services = lib.mkOption {
          type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
          default = { };
        };
      };
    };

  evalWith =
    settings:
    (lib.evalModules {
      modules = [
        stubModule
        module
        {
          _module.args.pkgs = pkgs.extend overlay;
          programs.binpass = settings;
        }
      ];
    }).config;

  # A configuration exercising every option that produces output.
  full = evalWith {
    enable = true;
    storeDir = "/home/tester/.password-store";
    identityFile = "/home/tester/.local/share/binpass/identities.age";
    replacePass = true;
    tomb = {
      enable = true;
      timer = "30m";
    };
    settings = {
      store.dir = "/home/tester/.password-store";
      crypto.default = "age";
      generate.length = 25;
      sync = {
        auto = "off";
        conflict = "keep-both";
        default_remote = "origin";
      };
    };
  };

  # The default case: enabled and otherwise untouched.
  minimal = evalWith { enable = true; };

  configYaml = full.xdg.configFile."binpass/config.yaml".source;
  tombService = full.systemd.user.services.binpass-tomb;
in
runCommand "binpass-home-module-test"
  {
    inherit configYaml;
    passAsFile = [ "checks" ];
    checks = ''
      # The generated config must be the YAML binpass parses, with the keys
      # it actually reads.
      grep -q 'dir: /home/tester/.password-store' "$configYaml"
      grep -q 'default: age' "$configYaml"
      grep -q 'length: 25' "$configYaml"
      grep -q 'default_remote: origin' "$configYaml"
      grep -q 'conflict: keep-both' "$configYaml"
    '';

    storeDirVar = full.home.sessionVariables.PASSWORD_STORE_DIR or "";
    binpassDirVar = full.home.sessionVariables.BINPASS_DIR or "";
    identityVar = full.home.sessionVariables.BINPASS_IDENTITY or "";
    # replacePass must install something that really answers to `pass`, not
    # an alias that reports itself as binpass.
    passShim = lib.head (lib.filter (p: (p.meta.mainProgram or "") == "pass") full.home.packages);

    tombStart = tombService.Service.ExecStart;
    tombStop = tombService.Service.ExecStop;
    packageCount = builtins.length full.home.packages;

    # With no settings there must be no config file: writing an empty one
    # would override defaults with nothing and look deliberate.
    minimalHasConfig = if minimal.xdg.configFile ? "binpass/config.yaml" then "yes" else "no";
    minimalPackageCount = builtins.length minimal.home.packages;
  }
  ''
    set -eu
    bash "$checksPath"

    # A store directory must reach both names: pass-era tools read one,
    # binpass prefers the other, and setting only one splits the store in two.
    [ "$storeDirVar" = "/home/tester/.password-store" ]
    [ "$binpassDirVar" = "/home/tester/.password-store" ]
    [ "$identityVar" = "/home/tester/.local/share/binpass/identities.age" ]

    # replacePass adds the shim beside binpass itself.
    [ "$packageCount" = "2" ]
    [ -x "$passShim/bin/pass" ]
    # The completion has to be named for the command it completes: one
    # generated as binpass and installed as pass completes nothing.
    grep -q '__start_pass' "$passShim/share/bash-completion/completions/pass"
    [ -e "$passShim/share/zsh/site-functions/_pass" ]
    # And the binary must present itself as pass, or `pass --help` documents
    # a command the user did not type.
    "$passShim/bin/pass" --help | grep -q 'pass \[flags\]'
    [ "$minimalPackageCount" = "1" ]
    [ "$minimalHasConfig" = "no" ]

    # The tomb unit must close on stop. Without ExecStop, logging out leaves
    # the store extracted on disk, which is the failure the tomb exists to
    # prevent.
    case "$tombStart" in *"tomb open --timer=30m") ;; *) echo "bad ExecStart: $tombStart"; exit 1 ;; esac
    case "$tombStop"  in *"tomb close")           ;; *) echo "bad ExecStop: $tombStop";   exit 1 ;; esac

    touch "$out"
  ''
