# home-manager module for binpass.
#
# Manages the config file, the environment, shell integration, and optionally
# the tomb timer. The store itself is deliberately not managed: it is the
# user's data, it is encrypted, and a module that rewrote it would be a module
# that could lose it.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.binpass;
  yamlFormat = pkgs.formats.yaml { };

  # Only the keys binpass actually reads are emitted. Writing a setting the
  # program ignores is worse than not offering it: the user configures
  # something, nothing happens, and nothing says why.
  settingsFile = yamlFormat.generate "binpass-config.yaml" cfg.settings;

  hasSettings = cfg.settings != { };
in
{
  options.programs.binpass = {
    enable = lib.mkEnableOption "binpass, a pass(1)-compatible password manager";

    package = lib.mkPackageOption pkgs "binpass" { };

    passPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.binpass-pass or (pkgs.callPackage ../nix/pass-shim.nix { binpass = cfg.package; });
      defaultText = lib.literalExpression "pkgs.binpass-pass";
      description = ''
        The package installed when `replacePass` is on: binpass under the
        name `pass`, with completions generated for that name.
      '';
    };

    storeDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "~/.local/share/password-store";
      description = ''
        Password store directory. Sets both `PASSWORD_STORE_DIR` and
        `BINPASS_DIR`, so pass-era scripts and binpass agree on where the
        store is.

        Left null, binpass uses `~/.password-store`, the same default as pass.
      '';
    };

    identityFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "~/.local/share/binpass/identities.age";
      description = ''
        age identity file, exported as `BINPASS_IDENTITY`.

        This names a path; it does not place a key there. Putting a private
        key in the Nix store would make it world-readable, so the file has to
        be provisioned by something that keeps secrets out of the store, such
        as agenix, sops-nix, or your own hands.
      '';
    };

    settings = lib.mkOption {
      type = yamlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          store.dir = "~/.password-store";
          crypto.default = "age";
          clip.timeout = "45s";
          generate.length = 25;
          sync = {
            auto = "off";
            conflict = "keep-both";
            default_remote = "origin";
            remotes.origin = {
              type = "git";
              url = "git@github.com:you/password-store.git";
            };
          };
        }
      '';
      description = ''
        Contents of `~/.config/binpass/config.yaml`.

        Secrets do not belong here: everything in this attribute set is
        written to the Nix store, which is readable by every user on the
        machine. For a restic repository password use
        `sync.remotes.<name>.password_command` and have it read from
        somewhere else.
      '';
    };

    replacePass = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Install a `pass` executable that runs binpass.

        binpass implements pass's command surface and uses the same store
        format, so scripts, browser extensions, and anything else calling
        `pass` keep working. It is off by default because shadowing a command
        the user did not ask to have shadowed is not a decision a module
        should make quietly.

        This conflicts with `programs.password-store.enable`; enabling both
        puts two `pass` binaries in one profile.
      '';
    };

    enableBashIntegration = lib.mkEnableOption "Bash completion" // {
      default = true;
    };
    enableZshIntegration = lib.mkEnableOption "Zsh completion" // {
      default = true;
    };
    enableFishIntegration = lib.mkEnableOption "Fish completion" // {
      default = true;
    };

    secretService = {
      enable = lib.mkEnableOption ''
        the Secret Service provider, so that programs using the system
        keyring read their secrets from the password store
      '';

      takeover = lib.mkOption {
        type = lib.types.enum [
          "refuse"
          "wait"
          "replace"
        ];
        default = "refuse";
        description = ''
          What to do when another program already owns
          `org.freedesktop.secrets`.

          Only one provider can hold that name, and the usual holder is
          gnome-keyring. `refuse` leaves it alone and fails, which is the
          safe default: two providers taking turns would mean secrets stored
          in one and looked up in the other. Mask the competitor instead —
          `binpass ss doctor` prints the commands.
        '';
      };
    };

    tomb = {
      enable = lib.mkEnableOption ''
        a user service that opens the tomb on login and closes it on logout
      '';

      timer = lib.mkOption {
        type = lib.types.str;
        default = "1h";
        example = "30m";
        description = ''
          Auto-close timeout passed to `binpass tomb open --timer`.

          The value of a tomb is bounded by how long it stays open, so this is
          not merely a convenience: a tomb open all day protects only the
          hours you are not logged in.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.replacePass && (config.programs.password-store.enable or false));
        message = ''
          programs.binpass.replacePass and programs.password-store.enable both
          install a `pass` binary into the same profile. Enable one.
        '';
      }
    ];

    home.packages = [
      cfg.package
    ]
    ++ lib.optional cfg.replacePass cfg.passPackage;

    xdg.configFile."binpass/config.yaml" = lib.mkIf hasSettings {
      source = settingsFile;
    };

    home.sessionVariables =
      lib.optionalAttrs (cfg.storeDir != null) {
        # Both names, because a store is shared with anything pass-era the
        # user still runs.
        PASSWORD_STORE_DIR = cfg.storeDir;
        BINPASS_DIR = cfg.storeDir;
      }
      // lib.optionalAttrs (cfg.identityFile != null) {
        BINPASS_IDENTITY = cfg.identityFile;
      };

    # The package ships completions in the standard locations; these only
    # matter for shells whose completion path home-manager manages.
    programs.bash.enable = lib.mkIf cfg.enableBashIntegration (lib.mkDefault true);
    programs.zsh.enable = lib.mkIf cfg.enableZshIntegration (lib.mkDefault true);
    programs.fish.enable = lib.mkIf cfg.enableFishIntegration (lib.mkDefault true);

    systemd.user.services.binpass-ss = lib.mkIf (cfg.secretService.enable && pkgs.stdenv.isLinux) {
      Unit = {
        Description = "binpass Secret Service provider";
        Documentation = "https://github.com/71g3pf4c3/binpass/blob/main/docs/secret-service.md";
        # Not "After": only one of the two can own the name, so they must not
        # both be running.
        Conflicts = [ "gnome-keyring-daemon.service" ];
        After = [ "dbus.socket" ];
        Requires = [ "dbus.socket" ];
      };

      Service = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} ss serve --takeover=${cfg.secretService.takeover}";
        Restart = "on-failure";
        RestartSec = 2;
      };

      Install.WantedBy = [ "default.target" ];
    };

    systemd.user.services.binpass-tomb = lib.mkIf (cfg.tomb.enable && pkgs.stdenv.isLinux) {
      Unit = {
        Description = "binpass tomb";
        Documentation = "https://github.com/71g3pf4c3/binpass/blob/main/docs/tomb.md";
      };

      Service = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} tomb open --timer=${cfg.tomb.timer}";
        # Without this, ending a session leaves the store extracted on disk
        # with nothing recording that it happened. The whole point of a tomb
        # is that it closes.
        ExecStop = "${lib.getExe cfg.package} tomb close";
        RemainAfterExit = true;
        Restart = "no";
      };

      Install.WantedBy = [ "default.target" ];
    };
  };
}
