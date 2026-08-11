# NixOS module for binpass.
#
# System-wide installation, optional replacement of pass(1), and the polkit
# rule the LUKS tomb needs. Per-user settings belong in the home-manager
# module: a password store is one user's data, and a system module writing
# into a home directory is a system module that fights with whatever else
# manages it.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.binpass;

  passShim = cfg.passPackage;
in
{
  options.programs.binpass = {
    enable = lib.mkEnableOption "binpass, a pass(1)-compatible password manager";

    package = lib.mkOption {
      type = lib.types.package;
      default =
        pkgs.binpass or (throw ''
          programs.binpass.package is unset and pkgs.binpass does not exist.

          Add the flake's overlay:

            nixpkgs.overlays = [ binpass.overlays.default ];

          or set programs.binpass.package explicitly.
        '');
      defaultText = lib.literalExpression "pkgs.binpass";
      description = "The binpass package to use.";
    };

    passPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.binpass-pass or (pkgs.callPackage ../nix/pass-shim.nix { binpass = cfg.package; });
      defaultText = lib.literalExpression "pkgs.binpass-pass";
      description = ''
        The package installed when `replacePass` is on: binpass under the
        name `pass`, with completions generated for that name.
      '';
    };

    replacePass = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Install a `pass` executable that runs binpass, system-wide.

        binpass implements pass's command surface and reads the same store
        format, so scripts and browser extensions calling `pass` keep working.
        Off by default: replacing a command for every user on the machine is
        not something to do without being asked.

        Conflicts with `programs.password-store.enable`.
      '';
    };

    enableTombPolkit = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow members of `tombGroup` to run cryptsetup, mount and umount
        without a password, so that `binpass tomb --type=luks` works without
        sudo.

        Read what this grants before enabling it. Unrestricted `mount` is
        close to root: a user who can mount anything anywhere can generally
        arrange to become root. On a single-user laptop that is often an
        acceptable trade for not typing a password on every unlock; on a
        shared machine it is not, and `sudo binpass tomb open` is the honest
        answer.
      '';
    };

    tombGroup = lib.mkOption {
      type = lib.types.str;
      default = "binpass-tomb";
      description = ''
        Group whose members may run the tomb helpers unprivileged. Created
        automatically when `enableTombPolkit` is on; add users to it
        explicitly, so that the grant is visible in the configuration rather
        than implied.
      '';
    };

    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      example = lib.literalExpression "[ pkgs.rclone pkgs.restic ]";
      description = ''
        Extra programs to install alongside binpass.

        binpass drives its transports and pickers as external binaries, so the
        features that need them are unavailable until they are on PATH:
        `rclone` for cloud sync, `restic` for snapshot sync, `cryptsetup` for
        the LUKS tomb, `rofi`/`fzf`/`dmenu` for the picker.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # NixOS has no programs.password-store; pass is installed by putting
        # pkgs.pass in systemPackages, so that is what has to be checked. Two
        # packages owning bin/pass make the profile fail to build with a
        # collision error that names store paths and not this option.
        assertion =
          cfg.replacePass
          -> !(lib.any (p: (p.pname or p.name or "") == "password-store") config.environment.systemPackages);
        message = ''
          programs.binpass.replacePass installs a `pass` binary, and
          pkgs.pass is also in environment.systemPackages. Remove one:
          binpass reads the same store format, so keeping both is only
          useful while migrating.
        '';
      }
      {
        assertion = cfg.enableTombPolkit -> pkgs.stdenv.isLinux;
        message = "programs.binpass.enableTombPolkit needs polkit, which is Linux-only.";
      }
    ];

    environment.systemPackages = [
      cfg.package
    ]
    ++ cfg.extraPackages
    ++ lib.optional cfg.replacePass passShim
    ++ lib.optionals cfg.enableTombPolkit [
      pkgs.cryptsetup
      pkgs.e2fsprogs
    ];

    users.groups = lib.mkIf cfg.enableTombPolkit {
      ${cfg.tombGroup} = { };
    };

    security.polkit = lib.mkIf cfg.enableTombPolkit {
      enable = true;
      extraConfig = ''
        // binpass tomb --type=luks drives cryptsetup, mount and umount, none
        // of which work unprivileged. Members of ${cfg.tombGroup} may run
        // them without a password.
        polkit.addRule(function(action, subject) {
          if (subject.isInGroup("${cfg.tombGroup}") &&
              (action.id == "org.freedesktop.udisks2.encrypted-unlock" ||
               action.id == "org.freedesktop.udisks2.filesystem-mount")) {
            return polkit.Result.YES;
          }
        });
      '';
    };

    security.sudo.extraRules = lib.mkIf cfg.enableTombPolkit [
      {
        groups = [ cfg.tombGroup ];
        commands = [
          {
            command = "${pkgs.cryptsetup}/bin/cryptsetup";
            options = [ "NOPASSWD" ];
          }
          {
            command = "${pkgs.util-linux}/bin/mount";
            options = [ "NOPASSWD" ];
          }
          {
            command = "${pkgs.util-linux}/bin/umount";
            options = [ "NOPASSWD" ];
          }
        ];
      }
    ];

    # The LUKS backend needs dm-crypt, and a kernel without it fails at
    # cryptsetup with a message about the device mapper rather than anything
    # naming binpass.
    boot.kernelModules = lib.mkIf cfg.enableTombPolkit [ "dm_crypt" ];
  };
}
