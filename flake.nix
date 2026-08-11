{
  description = "binpass — pass(1) reimagined: GPG and age, hardware keys, tomb, sync";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      # The package definition is shared by the flake outputs and the overlay,
      # so that a module using the overlay builds the same derivation the
      # flake exposes rather than a second, subtly different one.
      binpassPackage =
        {
          lib,
          buildGoModule,
          installShellFiles,
          gnupg,
          pass,
          age,
          git,
          qrencode,
          tree,
        }:
        buildGoModule (finalAttrs: {
          pname = "binpass";
          version = "0.1.0";
          src = ./.;

          # Hash of the fetched module set. null would mean "the source
          # vendors its dependencies", which this repository does not.
          vendorHash = "sha256-szHslzVzRtGcMJ1IXHh08wIrpjqTtkSc5pXKuraiMaM=";

          env.CGO_ENABLED = 0;
          ldflags = [
            "-s"
            "-w"
            "-X main.version=${finalAttrs.version}"
          ];

          nativeBuildInputs = [ installShellFiles ];

          nativeCheckInputs = [
            gnupg
            pass
            age
            git
            qrencode
            tree
          ];

          # Completion is what makes a password manager usable at the prompt,
          # and asking every user to wire it up by hand is how it ends up not
          # wired up at all.
          postInstall = ''
            installShellCompletion --cmd binpass \
              --bash <($out/bin/binpass completion bash) \
              --zsh <($out/bin/binpass completion zsh) \
              --fish <($out/bin/binpass completion fish)
          '';

          meta = {
            description = "A pass(1)-compatible password manager with age, hardware keys and sync";
            homepage = "https://github.com/71g3pf4c3/binpass";
            license = lib.licenses.mit;
            mainProgram = "binpass";
            platforms = lib.platforms.unix ++ lib.platforms.windows;
          };
        });
    in
    {
      # An overlay so that a configuration can `pkgs.binpass` anywhere, and so
      # that `pass` can be replaced store-wide by one line.
      overlays.default = final: _prev: {
        binpass = final.callPackage binpassPackage { };

        # binpass installed under the name pass, with completions to match.
        #
        # The binary answers to whichever name it was invoked under, so this
        # is a genuine replacement rather than an alias: `pass --help` says
        # pass, and tab completion completes pass.
        binpass-pass = final.callPackage ./nix/pass-shim.nix { };
      };

      nixosModules.default = import ./nix/nixos-module.nix;
      nixosModules.binpass = self.nixosModules.default;

      homeModules.default = import ./nix/home-module.nix;
      homeModules.binpass = self.homeModules.default;
      # home-manager still reads homeManagerModules in much of the wild.
      homeManagerModules = self.homeModules;
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Tools the test suite shells out to. gnupg and pass are what make the
        # compatibility tests meaningful: they run against the real thing.
        testTools = with pkgs; [
          gnupg
          pass
          age
          git
          qrencode
          # pass renders listings through tree(1); the golden tests compare
          # binpass against its exact output, so it must be pinned here
          # rather than inherited from the host.
          tree
        ];

        # Pickers and typing tools `binpass menu` drives. They are not needed
        # to build or test binpass, only to exercise the menu interactively.
        menuTools = with pkgs; [
          fzf
          rofi
          dmenu
          wtype
          xdotool
        ];

        # Transports and containers the optional subsystems drive. binpass
        # calls these as external binaries, so a dev shell without them can
        # build everything and exercise nothing.
        syncTools = with pkgs; [
          rclone
          restic
          cryptsetup
        ];

        devTools = with pkgs; [
          go
          gopls
          go-tools
          golangci-lint
          goreleaser
          # goreleaser shells out to syft for the SBOM it attaches to each
          # archive; without it a release fails at the very last step.
          syft
          gotestsum
          mockgen
          delve
        ];
      in
      {
        packages.default = pkgs.callPackage binpassPackage { };
        packages.binpass = self.packages.${system}.default;

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          packages = devTools ++ testTools ++ menuTools ++ syncTools;

          # A shell that inherits PASSWORD_STORE_* from the user's session
          # would make tests pass or fail depending on whose machine they run
          # on, so the dev shell starts from a clean slate.
          shellHook = ''
            unset PASSWORD_STORE_DIR PASSWORD_STORE_CLIP_TIME \
                  PASSWORD_STORE_GENERATED_LENGTH PASSWORD_STORE_CHARACTER_SET \
                  PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS PASSWORD_STORE_UMASK \
                  PASSWORD_STORE_SIGNING_KEY PASSWORD_STORE_GPG_OPTS \
                  PASSWORD_STORE_ENABLE_EXTENSIONS PASSWORD_STORE_EXTENSIONS_DIR \
                  PASSWORD_STORE_X_SELECTION
            unset ''${!BINPASS_@}
            export CGO_ENABLED=0
            echo "binpass dev shell: $(go version)"
            echo "  gpg $(gpg --version | head -1 | cut -d' ' -f3), pass $(pass version 2>/dev/null | grep -o 'v[0-9.]*' | head -1)"
          '';
        };

        checks = {
          package = self.packages.${system}.default;

          # A module that only type-checks in someone else's configuration is
          # a module nobody finds out is broken until they try it.
          homeModule = pkgs.callPackage ./nix/tests/home-module.nix {
            module = self.homeModules.default;
            overlay = self.overlays.default;
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
