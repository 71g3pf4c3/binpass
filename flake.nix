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
    flake-utils.lib.eachDefaultSystem (
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
        packages.default = pkgs.buildGoModule (finalAttrs: {
          pname = "binpass";
          version = "0.1.0";
          src = ./.;

          # Hash of the fetched module set. null would mean "the source
          # vendors its dependencies", which this repository does not.
          vendorHash = "sha256-bnv8ffH4/AiLkqQGZmIeLkoUk5wCRI4BIC1rUEl3oOs=";

          env.CGO_ENABLED = 0;
          ldflags = [
            "-s"
            "-w"
            "-X main.version=${finalAttrs.version}"
          ];

          nativeCheckInputs = testTools;

          meta = with pkgs.lib; {
            description = "A pass(1)-compatible password manager with age, hardware keys and sync";
            homepage = "https://github.com/71g3pf4c3/binpass";
            license = licenses.mit;
            mainProgram = "binpass";
          };
        });

        devShells.default = pkgs.mkShell {
          packages = devTools ++ testTools ++ menuTools;

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

        checks.default = self.packages.${system}.default;
      }
    );
}
