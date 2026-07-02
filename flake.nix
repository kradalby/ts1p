{
  description = "ts1p — a setec-wire-compatible secrets server backed by 1Password";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    flake-checks.url = "github:kradalby/flake-checks";
    flake-checks.inputs.nixpkgs.follows = "nixpkgs";
    flake-checks.inputs.flake-utils.follows = "flake-utils";
    # Latest stable release, deliberately not following our nixpkgs: headscale
    # builds against the toolchain its release pins.
    headscale.url = "github:juanfont/headscale/v0.29.2";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-checks
    , headscale
    }:
    let
      hashes = builtins.fromJSON (builtins.readFile ./flakehashes.json);
    in
    {
      overlays.default = _final: prev: {
        ts1p = self.packages.${prev.system}.default;
      };
      nixosModules.default = import ./module.nix self;
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # Scoped unfree import for the one unfree tool in the dev shell (op),
        # so the shell evaluates purely — locally and on garnix — without a
        # blanket NIXPKGS_ALLOW_UNFREE.
        pkgsUnfree = import nixpkgs {
          inherit system;
          config.allowUnfreePredicate = p: (nixpkgs.lib.getName p) == "1password-cli";
        };
        fc = flake-checks.lib;
        common = {
          inherit pkgs;
          root = ./.;
          pname = "ts1p";
          version = "0.1.0";
          vendorHash = hashes.vendorHash;
          goPkg = pkgs.go_1_26;
          subPackages = [ "cmd/ts1p" ];
        };
      in
      {
        packages.default = (fc.goBuild common).overrideAttrs (_: {
          meta.mainProgram = "ts1p";
        });
        formatter = fc.formatter common;
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_1_26
            pkgs.gopls
            pkgs.golangci-lint
            pkgs.gofumpt
            # The treefmt wrapper, configured identically to the formatting check
            # (gofumpt + goimports -local + nixpkgs-fmt). Run `treefmt` or `nix fmt`.
            (fc.formatter common)
            pkgs.prek
            # Not a flake check: it fetches the live vulnerability database.
            pkgs.govulncheck
            pkgs.gnumake
            pkgsUnfree._1password-cli
          ];
        };
        checks = {
          build = fc.goBuild common;
          gotest = fc.goTest (common // { goRace = true; });
          golangci-lint = fc.goLint common;
          formatting = fc.goFormat common;
        }
        # NixOS evaluation needs a Linux system.
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          module-eval = import ./module-eval.nix { inherit pkgs self nixpkgs system; };
        };
      }
    );
}
