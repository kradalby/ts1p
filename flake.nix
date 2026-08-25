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
    {
      self,
      nixpkgs,
      flake-utils,
      flake-checks,
      headscale,
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
        # Bare `pkgs.go` and `pkgs.buildGoModule` still track the previous Go
        # release in nixpkgs-unstable, so the latest attributes are named
        # explicitly: ts1p follows the newest Go, not whatever nixpkgs
        # defaults to. The Go dev tools are rebuilt against it as well —
        # goimports ships wrapped with a `go` on PATH, and if that `go` is
        # older than the go.mod directive, GOTOOLCHAIN=auto tries to fetch a
        # toolchain from inside the network-less treefmt sandbox. golangci-lint
        # and gopls already track the latest Go upstream, so they need no
        # override.
        goLatestOverlay = _final: prev: {
          gotools = prev.gotools.override {
            buildGoModule = prev.buildGoLatestModule;
            go = prev.go_latest;
          };
          gofumpt = prev.gofumpt.override {
            buildGoModule = prev.buildGoLatestModule;
          };
        };
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ goLatestOverlay ];
        };
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
          goPkg = pkgs.go_latest;
          subPackages = [ "cmd/ts1p" ];
        };
        # The dashboard generator is a separate binary (cmd/dashboard) so the
        # Grafana Foundation SDK's dependencies stay out of the ts1p server build.
        # It emits the ts1p Grafana dashboard as a bare JSON model on stdout.
        dashboard =
          (fc.goBuild (
            common
            // {
              pname = "ts1p-dashboard";
              subPackages = [ "cmd/dashboard" ];
            }
          )).overrideAttrs
            (_: {
              meta.mainProgram = "dashboard";
            });

        # Runs the generator and captures only the dashboard JSON, so a Nix
        # consumer can provision it directly. Build() schema-validates, so a
        # broken dashboard fails this build rather than shipping broken JSON.
        grafanaDashboards = pkgs.runCommand "ts1p-grafana-dashboards" { } ''
          mkdir -p $out
          ${dashboard}/bin/dashboard > $out/ts1p.json
        '';
      in
      {
        packages = {
          default = (fc.goBuild common).overrideAttrs (_: {
            meta.mainProgram = "ts1p";
          });
          inherit dashboard grafanaDashboards;
        };
        formatter = fc.formatter common;
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_latest
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
          # Generating the dashboard JSON is its own validation (Build() fails on
          # a bad panel), so building it in CI keeps the artifact honest.
          inherit grafanaDashboards;
        }
        # NixOS evaluation and the full-stack VM test need a Linux system (and,
        # for the VM, KVM).
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          module-eval = import ./module-eval.nix {
            inherit
              pkgs
              self
              nixpkgs
              system
              ;
          };
          e2e = import ./e2e.nix {
            inherit
              pkgs
              self
              headscale
              system
              ;
          };
        };
      }
    );
}
