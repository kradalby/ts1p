# Eval-time smoke test for the NixOS module: assemble a minimal system in prod
# and dev shape and assert the rendered ExecStart, so a broken option or service
# definition fails `nix flake check` without spinning up a VM.
{ pkgs, self, nixpkgs, system }:
let
  inherit (pkgs) lib;

  execStartFor =
    cfg:
    (
      (import (nixpkgs + "/nixos/lib/eval-config.nix") {
        inherit system;
        modules = [
          self.nixosModules.default
          {
            boot.loader.grub.enable = false;
            fileSystems."/" = {
              device = "/dev/sda1";
              fsType = "ext4";
            };
            system.stateVersion = "24.11";
            services.ts1p = cfg;
          }
        ];
      }).config.systemd.services.ts1p.serviceConfig.ExecStart
    );

  prod = execStartFor {
    enable = true;
    vault = "ts1p";
    environmentFile = "/run/secrets/ts1p";
  };
  dev = execStartFor {
    enable = true;
    dev = true;
  };

  check = cond: msg: if cond then true else throw "module-eval: ${msg}";
in
assert check (lib.hasInfix "--vault=ts1p" prod) "prod ExecStart missing --vault: ${prod}";
assert check (lib.hasInfix "--dev" dev) "dev ExecStart missing --dev: ${dev}";
assert check (!lib.hasInfix "--vault=" dev) "dev ExecStart must not set --vault: ${dev}";
pkgs.runCommand "ts1p-module-eval-ok" { } "touch $out"
