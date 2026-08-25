# NixOS module for ts1p. Import via the flake's nixosModules.default.
#
#   services.ts1p = {
#     enable = true;
#     vault = "ts1p";
#     environmentFile = config.age.secrets.ts1p-op-token.path; # OP_SERVICE_ACCOUNT_TOKEN=...
#   };
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.ts1p;
  # A Go time.Duration string (e.g. "1h", "30m", "1h30m", "500ms", "0"), validated
  # at eval time so a typo fails the build instead of crash-looping the service.
  duration = lib.types.strMatching "0|([0-9]+(ns|us|ms|s|m|h))+";
in
{
  imports = [
    (lib.mkRenamedOptionModule
      [ "services" "ts1p" "tokenFile" ]
      [ "services" "ts1p" "environmentFile" ]
    )
  ];

  options.services.ts1p = {
    enable = lib.mkEnableOption "ts1p, a setec-compatible secrets server backed by 1Password";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.default;
      defaultText = lib.literalExpression "ts1p flake package";
      description = "The ts1p package to run.";
    };

    hostname = lib.mkOption {
      type = lib.types.str;
      default = "ts1p";
      description = "Tailnet hostname to serve as.";
    };

    vault = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "ts1p";
      description = "1Password vault name holding the secrets. Required unless dev = true.";
    };

    dev = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Run with an in-memory backend and serve plain HTTP over the tailnet.
        For testing only: secrets are lost on restart and no 1Password token is
        required.
      '';
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path to an EnvironmentFile sourced by the service. In production it
        carries the 1Password service account token as
        OP_SERVICE_ACCOUNT_TOKEN=...; it may also carry TS_AUTHKEY=... for
        unattended tailnet enrolment. Keep it out of the Nix store (e.g. an
        agenix/ragenix secret). Required unless dev = true.
      '';
    };

    loginServer = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Tailscale control URL (empty for the default).";
    };

    debugAddr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:9090";
      description = ''
        Loopback address for the full debug listener (pprof, statsviz, /metrics).
        Empty disables it. Keep it on loopback: it exposes pprof, which the
        tailnet listener deliberately does not (a heap dump would leak secrets).
      '';
    };

    service = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "secrets";
      description = ''
        Advertise as a Tailscale Service of this name instead of serving the node
        FQDN, so several stateless instances (on different hosts) form one HA
        front door reachable at <name>.<tailnet>. Empty disables it.

        Requires a control plane that supports Tailscale Services and a *tagged*
        auth key (set TS_AUTHKEY in environmentFile to a tagged key, and add a
        control-plane auto-approver for that tag to this service).
      '';
    };

    cacheExpiry = lib.mkOption {
      type = duration;
      default = "1h";
      description = "Base lifetime of a cached 1Password read before refetch (jittered ±20% per entry).";
    };

    cacheMaxEntries = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = "Maximum number of cached secrets (0 = unbounded).";
    };

    cacheWarm = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Keep the 1Password read cache warm in the background so cold reads never hit the request path.";
    };

    # TODO(kradalby): remove with the 1Password WASM-core workaround (kradalby/ts1p#2).
    opMaxAge = lib.mkOption {
      type = duration;
      default = "0";
      description = ''
        Recycle (exit for a clean restart) once the 1Password WASM core has been
        alive this long, working around its corruption under sustained uptime;
        "0" disables. See https://github.com/kradalby/ts1p/issues/2.
      '';
    };

  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.dev || cfg.vault != "";
        message = "services.ts1p: set vault (or enable dev).";
      }
      {
        assertion = cfg.dev || cfg.environmentFile != null;
        message = "services.ts1p: set environmentFile with OP_SERVICE_ACCOUNT_TOKEN (or enable dev).";
      }
    ];

    systemd.services.ts1p = {
      description = "ts1p secrets server (setec API over 1Password)";
      wantedBy = [ "multi-user.target" ];
      # nss-lookup.target orders ts1p after DNS is resolvable; ts1p also retries
      # its 1Password connect in-process, so a slow resolver no longer crash-loops.
      after = [
        "network-online.target"
        "nss-lookup.target"
      ];
      wants = [
        "network-online.target"
        "nss-lookup.target"
      ];

      # TODO(kradalby): the start-limit backstop and Restart=always exist for the
      # 1Password WASM-core recycle/exit workaround; revisit when kradalby/ts1p#2
      # is fixed. The limit turns a poisoned-input OOB-exit loop into a visible
      # failed state instead of an endless restart; a proactive recycle (hours
      # apart) stays well under it, and an upstream outage cannot trip it —
      # ts1p retries its 1Password connect in-process indefinitely rather than
      # exiting.
      startLimitIntervalSec = 600;
      startLimitBurst = 5;

      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe cfg.package)
            "--hostname=${cfg.hostname}"
            "--state-dir=/var/lib/ts1p"
            "--cache-expiry=${cfg.cacheExpiry}"
            "--cache-max-entries=${toString cfg.cacheMaxEntries}"
            "--cache-warm=${lib.boolToString cfg.cacheWarm}"
            "--op-max-age=${cfg.opMaxAge}"
            "--debug-addr=${cfg.debugAddr}"
          ]
          ++ lib.optional cfg.dev "--dev"
          ++ lib.optional (cfg.vault != "") "--vault=${cfg.vault}"
          ++ lib.optional (cfg.service != "") "--service=${cfg.service}"
          ++ lib.optional (cfg.loginServer != "") "--login-server=${cfg.loginServer}"
        );

        StateDirectory = "ts1p";
        StateDirectoryMode = "0700";
        DynamicUser = true;
        # always (not on-failure): a proactive WASM-core recycle exits 0 and must
        # still restart. See kradalby/ts1p#2.
        Restart = "always";
        RestartSec = "5s";

        # ts1p sends sd_notify READY once its listener is up, so "active" means
        # serving and dependents can order on it. No start timeout: the initial
        # 1Password connect retries until the outage ends, and a first boot
        # without TS_AUTHKEY waits on interactive tailnet auth.
        Type = "notify";
        TimeoutStartSec = "infinity";
        # SIGTERM goes to the main pid so it drains in-flight requests itself;
        # SIGKILL only mops up stragglers at the stop timeout.
        KillMode = "mixed";

        # tsnet is a Tailscale node: it needs CAP_NET_ADMIN to set the bypass
        # socket mark (SO_MARK). Without it, tailscale falls back to binding
        # sockets to the default-route interface, which breaks connectivity on
        # multi-homed hosts where the control server or peers are on another
        # interface.
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];

        # Hardening. ts1p needs outbound network (Tailscale + 1Password) and its
        # own state directory; nothing else.
        #
        # The process heap holds every version of every secret (the warmer keeps
        # the vault resident), so no page of it may ever reach disk: no swap,
        # and no core dumps (systemd-coredump would happily persist one).
        MemorySwapMax = 0;
        LimitCORE = 0;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        # AF_UNIX is required for tsnet's local API socket (and the server's
        # WhoIs calls over it).
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = false; # 1Password SDK runs a wasm core
        SystemCallFilter = [ "@system-service" ];
        SystemCallErrorNumber = "EPERM";
      }
      // lib.optionalAttrs (cfg.environmentFile != null) {
        EnvironmentFile = cfg.environmentFile;
      };
    };
  };
}
