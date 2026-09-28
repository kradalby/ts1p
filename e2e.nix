# Full-stack NixOS VM integration test. A headscale control server (the
# headscale flake's test kit), a ts1p node brought up via this repo's NixOS
# module (in --dev mode), and three Tailscale clients with different
# ACL-capability grants:
#
#   writer  — full secrets capability: read and write succeed
#   reader  — get/info only: reads succeed, writes are denied
#   denied  — no capability: every call is denied, though the node is reachable
#
# This proves the real path end to end — tailnet enrolment, WhoIs identity, the
# capability grants, and the version lifecycle — against a genuine control plane,
# exercising accepted, read-only, and access-denied outcomes across clients.
{
  pkgs,
  self,
  headscale,
}:
let
  fullActions = [
    "get"
    "info"
    "put"
    "create-version"
    "activate"
    "delete"
  ];

  # Applied live with `headscale policy set`. acls open the network; grants
  # attach capabilities. hs-authkey users have no email, so groups name them
  # by user name ("writer@").
  policy = pkgs.writeText "policy.hujson" (
    builtins.toJSON {
      groups = {
        "group:writers" = [ "writer@" ];
        "group:readers" = [ "reader@" ];
      };
      acls = [
        {
          action = "accept";
          src = [ "*" ];
          dst = [ "*:*" ];
        }
      ];
      grants = [
        {
          src = [ "group:writers" ];
          dst = [ "*" ];
          app."tailscale.com/cap/secrets" = [
            {
              action = fullActions;
              secret = [ "*" ];
            }
          ];
        }
        {
          src = [ "group:readers" ];
          dst = [ "*" ];
          app."tailscale.com/cap/secrets" = [
            {
              action = [
                "get"
                "info"
              ];
              secret = [ "*" ];
            }
          ];
        }
      ];
    }
  );

  tailscaleClient = {
    imports = [ headscale.nixosModules.testkit-peer ];
    environment.systemPackages = [ pkgs.curl ];
  };
in
pkgs.testers.runNixOSTest {
  name = "ts1p-e2e";

  nodes = {
    headscale.imports = [ headscale.nixosModules.testkit ];

    ts1p =
      { lib, nodes, ... }:
      {
        imports = [ self.nixosModules.default ];
        services.ts1p = {
          enable = true;
          dev = true;
          hostname = "ts1p";
          loginServer = "http://headscale";
          environmentFile = "/etc/ts1p.env";
        };
        # Start only after the test writes TS_AUTHKEY into the EnvironmentFile.
        systemd.services.ts1p.wantedBy = lib.mkForce [ ];
        # tsnet's control dialer resolves "headscale" via /etc/hosts and dials
        # the v6 address without falling back to v4; the test VLAN's v6 routing
        # is broken, so pin the control hostname to headscale's v4 VLAN IP.
        networking.extraHosts = lib.mkForce "${nodes.headscale.networking.primaryIPAddress} headscale";
      };

    writer = { ... }: tailscaleClient;
    reader = { ... }: tailscaleClient;
    denied = { ... }: tailscaleClient;
  };

  testScript = ''
    import datetime as dt

    # How long a node gets to join the tailnet or reach ts1p over it.
    settle = dt.timedelta(minutes=2)

    start_all()

    # hs-authkey waits for headscale and creates the user. "server" owns the
    # ts1p node; its identity is the grant *destination*, so its user is
    # immaterial (dst = * covers it).
    key = {
        user: headscale.succeed(f"hs-authkey {user}").strip()
        for user in ["writer", "reader", "denied", "server"]
    }

    headscale.succeed("headscale policy set -f ${policy}")

    ts1p.succeed("install -m 600 /dev/null /etc/ts1p.env")
    ts1p.succeed(f"echo 'TS_AUTHKEY={key['server']}' > /etc/ts1p.env")
    # Returns once tsnet is up (Type=notify). The unit never times out its own
    # start, so bound it here or unreachable control hangs the test.
    ts1p.succeed("systemctl start ts1p.service", timeout=settle)

    # Join the clients, each as its own user.
    for node, user in [(writer, "writer"), (reader, "reader"), (denied, "denied")]:
        node.succeed(f"hs-join {key[user]}")

    # Resolve ts1p's tailnet IP from a client's netmap.
    ts1p_ip = writer.wait_until_succeeds("tailscale ip -4 ts1p", timeout=settle).strip()

    hdr = "-H 'Content-Type: application/json' -H 'Sec-X-Tailscale-No-Browsers: setec'"
    put = '{"Name":"greeting","Value":"aGVsbG8="}'   # value 'hello'
    get = '{"Name":"greeting"}'

    def code(path, body, extra=""):
        return (
            f"test \"$(curl -s -o /dev/null -w '%{{http_code}}' {hdr} {extra} "
            f"-X POST -d '{body}' http://{ts1p_ip}{path})\""
        )

    # writer: write then read both succeed (retry until the tailnet path is up).
    writer.wait_until_succeeds(code("/api/put", put) + " = 200", timeout=settle)
    writer.succeed(code("/api/get", get) + " = 200")
    out = writer.succeed(f"curl -fsS {hdr} -X POST -d '{get}' http://{ts1p_ip}/api/get")
    assert '"Value":"aGVsbG8="' in out, f"unexpected get body: {out}"
    assert '"Version":1' in out, f"unexpected version: {out}"

    # reader: reads succeed, writes are denied.
    reader.wait_until_succeeds(code("/api/get", get) + " = 200", timeout=settle)
    reader.succeed(code("/api/put", '{"Name":"x","Value":"eQ=="}') + " = 403")

    # denied: reachable, but every call is access-denied.
    denied.wait_until_succeeds(code("/api/get", get) + " = 403", timeout=settle)
    denied.succeed(code("/api/put", put) + " = 403")

    # The browser-blocking header is mandatory: omitting it is rejected even for
    # an otherwise-authorized writer.
    writer.succeed(
        f"test \"$(curl -s -o /dev/null -w '%{{http_code}}' "
        f"-H 'Content-Type: application/json' -X POST -d '{get}' "
        f"http://{ts1p_ip}/api/get)\" = 403"
    )
  '';
}
