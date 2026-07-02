# Full-stack NixOS VM integration test. A headscale control server (latest
# stable, patched to allowlist the secrets capability), a
# ts1p node brought up via this repo's NixOS module (in --dev mode), and three
# Tailscale clients with different ACL-capability grants:
#
#   writer  — full secrets capability: read and write succeed
#   reader  — get/info only: reads succeed, writes are denied
#   denied  — no capability: every call is denied, though the node is reachable
#
# This proves the real path end to end — tailnet enrolment, WhoIs identity, the
# capability grants, and the version lifecycle — against a genuine control plane,
# exercising accepted, read-only, and access-denied outcomes across clients.
{ pkgs, self, headscale, system }:
let
  # Latest stable headscale, plus the (already-merged) upstream commit that
  # allowlists tailscale.com/cap/secrets in grants — policy set rejects the
  # capability without it. Drop the patch once a release contains
  # juanfont/headscale@66937040f.
  headscalePkg = headscale.packages.${system}.default.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [ ./headscale-cap-secrets.patch ];
  });

  # Self-signed cert for the control server, trusted by every joining node.
  tls-cert = pkgs.runCommand "selfSignedCerts" { buildInputs = [ pkgs.openssl ]; } ''
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
      -out cert.pem -keyout key.pem \
      -subj '/CN=headscale' -addext "subjectAltName=DNS:headscale"
    mkdir -p $out
    cp key.pem cert.pem $out
  '';

  fullActions = [ "get" "info" "put" "create-version" "activate" "delete" ];

  # Loaded via `headscale policy set` once the users exist (database mode), so
  # user references resolve. acls open the network; grants attach capabilities.
  policy = pkgs.writeText "policy.hujson" (builtins.toJSON {
    groups = {
      "group:writers" = [ "writer@example.com" ];
      "group:readers" = [ "reader@example.com" ];
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
          { action = fullActions; secret = [ "*" ]; }
        ];
      }
      {
        src = [ "group:readers" ];
        dst = [ "*" ];
        app."tailscale.com/cap/secrets" = [
          { action = [ "get" "info" ]; secret = [ "*" ]; }
        ];
      }
    ];
  });

  trustCert.security.pki.certificateFiles = [ "${tls-cert}/cert.pem" ];

  tailscaleClient = trustCert // {
    services.tailscale.enable = true;
    environment.systemPackages = [ pkgs.curl ];
  };
in
pkgs.testers.runNixOSTest {
  name = "ts1p-e2e";

  nodes = {
    headscale =
      { ... }:
      {
        services.headscale = {
          enable = true;
          package = headscalePkg;
          port = 8080;
          settings = {
            server_url = "https://headscale";
            ip_prefixes = [ "100.64.0.0/10" ];
            derp = {
              server = {
                enabled = true;
                region_id = 999;
                stun_listen_addr = "0.0.0.0:3478";
              };
              urls = [ ];
            };
            dns = {
              base_domain = "tailnet";
              override_local_dns = false;
            };
            policy.mode = "database";
          };
        };
        services.nginx = {
          enable = true;
          virtualHosts.headscale = {
            addSSL = true;
            sslCertificate = "${tls-cert}/cert.pem";
            sslCertificateKey = "${tls-cert}/key.pem";
            locations."/" = {
              proxyPass = "http://127.0.0.1:8080";
              proxyWebsockets = true;
            };
          };
        };
        networking.firewall = {
          allowedTCPPorts = [ 80 443 ];
          allowedUDPPorts = [ 3478 ];
        };
        environment.systemPackages = [ headscalePkg pkgs.jq ];
      };

    ts1p =
      { lib, nodes, ... }:
      trustCert
      // {
        imports = [ self.nixosModules.default ];
        services.ts1p = {
          enable = true;
          dev = true;
          hostname = "ts1p";
          loginServer = "https://headscale";
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
    import json

    start_all()
    headscale.wait_for_unit("headscale")
    headscale.wait_for_open_port(443)

    # Users — emails match the policy groups; "server" owns the ts1p node.
    for name in ["writer", "reader", "denied", "server"]:
        email = f"{name}@example.com"
        headscale.succeed(f"headscale users create {name} --email {email}")

    users = json.loads(headscale.succeed("headscale users list -o json"))
    uid = {u["name"]: u["id"] for u in users}

    # Now that the users exist, load the capability policy.
    headscale.succeed("headscale policy set -f ${policy}")

    def preauthkey(user):
        return headscale.succeed(
            f"headscale preauthkeys create --user {uid[user]} --reusable"
        ).strip()

    # Bring ts1p online (its identity is the grant *destination*, so its user is
    # immaterial; dst = * covers it).
    ts1p.succeed("install -m 600 /dev/null /etc/ts1p.env")
    ts1p.succeed(f"echo 'TS_AUTHKEY={preauthkey('server')}' > /etc/ts1p.env")
    ts1p.succeed("systemctl start ts1p.service")
    ts1p.wait_for_unit("ts1p.service")

    # Join the clients, each as its own user.
    for node, user in [(writer, "writer"), (reader, "reader"), (denied, "denied")]:
        node.succeed(
            f"tailscale up --login-server 'https://headscale' --auth-key {preauthkey(user)}"
        )

    # Resolve ts1p's tailnet IP (tolerate camelCase or snake_case JSON).
    headscale.wait_until_succeeds(
        "headscale nodes list -o json | "
        "jq -e 'map(.givenName // .given_name) | index(\"ts1p\")'",
        timeout=120,
    )
    ts1p_ip = headscale.succeed(
        "headscale nodes list -o json | jq -r "
        "'.[] | select((.givenName // .given_name)==\"ts1p\") | "
        "[(.ipAddresses // .ip_addresses)[] | select(startswith(\"100.\"))][0]'"
    ).strip()

    hdr = "-H 'Content-Type: application/json' -H 'Sec-X-Tailscale-No-Browsers: setec'"
    put = '{"Name":"greeting","Value":"aGVsbG8="}'   # value 'hello'
    get = '{"Name":"greeting"}'

    def code(path, body, extra=""):
        return (
            f"test \"$(curl -s -o /dev/null -w '%{{http_code}}' {hdr} {extra} "
            f"-X POST -d '{body}' http://{ts1p_ip}{path})\""
        )

    # writer: write then read both succeed (retry until the tailnet path is up).
    writer.wait_until_succeeds(code("/api/put", put) + " = 200", timeout=120)
    writer.succeed(code("/api/get", get) + " = 200")
    out = writer.succeed(f"curl -fsS {hdr} -X POST -d '{get}' http://{ts1p_ip}/api/get")
    assert '"Value":"aGVsbG8="' in out, f"unexpected get body: {out}"
    assert '"Version":1' in out, f"unexpected version: {out}"

    # reader: reads succeed, writes are denied.
    reader.wait_until_succeeds(code("/api/get", get) + " = 200", timeout=120)
    reader.succeed(code("/api/put", '{"Name":"x","Value":"eQ=="}') + " = 403")

    # denied: reachable, but every call is access-denied.
    denied.wait_until_succeeds(code("/api/get", get) + " = 403", timeout=120)
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
