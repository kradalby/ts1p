# ts1p

A [`setec`](https://github.com/tailscale/setec)-compatible secrets server backed
by a 1Password vault.

## Why

Used in my homelab. The draw is setec's access model: secret access is a
Tailscale grant, so a node either has a grant or it doesn't, and the secret is
never copied onto the machines that use it. Works with headscale.

setec stores its database encrypted with AWS KMS. ts1p keeps the API and the
grant model but stores each secret in 1Password, which is already synced, backed
up, and audited. No database to encrypt, no KMS key to manage.

## How it works

```
setec client ──HTTP──▶ ts1p ──▶ store ──▶ cache ──▶ 1Password
              (grants)         (versions) (expiry)  (one item per secret)
```

- **server**: setec's `/api/*` endpoints, every call authorized against a
  Tailscale grant and audited.
- **store**: setec's version semantics (active/latest, forever-claimed versions,
  Put de-duplication).
- **backend**: a four-method interface. Today 1Password, plus an in-memory fake
  for tests. Another password manager is another implementation.
- **cache**: an expiry read cache with a background warmer, so reads are served
  from memory instead of 1Password.

The 1Password SDK runs a WASM core that corrupts under sustained uptime, so the
cache also shields it. The warmer re-reads each secret at 75% of `--cache-expiry`
(about one read per secret per 45 minutes at the 1h default), concurrent misses
are coalesced, and a resident value is served if 1Password is briefly
unavailable. `--cache-expiry=0` caches forever and disables the warmer; it does
not mean "no caching".

Each secret is one 1Password item: a `value` field with the active version, and
a `ts1p-meta` JSON field with the full version history. `ts1p-meta` is the source
of truth; `value` is a read-only view, so editing it in the 1Password app rotates
nothing and is overwritten on the next write. Rotate through the API. An
out-of-band edit to `ts1p-meta` is picked up within `--cache-expiry`, immediately
with `Cache-Control: no-cache`, or via `POST /debug/flush-cache`.

setec keeps every version forever in that one field, so a frequently-rotated
secret grows toward 1Password's ~1MiB item limit. ts1p warns at 512KiB and
refuses writes past 1MiB, naming the fix (`setec delete-version`).

## Run

ts1p needs a 1Password
[service account](https://developer.1password.com/docs/service-accounts/) token
(available on every plan) scoped to a dedicated vault, in
`OP_SERVICE_ACCOUNT_TOKEN`. Select the vault by name with `--vault`.

```sh
export OP_SERVICE_ACCOUNT_TOKEN=ops_...
export TS_AUTHKEY=tskey-auth-...   # optional: unattended tailnet enrolment
ts1p --vault ts1p --state-dir /var/lib/ts1p --hostname ts1p
```

Without `TS_AUTHKEY`, tsnet logs an interactive auth URL on first start. Disable
key expiry for the node, or use a tagged key. An expired node key takes the
server off the tailnet while the process keeps running.

Then point any [`setec`](https://github.com/tailscale/setec) client at it:

```sh
setec -s https://ts1p.your-tailnet.ts.net put my/secret
setec -s https://ts1p.your-tailnet.ts.net get my/secret
```

Configuration is via flags or `TS1P_`-prefixed environment variables
(`TS1P_VAULT`, `TS1P_CACHE_EXPIRY`, …); see `ts1p --help`. `--dev` runs an
in-memory backend over plain HTTP for testing.

## Grants

ts1p reads grants from setec's capability, `tailscale.com/cap/secrets`.
headscale must allow it in `tailscaleCapAllowlist` (it's an official Tailscale
feature). A grant is a list of rules, each an action list plus a secret pattern
(`*` matches a trailing segment):

```jsonc
"grants": [
  {
    "src": ["group:writers"],
    "dst": ["tag:ts1p"], // or the service, for HA: ["svc:secrets"]
    "app": {
      "tailscale.com/cap/secrets": [
        { "action": ["get", "info", "put", "create-version", "activate", "delete"],
          "secret": ["*"] }
      ]
    }
  },
  {
    "src": ["group:readers"],
    "dst": ["tag:ts1p"],
    "app": {
      "tailscale.com/cap/secrets": [
        { "action": ["get", "info"], "secret": ["prod/*"] }
      ]
    }
  }
]
```

The `/debug` endpoints on the tailnet need the strongest grant (`delete` on `*`)
plus the API's anti-CSRF header:

- `GET /debug/vars`: expvar counters.
- `POST /debug/flush-cache`: drop the read cache so the next read hits 1Password.

```sh
curl -H "Sec-X-Tailscale-No-Browsers: setec" https://ts1p.your-tailnet.ts.net/debug/vars
```

`GET /metrics` is un-gated (a scraper holds no grant) and serves only numeric
`ts1p_*` counters and Go runtime metrics. pprof and statsviz never touch the
tailnet, because a heap dump would leak the decrypted secrets in memory. They run
on a loopback-only debug listener (`--debug-addr`, default `127.0.0.1:9090`).

## NixOS

```nix
{
  inputs.ts1p.url = "github:kradalby/ts1p";

  # in your configuration:
  imports = [ ts1p.nixosModules.default ];
  services.ts1p = {
    enable = true;
    vault = "ts1p";
    environmentFile = config.age.secrets.ts1p-op-token.path; # OP_SERVICE_ACCOUNT_TOKEN=... (and optionally TS_AUTHKEY=...)
  };
}
```

The audit log (`/var/lib/ts1p/audit.log`, one JSON line per authorized-or-denied
call) grows without bound and ts1p holds its fd open; rotate it with copytruncate
semantics, or let a restart (e.g. an `--op-max-age` recycle) reopen it after an
external move.

## High availability

ts1p is stateless; 1Password is the store. Run it on several hosts with the same
`--service` (a
[Tailscale Service](https://tailscale.com/kb/1552/tailscale-services)) and lose
any one host without losing the tailnet name:

```sh
ts1p --vault ts1p --state-dir /var/lib/ts1p --service secrets
setec -s https://secrets.your-tailnet.ts.net get my/secret
```

Each instance caches independently with no cross-instance invalidation, so you
are at the mercy of 1Password's consistency. A write on one instance appears on
another only after its cache expires, and two instances writing the same secret
at once are last-writer-wins. Route automated writes through one instance.
Service mode needs a tagged auth key, a control-plane auto-approver for that tag,
and grants whose `dst` names the service (`svc:secrets`). It is off by default
and new in this release, not yet covered by the VM e2e test.

## Security

- Secret values are never logged or audited, only principal, action, and
  version.
- The token comes from the environment, scoped to a single vault; service
  accounts cannot reach the Private vault.
- No secret material touches local disk, and the NixOS unit forbids swap and core
  dumps so process memory cannot page out.
- tsnet's log upload to log.tailscale.com is disabled unconditionally
  (`TS_NO_LOGS_NO_SUPPORT`); a secrets server must not phone home, even metadata.
- Identity is Tailscale WhoIs on the source address, so traffic through a subnet
  router inherits the router's grants. Don't grant secrets to subnet routers.

## Develop

```sh
nix develop          # go, gopls, golangci-lint, gofumpt, treefmt, prek, op
nix fmt              # format Go + Nix (gofumpt + goimports + nixfmt) via treefmt
nix flake check      # build + race tests + lint + formatting
go test -race ./...  # unit, conformance (vs setec client), differential, property, fuzz
```

The conformance suite runs setec's real client against ts1p; the differential
test replays an identical script against setec's reference server and ts1p and
requires byte-identical responses. The 1Password backend has a gated integration
test and a full Go end-to-end test (`-tags e2e`), both requiring
`OP_SERVICE_ACCOUNT_TOKEN` and `TS1P_TEST_VAULT`.

`nix build .#checks.x86_64-linux.e2e` runs a full-stack NixOS VM test: a
headscale control server, ts1p brought up through its NixOS module, and three
Tailscale clients exercising the capability matrix over a real tailnet, a writer
(read+write), a reader (read-only; writes denied), and a node with no grant (all
calls denied).
