# ACME certificate issuance via Cloudflare DNS-01, for every catalog app
# exposed publicly and for the ferrum dashboard itself. One security.acme.certs entry
# per public vhost, all sharing the same Cloudflare API token -- DNS-01,
# not HTTP-01, because it works even when the box isn't reachable on port
# 80/443 from the internet yet (e.g. behind NAT during initial setup) and
# because it's what makes wildcard-adjacent subdomain issuance simple.
#
# CLOUDFLARE_DNS_API_TOKEN (not CF_API_KEY/CF_API_EMAIL, the OLD Global-Key
# auth path) is lego's env var for a SCOPED Cloudflare API token -- the
# token needs Zone:Read + DNS:Edit permission on the zone that owns
# ferrum.proxy.baseDomain. Confirmed against go-acme/lego's own Cloudflare
# provider (the ACME client security.acme uses for DNS-01): this is the
# real, current env var name, not a guess -- Saltbox's own well-known
# weakness was defaulting to the Global API key, which this project set
# out from the start to avoid (see the spec's Global Constraints).
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  proxyEnabled = ferrum.proxy.enable;
  proxyLib = import ./lib.nix { inherit lib; };
  vhostNameFor = proxyLib.vhostNameFor ferrum;
  publicApps = proxyLib.publicApps ferrum;

  # D6/A6. Everything below used to key on publicApps alone, which made the
  # SAFEST configuration ferrum offers the one that silently broke: a host
  # publishing only the dashboard, with every catalog app left at lan or
  # local, has publicApps == { }, so it got no certificate, no acme.email
  # assertion and no DNS-01 credential assertion -- it just fell through to
  # the self-signed branch with nothing firing to say so. This names A6's
  # unstated precondition. It is the identical security.acme.certs shape,
  # OR'd in independently, not a second issuance mechanism.
  daemonPublished = proxyLib.daemonPublished ferrum;
  daemonVhostNameValue = proxyLib.vhostNameFor ferrum (proxyLib.daemonApp ferrum);

  # "Does this host need a real certificate from Let's Encrypt at all?" Every
  # assertion and secret below is gated on this rather than on publicApps, so
  # the dashboard-only host is held to the same requirements as an app host.
  realCertsNeeded = publicApps != { } || daemonPublished;

  credentialSecret = ferrum.proxy.acme.credentialSecret;
  credentialProvided = ferrum.secrets ? "${credentialSecret}";
  # nginx (not "acme", security.acme.certs' own default group) is the
  # process that actually needs to read the issued certificate, since it's
  # nginx.nix's virtualHosts entries that reference these certs via
  # useACMEHost -- confirmed by reading nixos/modules/security/acme/default.nix,
  # whose real default is group = "acme", which nginx's own unprivileged
  # nginx:nginx user was never a member of (found during the final
  # whole-branch review's own re-verification via a real nix eval: any
  # host with a public app AND ferrum.auth.enable = true failed a hard
  # nixpkgs assertion -- "Certificate ... must be readable by
  # service(s) nginx.service (user=nginx groups=nginx)..." -- until this
  # group override was added).
  nginxGroup = config.services.nginx.group;
in
lib.mkIf proxyEnabled {
  security.acme.acceptTerms = true;
  security.acme.defaults.email = ferrum.proxy.acme.email;

  assertions = [
    {
      assertion = ferrum.proxy.baseDomain != "";
      message = "ferrum.proxy.enable is true but ferrum.proxy.baseDomain is empty -- every vhost name and the self-signed certificate's CN derive from it.";
    }
    {
      assertion = !realCertsNeeded || ferrum.proxy.acme.email != "";
      message = "ferrum.proxy publishes a public-exposure app or the ferrum dashboard itself, but ferrum.proxy.acme.email is empty -- Let's Encrypt requires a real contact address.";
    }
    {
      assertion = !realCertsNeeded || credentialProvided;
      message = ''
        ferrum.proxy publishes a public-exposure app or the ferrum dashboard
        itself, which needs a real ACME certificate, but ferrum.secrets does
        not declare
        "${credentialSecret}". Add it to ferrum.secrets in settings.json
        and encrypt the Cloudflare DNS-01 token to this host's own age
        recipient -- see README.md's reverse-proxy section for the full
        procedure -- then re-apply.
      '';
    }
    {
      assertion = !credentialProvided || builtins.pathExists (/. + "${ferrum.secretsDir}/${credentialSecret}.sops");
      message = ''
        ferrum.secrets declares "${credentialSecret}" but
        ${ferrum.secretsDir}/${credentialSecret}.sops does not exist yet.
        Encrypt your Cloudflare DNS-01 token to this host's own age
        recipient first -- see README.md's reverse-proxy section for the
        full procedure -- then re-apply.
      '';
    }
  ];

  # The DNS-01 credential is operator-provided via `ferrum.secrets` -- same
  # zero-privilege sops-encrypt mechanism as qBittorrent's VPN config (see
  # modules/apps/qbittorrent/service.nix's own `ferrum.secrets ? "..."` +
  # pathExists pattern, mirrored here). Must go through sops-nix's own
  # decryption like every other secret in this codebase; environmentFile
  # cannot point at the raw .sops ciphertext directly. Gated on
  # credentialProvided too (not just the consumer branches below) so this
  # never attempts to decrypt a .sops file that was declared but never
  # actually written.
  #
  # All three consumer branches are load-bearing -- do not collapse them back
  # to `publicApps != { }`. The same Cloudflare token now has more than one
  # reader:
  #
  #   * publicApps != { } -- lego's DNS-01 challenge, via the
  #     security.acme.certs entries below. The original, narrowest reader.
  #     Folded into realCertsNeeded above.
  #
  #   * ferrum.proxy.dns.enable -- modules/proxy/dns.nix's record
  #     reconciliation, which names /run/secrets/${credentialSecret}
  #     literally as its credentialFile. A host that publishes no app but
  #     still wants its records managed (dns.nix emits the auth and daemon
  #     records on conditions of their own) would otherwise reach Cloudflare
  #     with no token on disk and fail at runtime with a missing-file error.
  #
  # The timer-driven ferrum-dns-updater unit reads the same path on a
  # schedule long after any apply finished, and it needs no branch of its
  # own: dns.nix gates both the timer and the service on its internal
  # `ddnsEnabled = ferrum.proxy.enable && dns.enable && dns.ddnsUpdater.enable`,
  # so the unit cannot exist unless ferrum.proxy.dns.enable is already true
  # and the branch above has already materialized the credential -- and
  # dns.nix asserts credentialProvided on that same condition, so there is
  # no host where the timer exists and the token does not. A third
  # disjunct on the RAW ferrum.proxy.dns.ddnsUpdater.enable used to sit here,
  # justified as insurance against "a credential missing when the timer
  # fires" -- a state the conjunction above makes unreachable. What it did
  # reach was the opposite case: dns.enable = false with ddnsUpdater.enable
  # = true decrypted a Zone:Read + DNS:Edit token to /run/secrets with no
  # consumer of any kind on the host.
  #
  # Ownership stays acme:acme in both branches. ferrum-dns-updater runs as
  # root (dns.nix's own serviceConfig comment), so it reads the file without
  # a second principal; adding a user or group here would widen the set of
  # identities that can read a Zone:Read + DNS:Edit token for no gain.
  #   * daemonPublished -- the daemon's own certificate entry below, added by
  #     D6. This disjunct is load-bearing in the same way the other two are:
  #     that cert entry names config.sops.secrets.${credentialSecret}.path as
  #     its environmentFile, so on a dashboard-only host the token must be on
  #     disk even though publicApps is empty.
  sops.secrets."${credentialSecret}" = lib.mkIf
    (credentialProvided
      && (realCertsNeeded
      || ferrum.proxy.dns.enable))
    {
      sopsFile = /. + "${ferrum.secretsDir}/${credentialSecret}.sops";
      format = "binary";
      owner = "acme";
      group = "acme";
    };

  # lego reads CLOUDFLARE_DNS_API_TOKEN from this file via systemd's
  # EnvironmentFile= mechanism (confirmed by reading
  # nixos/modules/security/acme/default.nix: `environmentFile` is passed
  # straight through as systemd's own `EnvironmentFile=`, exactly like
  # every other secret this project wires -- never Nix-interpolated).
  # ferrum.secrets."acme-dns" is the existing default from
  # ferrum.proxy.acme.credentialSecret; the operator writes this secret
  # via ferrumd (Phase 1.5) or by hand with sops, same as
  # qBittorrent's VPN config in Phase 1.4a.
  security.acme.certs = lib.mapAttrs'
    (_: app: lib.nameValuePair (vhostNameFor app) {
      dnsProvider = ferrum.proxy.acme.dnsProvider;
      environmentFile = config.sops.secrets."${credentialSecret}".path;
      group = nginxGroup;
      server = lib.mkIf ferrum.proxy.acme.staging
        "https://acme-staging-v02.api.letsencrypt.org/directory";
    })
    publicApps
  // lib.optionalAttrs daemonPublished {
    # The control plane's own certificate (A6). Same shape as an app's entry
    # above and the auth vhost's below -- same provider, same token, same
    # staging switch -- keyed by the vhost name modules/proxy/nginx.nix's
    # daemon vhost references through useACMEHost.
    "${daemonVhostNameValue}" = {
      dnsProvider = ferrum.proxy.acme.dnsProvider;
      environmentFile = config.sops.secrets."${credentialSecret}".path;
      group = nginxGroup;
      server = lib.mkIf ferrum.proxy.acme.staging
        "https://acme-staging-v02.api.letsencrypt.org/directory";
    };
  }
  // lib.optionalAttrs (ferrum.auth.enable && realCertsNeeded) {
    "auth.${ferrum.proxy.baseDomain}" = {
      dnsProvider = ferrum.proxy.acme.dnsProvider;
      environmentFile = config.sops.secrets."${credentialSecret}".path;
      group = nginxGroup;
      server = lib.mkIf ferrum.proxy.acme.staging
        "https://acme-staging-v02.api.letsencrypt.org/directory";
    };
  };
}
