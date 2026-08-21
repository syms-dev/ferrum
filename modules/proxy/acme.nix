# ACME certificate issuance via Cloudflare DNS-01, for every catalog app
# (and, later, the daemon) exposed publicly. One security.acme.certs entry
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
in
lib.mkIf proxyEnabled {
  security.acme.acceptTerms = true;
  security.acme.defaults.email = ferrum.proxy.acme.email;

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
    (id: app: lib.nameValuePair (vhostNameFor app) {
      dnsProvider = ferrum.proxy.acme.dnsProvider;
      environmentFile = /. + "${ferrum.secretsDir}/${ferrum.proxy.acme.credentialSecret}.sops";
      server = lib.mkIf ferrum.proxy.acme.staging
        "https://acme-staging-v02.api.letsencrypt.org/directory";
    })
    publicApps;
}
