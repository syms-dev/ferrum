# Shared helpers for every modules/proxy/*.nix file. Plain pure functions of
# `ferrum` (config.ferrum), not a NixOS module -- imported directly, the same
# way modules/lib/catalog.nix is, never added to any imports list.
{ lib }:
{
  vhostNameFor = ferrum: app: "${app.subdomain}.${ferrum.proxy.baseDomain}";

  # Every app that gets an nginx vhost at all -- "local" apps are reached
  # only through ferrumd's own internal proxying (Phase 1.5), matching
  # modules/lib/app-submodule.nix's own doc comment on the exposure option.
  exposedApps = ferrum: lib.filterAttrs
    (_: app: app.enable && app.exposure != "local")
    ferrum.apps;

  # The subset of exposedApps that also needs a real ACME certificate.
  publicApps = ferrum: lib.filterAttrs
    (_: app: app.enable && app.exposure == "public")
    ferrum.apps;

  # Where modules/proxy/selfsigned-cert.nix persists the self-signed
  # certificate "lan"-exposure vhosts (and the auth vhost, when no app is
  # public) use -- shared with nginx.nix so both files agree on the path
  # without duplicating the string literal.
  selfSignedCertDir = "/var/lib/ferrum-proxy/selfsigned";
}
