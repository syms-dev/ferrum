# Shared helpers for every modules/proxy/*.nix file. Plain pure functions of
# `ferrum` (config.ferrum), not a NixOS module -- imported directly, the same
# way modules/lib/catalog.nix is, never added to any imports list.
{ lib }:
{
  vhostNameFor = ferrum: app: "${app.subdomain}.${ferrum.proxy.baseDomain}";
  exposedApps = ferrum: lib.filterAttrs
    (_: app: app.enable && app.exposure != "local")
    ferrum.apps;
  publicApps = ferrum: lib.filterAttrs
    (_: app: app.enable && app.exposure == "public")
    ferrum.apps;
  selfSignedCertDir = "/var/lib/ferrum-proxy/selfsigned";
  # The single gate for "does this app get Authelia forward-auth": auth
  # must be on, the proxy must be on (auth_request has nothing to sit in
  # front of otherwise), the app must actually have a vhost (exposure !=
  # "local"), and the app itself must not have opted out via a "bypass"
  # policy. Used identically by modules/proxy/nginx.nix's auth_request
  # wiring AND every servarr app's native-login-disable -- before this,
  # those two used different conditions (nginx.nix checked all four
  # properties, the servarr apps checked only auth.enable), so a host with
  # auth on but proxy off, or any local-exposure app, or a bypass-policy
  # public app, ended up with native login off and NO forward-auth in its
  # place (found during the final whole-branch review).
  authGated = ferrum: app:
    ferrum.auth.enable
    && ferrum.proxy.enable
    && app.exposure != "local"
    && app.auth.policy != "bypass";
}
