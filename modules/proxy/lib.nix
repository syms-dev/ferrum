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

  # The daemon, shaped like a catalog app.
  #
  # Four mechanisms in this directory take a catalog app as their unit and so
  # silently excluded ferrumd: authelia.nix's access_control.rules (built from
  # exposedApps), acme.nix's security.acme.certs (built from publicApps), and
  # nginx.nix's mkVhost / authGated. Patching each one independently
  # reproduces the same omission four times -- which is precisely the failure
  # the R13 planning panel found four separate times -- so there is ONE value
  # here that all of them consume instead.
  #
  # This is an internal value, NOT an operator-facing option: nothing in it is
  # settable, modules/lib/settings-schema.json does not change, and its only
  # operator inputs are ferrum.daemon.subdomain and ferrum.daemon.port, which
  # already exist. The literals are the REAL enums from
  # modules/lib/app-submodule.nix -- exposure is enum [ "local" "lan"
  # "public" ] and auth.policy is enum [ "bypass" "one_factor" "two_factor" ]
  # -- so every helper above treats this exactly as it treats a catalog app,
  # with no special case anywhere.
  #
  # "public" because the control plane gets a real certificate and a place on
  # the public listener (A1, A6). "one_factor" because it is forward-auth
  # gated exactly like a catalog app (A2) -- never "bypass", which authGated
  # reads as an opt-out. bypassPaths is empty because the daemon exempts no
  # path from the edge gate: ferrumd's own session cookie stays authoritative
  # underneath it (D4), so unlike a servarr's /api there is nothing here that
  # needs to reach the daemon unauthenticated.
  daemonApp = ferrum: {
    subdomain = ferrum.daemon.subdomain;
    port = ferrum.daemon.port;
    exposure = "public";
    auth.policy = "one_factor";
    auth.bypassPaths = [ ];
  };

  # "Is the control plane actually published on a real hostname?" -- the
  # single predicate behind the daemon's vhost (nginx.nix), its Authelia rule
  # (authelia.nix), its certificate (acme.nix) and its DNS record (dns.nix).
  # Deliberately one definition
  # rather than four, because those four must agree EXACTLY or the dashboard
  # only half-exists: a vhost with no Authelia rule denies everyone (that
  # file's access_control.default_policy is "deny"), a vhost with no
  # certificate falls silently to the self-signed branch, and a record with
  # no vhost resolves to nginx's catch-all and a closed connection.
  #
  # Note what this is NOT keyed on: publicApps. A host publishing only the
  # dashboard, with every catalog app left at lan/local -- the safest
  # configuration available -- still publishes the dashboard (D6).
  #
  # `daemon.enable` and `daemon.publish` are two terms because they answer
  # two questions, and for a long time only the first existed.
  # modules/core/daemon.nix is wrapped in `lib.mkIf ferrum.daemon.enable`,
  # so turning that off does not unpublish ferrumd -- it deletes the system
  # user, the unit and the polkit rule, leaving nothing to reach even over
  # the SSH tunnel daemon.listenAddress exists for. That collapsed "do not
  # publish the dashboard" and "do not run a dashboard" into one line, and
  # the installer's stage 1 had to write it: stage 1 sets proxy.enable and a
  # real baseDomain because ACME needs both, and it structurally cannot
  # enable Authelia, whose sops secrets cannot exist before the host does,
  # so leaving the daemon at its default would have published settings,
  # apply and rollback on a real certificate with auth_request absent
  # entirely. The price of that correct decision was the bug: a stage 2 that
  # failed -- and stage 2 has failed on real hardware in this project more
  # than once -- left a host with no web UI at all and SSH-only recovery, on
  # a product whose whole claim is that the UI works.
  #
  # `publish` separates them. Stage 1 now runs a loopback-bound,
  # tunnel-reachable dashboard while every consumer of this predicate still
  # sees an unpublished host. It is NOT an authentication boundary: what it
  # removes is the network path, not ferrumd's own login.
  daemonPublished = ferrum:
    ferrum.daemon.enable
    && ferrum.daemon.publish
    && ferrum.proxy.enable
    && ferrum.proxy.baseDomain != "";
}
