# Where an enabled catalog app actually listens, as seen from the ROOT
# network namespace. A plain pure function of `ferrum` (config.ferrum), not
# a NixOS module -- imported directly, the same way modules/lib/catalog.nix
# and modules/lib/hostnames.nix are, never added to any imports list.
#
# WHY THIS FILE EXISTS, AND WHY IT IS HERE RATHER THAN IN modules/proxy/.
#
# "127.0.0.1" is true for six of the seven catalog apps and false for the
# seventh. modules/apps/qbittorrent/service.nix sets NetworkNamespacePath=
# whenever a "qbittorrent-vpn" secret is declared, so qBittorrent's WebUI
# binds inside the `qbt-vpn` namespace and is reachable from the root
# namespace only across that file's own veth pair, at 10.200.1.2.
#
# Two things in this tree have to know that, and before this file only one
# of them did. modules/core/reconciler.nix carried the exception (so
# Sonarr/Radarr/Prowlarr were registered against the right address), while
# modules/proxy/nginx.nix rendered `proxy_pass http://127.0.0.1:<port>` for
# every app with no exception at all. The result was measured on the
# owner's host on 2026-10-06: nothing listens on 127.0.0.1:8090 in the root
# namespace, `curl http://127.0.0.1:8090/` exits 7, and
# `curl http://10.200.1.2:8090/` returns 200 -- so the vhost an app gets by
# DEFAULT (app-submodule.nix's exposure = "public") could not reach it.
# Authelia's forward-auth answers an unauthenticated probe with a 302
# before nginx ever dials the backend, which is why it looked healthy.
#
# The home is modules/lib/ rather than modules/proxy/lib.nix because the
# reconciler is not proxy-side: it runs on hosts with proxy.enable = false,
# and proxy/lib.nix says in its own first line that it is "shared helpers
# for every modules/proxy/*.nix file". Pointing a core module at a proxy
# module's helper inverts that dependency. The other direction is not
# available either -- modules/core/reconciler.nix is a NixOS module taking
# `{ config, lib, pkgs, ... }`, so it cannot be imported as a value. This
# directory is where the repo already keeps the pure helpers BOTH lanes
# import, so it is the only home both consumers can legally read.
#
# nix/modules/flake/checks.nix's `netns-apps-are-proxied-reachably` is the
# mechanical half: it derives "this app is in a namespace" from the
# evaluated systemd units rather than from this table, so a THIRD consumer
# that hand-copies 127.0.0.1 fails there instead of in the field.
{ lib }:
rec {
  # The address every app that is not placed in a namespace listens on.
  # Each app's own service.nix pins its bind address to this (see
  # sonarr/radarr/prowlarr's `bindaddress`).
  loopback = "127.0.0.1";

  # app id -> the root-namespace-reachable address of that app, for every
  # app THIS host puts in a network namespace. Empty on every host with no
  # VPN secret, which is what keeps the non-VPN output unchanged.
  #
  # Deliberately a table rather than per-app metadata in meta.nix: whether
  # qBittorrent is namespaced is a property of the HOST's configuration
  # (does a "qbittorrent-vpn" secret exist), not a static fact about the
  # app, and meta.nix is static. A second namespaced app is one more line
  # here, read by both consumers at once -- which is the whole point.
  #
  # 10.200.1.2 is the namespace side of the veth pair
  # modules/apps/qbittorrent/service.nix creates (10.200.1.1 <-> 10.200.1.2,
  # a /30), and the same file whitelists that /30 for WebUI auth precisely
  # because a caller arriving over it is not loopback.
  namespacedHosts = ferrum:
    lib.optionalAttrs (ferrum.secrets ? "qbittorrent-vpn") {
      qbittorrent = "10.200.1.2";
    };

  # The address a root-namespace caller -- nginx, the reconciler -- must
  # dial to reach app `id` on this host.
  hostFor = ferrum: id: (namespacedHosts ferrum).${id} or loopback;

  # The port app `id` ACTUALLY listens on, which is not always the port the
  # operator set.
  #
  # `ferrum.apps.<id>.port` is one uniform option across the catalog, and
  # that uniformity is what lets the UI render one form rather than seven --
  # but Plex and Jellyfin cannot honour it at any layer, which is what the
  # catalog's `portIsFixed` mark records. modules/core/options.nix asserts a
  # moved port on a marked app ("a port it cannot honour"), so on a host that
  # evaluates at all the two values agree; this function is what makes the
  # ADDRESS correct rather than merely consistent with an assertion
  # elsewhere.
  #
  # It was added for ferrumd's per-app health probe, and the reason is the
  # same defect this whole file exists for, one layer down. The measurement
  # recorded in nix/modules/flake/checks.nix's `fixed-ports-are-enforced`:
  # `plex.port = 9999` once rendered `proxy_pass http://127.0.0.1:9999` while
  # Plex went on serving 32400. A health probe built on the same value would
  # report Plex as REFUSED on a host where Plex is running perfectly -- a
  # status wrong in the alarming direction, which sends an operator to debug
  # an app that is fine.
  #
  # modules/proxy/nginx.nix still builds its upstream from `app.port`
  # directly and is protected by the assertion alone. Pointing it here too
  # would be the smaller statement of the same fact, and is deliberately left
  # for whoever next touches that file: it is not this change's to make.
  portFor = catalog: ferrum: id:
    if catalog.${id}.portIsFixed or false
    then catalog.${id}.defaultPort
    else ferrum.apps.${id}.port;

  # Both halves at once: the `host:port` a root-namespace caller must dial to
  # reach app `id`. The form ferrumd's `$FERRUM_APP_ADDRESSES` carries.
  addressFor = catalog: ferrum: id:
    "${hostFor ferrum id}:${toString (portFor catalog ferrum id)}";
}
