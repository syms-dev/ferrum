# Wire the ferrum overlay into nixpkgs so that pkgs.ferrum-apply and
# pkgs.ferrum-testapp are available to the other modules in this tree, then
# layer a second overlay on top that bakes ferrum.storage.*/ferrum.apply.*
# into pkgs.ferrum-apply as env-var defaults, so the CLI can never silently
# disagree with this host's own config -- whether it's invoked from a
# systemd unit (ferrum-state-restore already does this for
# FERRUM_ROOT_DEVICE, see state-restore.nix) or by hand over SSH, which is
# the only way apply/rollback are invoked before Phase 1.5's daemon exists
# to run them itself.
#
# Defined directly rather than reusing nix/modules/flake/overlays.nix's
# `flake.overlays.default`: that value lives in flake-parts' own `config`,
# a different module system evaluated at the flake level -- there is no
# `config.flake` inside a NixOS configuration (this module's `config` is
# the system configuration tree, e.g. `config.systemd.services...`, not
# the flake's own outputs), so a NixOS module can't reach it that way.
#
# Both overlays MUST be elements of the SAME list literal, in this order.
# They were originally two separate modules each setting `nixpkgs.overlays`
# independently -- NixOS concatenates `nixpkgs.overlays` definitions across
# modules, but NOT in import-declaration order (confirmed by hand: the
# config-wiring overlay, imported after this one, still ended up applied
# BEFORE the base overlay, so the base's plain `ferrum-apply =
# final.callPackage ...` silently clobbered the wrapper). A single list
# literal has no such ambiguity -- Nix list order is exactly written order.
{ config, lib, ... }:
let
  ferrum = config.ferrum;

  # Aggregated here, not per-app: nixpkgs.config.allowUnfreePredicate holds
  # a single function value, and NixOS's module system does not compose
  # two independently-defined functions from different modules the way it
  # composes nixpkgs.overlays' list -- two apps each setting their own
  # predicate (as Plex originally did, before this fix) produces a
  # conflicting-definitions eval error the moment BOTH are enabled on the
  # same host, not a silent union. Confirmed for real: enabling Plex
  # (plexmediaserver) and SABnzbd (whose sabnzbd package depends on the
  # unfree `unrar`) together on the same host is exactly the case that
  # would trigger it. Every catalog app's meta.nix may declare
  # `unfreePackages = [ "name" ... ];` (omitted/absent means none); this
  # collects the union across the WHOLE catalog, regardless of which apps
  # are actually enabled -- harmless, since an unfree package that's never
  # referenced (a disabled app) is never built regardless of whether its
  # name appears in this allowlist.
  catalog = import ../lib/catalog.nix { inherit lib; };
  unfreePackageNames = lib.unique (
    lib.concatMap (app: app.unfreePackages or [ ]) (lib.attrValues catalog)
  );

  # Only the three servarr apps ferrum-apply's secrets.rs module actually
  # generates keys for (see crates/ferrum-apply/src/secrets.rs's own
  # SERVARR_APPS list) -- qBittorrent/Plex/Jellyfin/SABnzbd have their own
  # auth mechanisms and are deliberately excluded even if enabled.
  enabledServarrApps = lib.filter
    (id: ferrum.apps.${id}.enable or false)
    [ "sonarr" "radarr" "prowlarr" ];
in
{
  nixpkgs.config.allowUnfreePredicate = pkg:
    builtins.elem (lib.getName pkg) unfreePackageNames;

  nixpkgs.overlays = [
    (import ../../nix/overlays)
    (final: prev: {
      # `--set-default` (not `--set`): a caller's own explicit environment=
      # still wins, matching how ferrum-state-restore.service sets
      # FERRUM_ROOT_DEVICE itself today. Only a host that changes these
      # from ferrum's own defaults is affected in practice.
      #
      # Wraps the ALREADY-wrapped base ferrum-apply (which wraps in
      # `btrfs` via its own postFixup) rather than replacing it --
      # wrapping a wrapper composes fine, since each layer just execs the
      # next and env vars are inherited through exec.
      ferrum-apply = prev.runCommand "ferrum-apply"
        { nativeBuildInputs = [ prev.makeWrapper ]; }
        ''
          mkdir -p $out/bin
          makeWrapper ${prev.ferrum-apply}/bin/ferrum-apply $out/bin/ferrum-apply \
            --set-default FERRUM_STATE_DIR ${lib.escapeShellArg ferrum.storage.stateDir} \
            --set-default FERRUM_SNAPSHOT_DIR ${lib.escapeShellArg ferrum.storage.snapshotDir} \
            --set-default FERRUM_JOURNAL_DIR ${lib.escapeShellArg ferrum.storage.journalDir} \
            --set-default FERRUM_MIN_FREE_GIB ${toString ferrum.storage.minFreeGiB} \
            --set-default FERRUM_HEALTH_CHECK_TIMEOUT_SEC ${toString ferrum.apply.healthCheckTimeoutSec} \
            --set-default FERRUM_SECRETS_DIR ${lib.escapeShellArg ferrum.secretsDir} \
            --set-default FERRUM_SERVARR_APPS ${lib.escapeShellArg (lib.concatStringsSep "," enabledServarrApps)}
        '' // {
        meta = (prev.ferrum-apply.meta or { }) // { mainProgram = "ferrum-apply"; };
      };
    })
  ];
}
