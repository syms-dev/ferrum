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
{ config, lib, pkgs, revision, ... }:
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
  #
  # ferrum.extraUnfreePackages joins the SAME union rather than being
  # allowed a predicate of its own, and the predicate below stays without
  # lib.mkDefault. Both of those are deliberate.
  #
  # nixpkgs.config is types.attrs, so definitions of it merge with `//` and
  # a later one WINS -- silently, with no conflict error. Measured at
  # 03d569f: a /etc/ferrum/custom/ module setting its own
  # allowUnfreePredicate produced a host where the predicate answered
  # plexmediaserver = false and unrar = false. The operator added one
  # package and took Plex and SABnzbd out, and the only symptom is a build
  # failure naming a package they never touched.
  #
  # lib.mkDefault does not fix that; it blesses it. It would let the custom
  # definition win CLEANLY, which is the same silent loss with a tidier
  # mechanism. The composable thing is the LIST, so the list is what this
  # option extends.
  unfreePackageNames = lib.unique (
    lib.concatMap (app: app.unfreePackages or [ ]) (lib.attrValues catalog)
    ++ ferrum.extraUnfreePackages
  );

  # Only the three servarr apps ferrum-apply's secrets.rs module actually
  # generates keys for (see crates/ferrum-apply/src/secrets.rs's own
  # SERVARR_APPS list) -- qBittorrent/Plex/Jellyfin/SABnzbd have their own
  # auth mechanisms and are deliberately excluded even if enabled.
  enabledServarrApps = lib.filter
    (id: ferrum.apps.${id}.enable or false)
    [ "sonarr" "radarr" "prowlarr" ];

  # ferrum-apply's encrypt side (crates/ferrum-apply/src/secrets.rs) derives
  # its age recipient from a hardcoded default public-key path unless told
  # otherwise. sops-nix's own decrypt side reads config.sops.age.sshKeyPaths
  # (which defaults to config.services.openssh.hostKeys's ed25519 entries,
  # see modules/core/secrets.nix) -- the default coincides with the Rust
  # side's hardcoded path today, but an operator overriding
  # services.openssh.hostKeys in custom/ (a different path, a different key
  # type, a key on another volume) would silently desync the two sides:
  # ferrum-apply would encrypt to a recipient sops-nix never decrypts with,
  # and activation would fail with a decryption error nowhere near this
  # cause. Passing the REAL configured path through, the same way
  # FERRUM_SECRETS_DIR/FERRUM_SERVARR_APPS already prevent this class of
  # drift, closes it. sops.age.sshKeyPaths holds PRIVATE key paths; the
  # public key sits alongside it at the same path plus ".pub" (standard
  # OpenSSH convention, and the only relationship ssh-to-age itself relies
  # on). Guarded with `or [ ]`/lib.optionalString so a host with
  # sops.age.sshKeyPaths somehow empty just falls back to the Rust side's
  # own hardcoded default instead of failing this eval.
  #
  # builtins.toString (not plain string interpolation) on the list element:
  # sops.age.sshKeyPaths is typed `types.listOf types.path`, and
  # interpolating a genuine Nix PATH value (as opposed to a string that
  # merely looks like one) copies it into the Nix store and yields that
  # store path instead of the literal text -- which here would mean
  # copying the PRIVATE host key into the world-readable store and
  # producing a nonsensical ".pub" path. Today's real default (via
  # config.services.openssh.hostKeys) happens to pass a plain string
  # through unchanged, so this has no observable effect yet, but
  # builtins.toString makes the expression correct regardless of which
  # representation a future value takes -- the same class of Nix
  # path-vs-string footgun this branch already spent multiple rounds
  # chasing for `sopsFile` (see modules/apps/sonarr/service.nix's comment).
  hostKeyPubPath =
    let paths = config.sops.age.sshKeyPaths or [ ];
    in lib.optionalString (paths != [ ]) "${builtins.toString (lib.head paths)}.pub";
  # ferrum-apply's own compiled-in fallback is
  # "/etc/ferrum#nixosConfigurations.default...", which quietly assumes every
  # host flake names its configuration `default`. Real host flakes name it
  # after the machine -- examples/hosts/template and docs/INSTALL.md both say
  # to -- so on the first real ferrum host a bare `ferrum-apply apply` failed
  # outright. Deriving it from this host's own hostName makes it always
  # correct, and the operator never has to learn the variable exists.
  #
  # NOTE FOR ANYONE EDITING THE makeWrapper BLOCK BELOW: it is one shell
  # command held together by trailing backslashes, so a `#` comment must
  # never be placed between two of its lines. The backslash joins the
  # comment into the command, everything after `#` is discarded, and every
  # following `--set-default` becomes a standalone command -- which fails
  # the build with the genuinely baffling "--set-default: command not
  # found". That really happened here; hence this binding.
  defaultFlakeRef =
    "/etc/ferrum#nixosConfigurations.${config.networking.hostName}.config.system.build.toplevel";
in
{
  nixpkgs.config.allowUnfreePredicate = pkg:
    builtins.elem (lib.getName pkg) unfreePackageNames;

  nixpkgs.overlays = [
    (import ../../nix/overlays)
    (final: prev: {
      # modules/core/daemon.nix's FERRUM_CATALOG consumes pkgs.ferrum-catalog.
      # It lived only in nix/modules/flake/packages.nix, which builds the
      # package but does NOT populate pkgs.* inside this module tree -- so
      # `nix flake check` passed while every real host eval failed with
      # "attribute 'ferrum-catalog' missing". That is the third instance of
      # the gap nix/overlays/default.nix's own ferrumd comment warns about.
      #
      # Defined in THIS config-wiring overlay rather than the base one
      # because it needs the `revision` specialArg, and the base overlay is a
      # plain `final: prev:` with no access to the module arguments.
      #
      # `revision` is mkHost's own parameter (modules/lib/default.nix:25),
      # threaded through specialArgs and, until now, consumed by NOTHING --
      # it was wired up waiting for exactly this consumer. Real host flakes
      # already pass their own `self.shortRev` (examples/hosts/template's
      # flake.nix:41 and saltbox's do), and checks.nix passes "ci", so using
      # it here makes ferrumVersion true on every existing host with no
      # host-flake change at all. Its default is "unknown".
      ferrum-catalog = prev.writeTextFile {
        name = "ferrum-catalog.json";
        destination = "/share/ferrum/catalog.json";
        # schemaVersion is the literal 1, mirroring the flake package byte for
        # byte rather than reading ferrum.schemaVersion. Both resolve to 1
        # today (modules/lib/migrations.nix has an empty migration list), but
        # the option is computed as `length migrations + 1` while the flake
        # package hardcodes it -- so reading the option here would make the two
        # producers disagree the first time a migration is added. Consistently
        # stale is better than newly divergent; that the flake package
        # hardcodes it at all is a separate pre-existing bug.
        text = builtins.toJSON {
          schemaVersion = 1;
          ferrumVersion = revision;
          apps = catalog;
        };
      };

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
            --set-default FERRUM_FLAKE_REF ${lib.escapeShellArg defaultFlakeRef} \
            --set-default FERRUM_KEEP_GENERATIONS ${toString ferrum.storage.keepGenerations} \
            --set-default FERRUM_HEALTH_CHECK_TIMEOUT_SEC ${toString ferrum.apply.healthCheckTimeoutSec} \
            --set-default FERRUM_SECRETS_DIR ${lib.escapeShellArg ferrum.secretsDir} \
            --set-default FERRUM_SERVARR_APPS ${lib.escapeShellArg (lib.concatStringsSep "," enabledServarrApps)} \
            ${lib.optionalString (hostKeyPubPath != "")
              "--set-default FERRUM_HOST_KEY_PUB ${lib.escapeShellArg hostKeyPubPath}"} \
            --set-default FERRUM_AUTH_ENABLED ${if ferrum.auth.enable then "1" else "0"} \
            --set-default FERRUM_AUTHELIA_STATE_DIR "/var/lib/authelia-main" \
            --set-default FERRUM_ADMIN_EMAIL ${lib.escapeShellArg ferrum.auth.adminEmail} \
            --set-default FERRUM_SABNZBD_STATE_DIR ${lib.escapeShellArg (if ferrum.apps.sabnzbd.enable or false then ferrum.apps.sabnzbd.stateDir else "")} \
            --set-default FERRUM_SABNZBD_PORT ${toString (ferrum.apps.sabnzbd.port or 8080)}
        '' // {
        meta = (prev.ferrum-apply.meta or { }) // { mainProgram = "ferrum-apply"; };
      };
    })
  ];

  # Put the operator's own CLI on PATH.
  #
  # FOUND ON THE FIRST REAL INSTALL, 2026-09-15: nothing in this module tree
  # had ever set environment.systemPackages, so `ferrum-apply` existed only
  # as a store path referenced by the ferrum-apply@ template unit's
  # ExecStart. On a real booted ferrum host the operator typed
  # `ferrum-apply apply` and got "command not found" -- which is the entire
  # documented workflow (docs/INSTALL.md's own first-boot and rollback
  # steps, and every "then re-apply" instruction in README.md) rendered
  # impossible.
  #
  # Every VM test missed it for the same structural reason: they invoke the
  # binary through the systemd unit or by explicit store path, never as a
  # bare command the way a human does.
  #
  # This is `pkgs.ferrum-apply`, so it resolves to the OVERLAID, wrapped
  # derivation defined above -- the one carrying every FERRUM_* default for
  # this host. An operator running it by hand gets exactly the same
  # environment a ferrumd-dispatched run gets, which is what makes the two
  # paths genuinely equivalent rather than superficially similar.
  environment.systemPackages = [
    pkgs.ferrum-apply

    # git is NOT optional on a ferrum host, and its absence is not a
    # convenience gap.
    #
    # /etc/ferrum is a git repository by design, because Nix SILENTLY
    # IGNORES untracked files inside a git tree -- an untracked
    # custom/whatever.nix is not "added but broken", it simply does not
    # exist as far as evaluation is concerned. So every documented
    # operator action there ends in `git add`, and ferrum-apply evaluates
    # that repo on every run.
    #
    # Without git the host cannot perform the actions its own design
    # requires. Found on the first real install: the installer's own R6 A2
    # commit of the generated hardware-configuration.nix failed with
    # "bash: line 1: git: command not found", leaving the real hardware
    # configuration present in the working tree but UNTRACKED -- i.e.
    # invisible to Nix, on the one file the host cannot boot correctly
    # without.
    pkgs.git
  ];
}
