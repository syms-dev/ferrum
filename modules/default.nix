# The ferrum NixOS module. Import this once from a host flake (normally via
# ferrum.lib.mkHost) to get the whole ferrum.* option namespace plus every
# app in the catalog, each gated on its own ferrum.apps.<id>.enable.
{ lib, ... }:
{
  # The settings document a host was built from, consumed by
  # ./core/bootstrap.nix to seed /etc/ferrum/settings.json on a brand-new
  # machine. ferrum.lib.mkHost overrides this with the real value.
  #
  # It MUST be declared here with mkDefault rather than relying on a
  # `ferrumSettingsSeed ? null` default in bootstrap.nix's own function
  # signature. That does not work for NixOS module arguments, and the
  # failure is not obvious: the module system resolves an argument by
  # looking up `config._module.args.<name>` and errors with "attribute
  # 'ferrumSettingsSeed' missing" if it is absent, never consulting the
  # function's default at all.
  #
  # Confirmed for real: with only the signature default, every test that
  # does `imports = [ ../modules ]` directly rather than going through
  # mkHost -- tests/rollback.nix, tests/apply-generation-switch.nix,
  # tests/privilege-boundary.nix and both daemon tests -- failed to
  # evaluate. mkHost's own plain assignment outranks this mkDefault.
  _module.args.ferrumSettingsSeed = lib.mkDefault null;

  # The ferrum revision this host was built from, consumed by
  # ./core/overlays.nix for ferrum-catalog's `ferrumVersion`. Same rule as
  # ferrumSettingsSeed above, and for the same reason: a `revision ?
  # "unknown"` default in overlays.nix's own signature is NOT consulted by
  # the module system, which looks up config._module.args.revision and
  # errors "attribute 'revision' missing" if it is absent.
  #
  # Confirmed for real: without this line every VM test failed to evaluate,
  # because pkgs.testers.runNixOSTest does `imports = [ ../modules ]`
  # directly and never goes through mkHost (see tests/privilege-boundary.nix's
  # own note). mkHost passes revision via specialArgs, which outranks this
  # mkDefault, so a real host still reports its true shortRev.
  _module.args.revision = lib.mkDefault "unknown";

  imports = [
    ./core/options.nix
    ./core/nix-settings.nix
    ./core/bootstrap.nix
    ./core/storage.nix
    ./core/pool.nix
    ./core/overlays.nix
    ./core/generations.nix
    ./core/state-restore.nix
    ./core/secrets.nix
    ./core/daemon.nix
    ./core/recyclarr.nix
    ./core/reconciler.nix
    ./proxy/acme.nix
    ./proxy/nginx.nix
    ./proxy/selfsigned-cert.nix
    ./proxy/authelia.nix
    ./apps/sonarr/service.nix
    ./apps/radarr/service.nix
    ./apps/prowlarr/service.nix
    ./apps/jellyfin/service.nix
    ./apps/plex/service.nix
    ./apps/sabnzbd/service.nix
    ./apps/qbittorrent/service.nix
  ];
}
