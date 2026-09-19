# Provisions /etc/ferrum on a real host, at real activation time.
#
# WHY THIS MODULE EXISTS. modules/core/daemon.nix gates ferrumd's startup on
# `unitConfig.AssertPathExists = [ "/etc/ferrum/settings.json"
# "/etc/ferrum/secrets" ]`, and the Phase 1.5a spec says those two paths are
# "provisioned once, at this exact ownership, by nixos-anywhere's own initial
# setup". Nothing ever implemented that. Until this module landed, NO module
# in the tree created /etc/ferrum at all -- so a freshly installed ferrum
# host booted with ferrumd permanently refusing to start, and the assertion
# meant to catch a mis-provisioned host instead caught every host. Found
# while building the Phase 1.6 install path, which is the first thing that
# ever had to produce a working box from nothing.
#
# THE OWNERSHIP MODEL is the one the 1.5a spec specifies, and each line of it
# is load-bearing rather than decorative:
#
#   /etc/ferrum/          root:root  0755  ferrumd can traverse, NOT create
#   /etc/ferrum/settings.json  root:ferrum 0664  ferrumd can rewrite THIS file
#   /etc/ferrum/secrets/  ferrum:ferrum 0750  ferrumd creates .sops files here
#   /etc/ferrum/custom/   root:root  0755  ferrumd can never touch this
#
# The parent stays root-owned precisely so a compromised ferrumd cannot
# create new entries beside settings.json -- in particular it can never drop
# a .nix file into custom/, which is what makes "compromising ferrumd yields
# the power expressed by the settings schema, not arbitrary Nix evaluation as
# root" true. Write permission on a directory is create/delete/rename
# permission on every name in it regardless of the individual files' modes;
# modules/core/storage.nix's own header explains this for /var/lib/ferrum and
# the identical reasoning applies here.
#
# THE SEED VALUE is threaded in as a module argument (`ferrumSettingsSeed`,
# set by ferrum.lib.mkHost) rather than reconstructed from the evaluated
# `config.ferrum`. That distinction is not stylistic. settings-schema.json
# declares `additionalProperties: false` at the top level and inside storage,
# proxy and auth, while the evaluated option tree carries far more than the
# schema admits -- every app submodule's derived defaults, `_module`, and
# every option an operator never wrote. Re-serializing that tree would seed a
# document that ferrumd's own PUT /api/settings validation then rejects,
# which is the most confusing possible first-boot state: a host whose own
# settings file is invalid by its own schema.
#
# A module argument rather than a new `ferrum.*` option, because anything
# declared under options.ferrum is walked by checks.schema-uniformity and
# forms part of the settings surface the security thesis reasons about. This
# value is build-time plumbing, not a setting.
#
# Its null default is declared in modules/default.nix via mkDefault, NOT as a
# `? null` in this signature -- see that file for why the signature form
# silently does not work.
{ config, lib, pkgs, ferrumSettingsSeed, ... }:
let
  ferrum = config.ferrum;

  # Same fallback as modules/core/storage.nix: on a host with
  # ferrum.daemon.enable = false the `ferrum` group does not exist, and
  # naming a nonexistent group makes tmpfiles fail at boot.
  ferrumdGroup = if ferrum.daemon.enable then "ferrum" else "root";

  # The operator's own settings document, post-migration -- exactly what
  # mkHost fed into config.ferrum, so it is the CURRENT schema version rather
  # than whatever older shape the file on the operator's disk was in.
  seedSettings = pkgs.writeText "ferrum-settings-seed.json"
    (builtins.toJSON ferrumSettingsSeed);

  # A host built by something other than mkHost (a bare `imports = [ ferrum
  # ]`, or a test) supplies no seed. Seeding an empty file would be worse
  # than seeding nothing: ferrumd would start against a settings document
  # that does not describe this host at all, and the operator's first PUT
  # would write that fiction back. Skip the seed instead and let daemon.nix's
  # AssertPathExists do its real job of refusing to start.
  haveSeed = ferrumSettingsSeed != null;
in
{
  systemd.tmpfiles.rules = [
    # Parent first: tmpfiles processes rules in path order within a run, but
    # declaring the parent explicitly is what pins its mode to 0755 rather
    # than inheriting whatever a `d` rule for a child would create it as.
    "d /etc/ferrum 0755 root root - -"

    # `C` = copy the argument to this path ONLY IF the path does not already
    # exist. This is the whole mechanism: it seeds a brand-new host, and it
    # is a no-op on every subsequent activation of an existing one.
    #
    # This MUST NOT be `L` (symlink) or a plain `f` with content. ferrumd
    # rewrites this file in place on every real PUT /api/settings, and the
    # operator edits it by hand; pointing it at a read-only store path, or
    # rewriting it from the flake on each activation, would silently discard
    # every change either of them made. The file is the daemon's, not the
    # module's, from the moment it first exists.
  ] ++ lib.optional haveSeed
    "C /etc/ferrum/settings.json 0664 root ${ferrumdGroup} - ${seedSettings}"

  # ...and then FIX the ownership of whatever is there, seeded or not.
  #
  # `C` only acts when the path does not exist, so on any host whose
  # settings.json arrived by another route it is a no-op -- and the file
  # keeps the ownership that route gave it. That case was assumed rare
  # ("a host provisioned before this module existed"), but it is now the
  # NORMAL path: ferrum-install ships settings.json through
  # nixos-anywhere's --extra-files, which extracts it as root:root 0644.
  # So every single fresh install ended activation printing "ferrumd will
  # not be able to save settings changes", and it was right -- the web UI
  # could not write its own settings file on a brand-new host.
  #
  # `z` adjusts mode/ownership of an existing path WITHOUT creating it and
  # without touching contents, which is exactly the missing half. It is
  # deliberately not `Z`: recursion here would walk secrets/ and custom/,
  # whose ownership is set separately and differently below.
  ++ [
    "z /etc/ferrum/settings.json 0664 root ${ferrumdGroup} - -"
  ]
  ++ [

    # Owned by ferrum, not root: ferrumd CREATES files in here (one .sops
    # file per secret, written by POST /api/secrets/:name), which needs write
    # permission on the directory itself, not just on the files.
    "d ${ferrum.secretsDir} 0750 ${ferrumdGroup} ${ferrumdGroup} - -"

    # Root-owned and ferrumd-unreachable, by design. This is the directory
    # holding hand-written Nix that survives an update -- the thing the
    # README promises Saltbox destroys and ferrum does not.
    "d /etc/ferrum/custom 0755 root root - -"
  ];

  # A host that was provisioned before this module existed has a
  # settings.json at whatever ownership nixos-anywhere's operator gave it,
  # and `C` above will not touch an existing file -- so its mode is NOT
  # corrected by the rule. Rather than silently leaving ferrumd unable to
  # write its own settings file, say so at activation, where an operator
  # running nixos-rebuild actually sees it.
  system.activationScripts.ferrumSettingsOwnership = lib.mkIf ferrum.daemon.enable ''
    if [ -e /etc/ferrum/settings.json ]; then
      if [ ! -w /etc/ferrum/settings.json ] || \
         [ "$(${pkgs.coreutils}/bin/stat -c %G /etc/ferrum/settings.json)" != "ferrum" ]; then
        echo "ferrum: /etc/ferrum/settings.json is not group-writable by 'ferrum';" >&2
        echo "        ferrumd will not be able to save settings changes." >&2
        echo "        Fix with: chown root:ferrum /etc/ferrum/settings.json && chmod 0664 /etc/ferrum/settings.json" >&2
      fi
    fi
  '';
}
