# Assembles the app catalog by scanning modules/apps/*/meta.nix.
#
# This is what makes the catalog enumerable: adding an app means adding a
# directory, not registering it in a second place. checks.catalog-consistency
# (nix/modules/flake/checks.nix) asserts every app directory that has a
# meta.nix also has a service.nix, since a meta.nix with no service.nix
# would let the UI advertise an app that silently does nothing when enabled.
{ lib }:
let
  appsDir = ../apps;

  dirNames = builtins.attrNames (builtins.readDir appsDir);

  appIds = builtins.filter
    (id: builtins.pathExists (appsDir + "/${id}/meta.nix"))
    dirNames;

  loadMeta = id:
    let
      meta = import (appsDir + "/${id}/meta.nix");
    in
    if meta.id or id != id then
      throw "ferrum: modules/apps/${id}/meta.nix declares id '${meta.id}', which does not match its directory name '${id}'"
    else
      meta // { inherit id; };
in
lib.listToAttrs (map (id: { name = id; value = loadMeta id; }) appIds)
