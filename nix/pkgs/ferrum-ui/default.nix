# The ferrum web UI, packaged by copying a directory.
#
# That is the entire build. `ui/` is hand-written HTML, CSS and ES modules
# with no build step, no npm and no bundler, which is a deliberate stack
# choice rather than an unfinished one: there is no node in the closure, no
# fixed-output hash to regenerate when a dependency bumps, no lockfile to
# drift, and nothing between the source an operator can read and the bytes
# the daemon serves. A `runCommand` copy is the honest expression of that.
#
# Consumed by modules/core/daemon.nix as FERRUM_UI_DIR. It must therefore
# exist in BOTH nix/modules/flake/packages.nix (the flake output) and
# nix/overlays/default.nix (which is what populates pkgs.* inside the NixOS
# module tree) -- a package defined only as a flake output builds fine and
# then fails at host eval with "attribute 'ferrum-ui' missing". That has now
# happened three times in this repository: ferrum-reconcile in Phase 1.4c,
# ferrumd, and ferrum-catalog in Phase 1.5b Task 2.
{ runCommand, uiSrc }:
runCommand "ferrum-ui" { } ''
  mkdir -p $out/share/ferrum/ui
  cp -r ${uiSrc}/. $out/share/ferrum/ui/
''
