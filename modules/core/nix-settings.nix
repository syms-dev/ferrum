# Base `nix` daemon settings every ferrum host needs, regardless of which
# apps are enabled.
#
# `ferrum-apply apply` (crates/ferrum-apply/src/apply.rs) shells out to
# `nix build --impure --no-link --print-out-paths ...` -- part of the new
# Nix CLI, which upstream Nix still gates behind these two experimental
# features. Nothing else in this module tree turned them on: a freshly
# provisioned host (nixos-anywhere, no operator-authored custom/ override)
# would fail its very first real apply job with "experimental Nix feature
# 'nix-command' is disabled". Enabling them here, unconditionally, for every
# ferrum host is what makes `ferrum-apply apply` work out of the box.
{ ... }:
{
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
}
