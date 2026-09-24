{ rustPlatform, lib, makeWrapper, btrfs-progs, sops, ssh-to-age, authelia, dnsutils }:
rustPlatform.buildRustPackage {
  pname = "ferrum-apply";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-apply";

  # ferrum-apply shells out to `btrfs` (preflight's check_is_subvolume, and
  # later apply/restore-state's snapshot/swap commands), `sops` and
  # `ssh-to-age` (secrets::ensure_all's encrypt-only secret generation),
  # and `authelia` (secrets::argon2id_hash, for the generated first-user
  # password).
  #
  # `dnsutils` provides `dig`, which ferrum-dns::dns_query shells out to for
  # decision D-07's post-apply check: every record ferrum writes is queried
  # against the zone's OWN authoritative nameservers, never the host's
  # recursive resolver, which can hold a negative-cache entry and report a
  # freshly created record as absent. Decision D-10 chose `dig` over a
  # hand-rolled DNS client precisely so no wire-format parser lives inside
  # this root-privileged binary. Only ferrum-apply needs it: verify_authoritative
  # is called from `apply` and from `reconcile-dns`, while ferrum-install's
  # two ferrum-dns call sites (verify_zone_access, list_records) are HTTPS --
  # so nix/pkgs/ferrum-install/* deliberately does NOT gain this input.
  #
  # nativeCheckInputs alone only puts these on PATH during this
  # derivation's own checkPhase -- it does NOT reach the installed binary
  # at runtime, so it's paired here with a wrapper that guarantees they're
  # all on PATH wherever this binary actually runs, independent of whether
  # a consuming systemd unit remembers to supply them too.
  nativeCheckInputs = [ btrfs-progs sops ssh-to-age authelia dnsutils ];
  nativeBuildInputs = [ makeWrapper ];
  postFixup = ''
    wrapProgram $out/bin/ferrum-apply --prefix PATH : ${lib.makeBinPath [ btrfs-progs sops ssh-to-age authelia dnsutils ]}
  '';
}
