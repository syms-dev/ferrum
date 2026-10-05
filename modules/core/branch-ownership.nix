# The ownership a pool branch root must have before anything seeds a tree
# under it -- and the recorded decision about who is allowed to change it.
#
# THE FAILURE THIS EXISTS FOR. On the owner's host /mnt/ferrum-disk-1
# arrived from whatever system populated it owned by UID 1001, a user that
# does not exist here at all. systemd-tmpfiles refused to descend into it
# and ferrum-media-tree.service died:
#
#   Detected unsafe path transition /mnt/ferrum-disk-1 (owned by 1001) ->
#     .../media (owned by root) during canonicalization of
#     mnt/ferrum-disk-1/media
#   ferrum-media-tree.service: Main process exited, code=exited,
#     status=73/CANTCREAT
#
# That is systemd's unsafe_transition(): descending FROM a root-owned
# directory into anything is fine, but descending from a directory some
# unprivileged user owns into a differently-owned child is not -- because
# the owner of that directory can replace what the next component resolves
# to, so a privileged traversal through it cannot be trusted.
# /mnt/ferrum-disk-0, which ferrum formatted itself, is root:ferrum-media
# 0775 and traverses fine; the whole difference between the two disks is who
# owns the mount point.
#
# This is NOT a regression from ferrum-media-tree.service. The plain
# tmpfiles rules that preceded it met the identical condition and failed at
# boot with nobody watching. The unit's only contribution was making a
# pre-existing failure visible, which is what it was written to do -- so the
# fix belongs in front of it rather than inside it.
#
# THE DECISION, and it is a decision rather than an accident: changing the
# ownership of an operator's disk is not obviously ferrum's business. The
# requirement allows either normalising during apply or refusing with a
# message that names the path, the owner and the fix. This does BOTH, split
# on the one signal that actually distinguishes the cases -- whether the
# owning UID still exists on this system:
#
#   * NO PASSWD ENTRY for the UID -> normalise. Nobody can be meaning
#     anything by an owner the system cannot even name; an unresolvable UID
#     is the signature of a disk carried over from another machine, which is
#     exactly the migration this requirement exists to support. Refusing
#     would print a chown the operator has no reason to decline, so ferrum
#     runs it: root:<mediaGroup> on the MOUNT POINT ITSELF, non-recursively.
#     Nothing inside the directory is touched -- the terabytes being migrated
#     keep every owner, group and mode they arrived with, and the single
#     directory ferrum does change is the one it is about to write its own
#     tree into.
#
#   * A REAL LOCAL USER -> refuse, naming the path, the user, their UID and
#     the exact command. Somebody created that account and gave it this disk.
#     Taking it away from them silently is a change ferrum has no standing to
#     make, and the requirement's own edge case says as much: a real local
#     owner is likelier deliberate.
#
# The normalise arm runs precisely the command the refuse arm would have
# printed. That symmetry is deliberate: ferrum never does anything to an
# operator's branch root that it would not otherwise have told them to type.
#
# Kept in its own file rather than inlined into modules/core/storage.nix so
# that nix/modules/flake/checks.nix can EXECUTE the real shipped script
# against fixture directories, instead of only grepping it back out of a
# generated unit. A guard whose arms have never been taken is a guard nobody
# has tested.
{ pkgs }:

pkgs.writeShellScript "ferrum-branch-ownership" ''
  # Usage: ferrum-branch-ownership <media-group> <branch-root>...
  #
  # Reports on every root before exiting, and exits non-zero if ANY of them
  # was refused: a pool with one bad disk should name that disk rather than
  # stop at it.
  set -u

  group="$1"
  shift

  status=0

  for root in "$@"; do
    if [ ! -d "$root" ]; then
      echo "ferrum: $root is not a directory, so the media tree cannot be seeded on it" >&2
      status=1
      continue
    fi

    # access(2) reports EROFS to root as well, so this catches a read-only
    # MOUNT and not merely an unwritable mode. A read-only branch is refused
    # here, by name, rather than becoming another CANTCREAT out of
    # systemd-tmpfiles with the cause left to be guessed.
    if [ ! -w "$root" ]; then
      echo "ferrum: $root is not writable -- the mount is read-only." >&2
      echo "ferrum: a pool branch must be writable; remount it rw, or drop it from ferrum.storage.pool.branches." >&2
      status=1
      continue
    fi

    if ! owner="$(${pkgs.coreutils}/bin/stat -c %u "$root")"; then
      echo "ferrum: could not read the owner of $root" >&2
      status=1
      continue
    fi

    if [ "$owner" = 0 ]; then
      continue
    fi

    if entry="$(${pkgs.getent}/bin/getent passwd "$owner")"; then
      name="''${entry%%:*}"
      echo "ferrum: $root is owned by $name (uid $owner), not root." >&2
      echo "ferrum: systemd-tmpfiles refuses to descend from a directory owned by a non-root" >&2
      echo "ferrum: user into root-owned children, so the media tree cannot be seeded here." >&2
      echo "ferrum: that uid is a real user on this host, so the ownership looks deliberate" >&2
      echo "ferrum: and ferrum will not change it for you. If it is not deliberate, run:" >&2
      echo "ferrum:" >&2
      echo "ferrum:     chown root:$group $root" >&2
      echo "ferrum:" >&2
      echo "ferrum: which changes the mount point only, nothing inside it, and then:" >&2
      echo "ferrum:     systemctl start ferrum-media-tree.service" >&2
      status=1
      continue
    fi

    echo "ferrum: $root is owned by uid $owner, which has no passwd entry on this host --" >&2
    echo "ferrum: a leftover from whatever populated the disk before. Taking ownership of" >&2
    echo "ferrum: the mount point itself (chown root:$group $root) so the media tree can be" >&2
    echo "ferrum: seeded under it. Nothing inside the directory is changed." >&2
    if ! ${pkgs.coreutils}/bin/chown "0:$group" "$root"; then
      echo "ferrum: chown root:$group $root failed" >&2
      status=1
    fi
  done

  exit "$status"
''
