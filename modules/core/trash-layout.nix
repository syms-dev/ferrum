# The TRaSH directory layout, named once so two modules cannot disagree.
#
# modules/core/storage.nix CREATES this tree under every data root;
# modules/core/parity.nix EXCLUDES the churning half of it from SnapRAID.
# Those are two consumers of one fact, and a second hardcoded copy of
# "torrents and usenet are the churn" is exactly the drift that would make
# the parity exclusion silently stop matching the directories the tree
# actually has -- a sync that costs CPU and protects nothing, while
# reporting success.
{ lib }:
let
  # The library categories every root gets a directory for.
  categories = [ "movies" "tv" "music" "books" ];

  # Files pass THROUGH these on their way into the library and are then
  # hardlinked into media/. Protecting them with parity means re-hashing
  # every in-flight download on every sync, for data that is either about to
  # become a media/ file or about to be deleted.
  #
  # The hardlink half of that is the part worth being sure of rather than
  # assuming, because the *arr import leaves the SAME inode with two names,
  # one inside an excluded directory and one inside an included one.
  # Confirmed against snapraid 12.4 on real loop-mounted ext4 disks: the
  # file is taken into the array exactly once, under its media/ name
  # (`snapraid list` showed it once, with "0 links"); deleting the excluded
  # torrents/ name changed nothing in a subsequent `snapraid diff`; and
  # `snapraid fix` restored the media/ name byte-identical afterwards. So
  # excluding the download directories costs no protection at all for
  # anything that has been imported.
  churn = [ "torrents" "usenet" ];

  # The imported library. The stable, final content parity EXISTS to
  # protect; never excluded.
  stable = [ "media" ];
in
{
  inherit categories churn stable;

  # Every directory ferrum creates under a data root, in the order
  # systemd-tmpfiles needs them (parents before children).
  subdirs =
    [ "torrents" "usenet" "usenet/incomplete" "usenet/complete" "media" ]
    ++ lib.concatMap
      (cat: [ "torrents/${cat}" "usenet/complete/${cat}" "media/${cat}" ])
      categories;
}
