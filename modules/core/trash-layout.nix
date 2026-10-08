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

  # THE TIE between this layout and the apps that name parts of it.
  #
  # `categories` above is the ONE list of library categories ferrum knows.
  # modules/core/storage.nix turns it into directories; each app's own
  # meta.nix names one of them in `mediaCategory`; and
  # modules/core/reconciler.nix uses that same attribute for BOTH the app's
  # root folder and the download-client category it registers. So the
  # category ferrum registers and the directory ferrum creates are the same
  # string by construction -- as long as every declared mediaCategory is
  # actually drawn from this list. This function is what makes that a build
  # failure rather than an assumption.
  #
  # It is the fourth time this repository has had two places computing one
  # value (nginx and the reconciler on addresses; Rust and Nix on the parity
  # last-sync path; the integration rule before modules/lib/integrations.nix),
  # and it is handled the same way: one source, and an eval-time failure if
  # anything drifts off it.
  #
  # Exported as a FUNCTION of the catalog rather than applied here, so
  # nix/modules/flake/checks.nix can run the real shipped guard against
  # synthetic catalogs and prove it rejects a bad one as well as accepting
  # the real one. A guard whose rejecting arm has never been taken is a
  # guard nobody has tested.
  #
  # Arguments:
  #   catalogAttrs - an attrset of app id -> meta (modules/lib/catalog.nix's
  #                  own shape). An app with no library omits mediaCategory.
  # Returns: a list of human-readable error strings, empty when consistent.
  mediaCategoryErrors = catalogAttrs:
    builtins.filter (x: x != null) (lib.mapAttrsToList
      (id: meta:
        let cat = meta.mediaCategory or null; in
        if cat == null || lib.elem cat categories then null
        else
          "modules/apps/${id}/meta.nix declares mediaCategory \"${cat}\", which is not one of the categories modules/core/trash-layout.nix creates directories for (${lib.concatStringsSep ", " categories}). That attribute is the app's root folder AND the download-client category ferrum registers, so a value off this list means ferrum would tell a download client to write into a directory nothing ever creates -- which is exactly the defect this guard was added for: the categories used to be the app ids, so completed jobs went to usenet/complete/sonarr while the usenet/complete/tv ferrum did create stayed empty. Either add \"${cat}\" to `categories` in trash-layout.nix, or name one of the existing ones.")
      catalogAttrs);

  # Every directory ferrum creates under a data root, in the order
  # systemd-tmpfiles needs them (parents before children).
  subdirs =
    [ "torrents" "usenet" "usenet/incomplete" "usenet/complete" "media" ]
    ++ lib.concatMap
      (cat: [ "torrents/${cat}" "usenet/complete/${cat}" "media/${cat}" ])
      categories;
}
