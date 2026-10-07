# The integration graph, computed ONCE from each app's own meta.nix.
#
# Every edge in this graph is declared in exactly one place --
# `integrations.consumes` / `integrations.providesTo` in modules/apps/*/meta.nix
# -- and modules/core/reconciler.nix has always read it from there. What did
# NOT live in one place was the rule that turns an edge into a registration
# KIND: "Prowlarr registering Sonarr or Radarr is an application, every other
# edge is a download client" was a local `pairKind` inside the reconciler, and
# the UI's Integrations panel needs the same sentence.
#
# A second copy of that rule in JavaScript is the defect class that produced
# the nginx/reconciler address split fixed in 2ec53b6 -- two files deriving the
# same fact from the same inputs, agreeing right up until one of them changed.
# modules/lib/app-address.nix exists for exactly that reason for ADDRESSES;
# this file is its counterpart for EDGES. The reconciler imports `pairKind`
# from here, and nix/modules/flake/packages.nix stamps `integrationEdges` into
# the catalog document the UI reads, so the browser transcribes a computed
# answer instead of recomputing one.
#
# Takes the catalog as an ARGUMENT rather than importing modules/lib/catalog.nix
# itself: the catalog is what the caller already has in scope in both call
# sites, and a self-import here would make annotating the catalog with this
# file's own output circular.
{ lib, catalog }:
let
  # The two registration kinds ferrum-reconcile knows, matching the Phase 1.4c
  # spec's own "exactly two" scope decision. Prowlarr registering Sonarr or
  # Radarr is its indexer push-sync feature ("application"); every other
  # consumes/providesTo edge is a download client.
  #
  # Moved here verbatim from modules/core/reconciler.nix, which now calls it.
  #
  # Arguments:
  #   consumer - the app id doing the registering.
  #   provider - the app id being registered into it.
  # Returns: "application" or "downloadClient".
  pairKind = consumer: provider:
    if consumer == "prowlarr" && lib.elem provider [ "sonarr" "radarr" ]
    then "application"
    else "downloadClient";

  # Every edge `id` sits on, from BOTH ends, each already carrying its kind.
  #
  # Both directions on purpose: the operator question this answers ("what is
  # this app already connected to?") does not care which meta.nix happens to
  # declare the edge, and the catalog's own symmetry rule -- enforced by
  # reconciler.nix's `symmetryErrors` at evaluation -- guarantees each edge is
  # declared at both ends, so reading one end only would halve the answer
  # rather than deduplicate it.
  #
  # Arguments:
  #   id - the catalog app id.
  # Returns: a list of { kind; consumer; provider; }.
  edgesFor = id:
    let meta = catalog.${id} or { }; in
    (map (provider: { kind = pairKind id provider; consumer = id; inherit provider; })
      (meta.integrations.consumes or [ ]))
    ++ (map (consumer: { kind = pairKind consumer id; inherit consumer; provider = id; })
      (meta.integrations.providesTo or [ ]));
in
{
  inherit pairKind edgesFor;

  # The catalog with each app's own edges stamped onto it, for serialization
  # into catalog.json. The UI renders `integrationEdges` and derives nothing.
  annotate = lib.mapAttrs (id: meta: meta // { integrationEdges = edgesFor id; }) catalog;
}
