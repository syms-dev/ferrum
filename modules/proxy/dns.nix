# The DNS records ferrum owns for what it publishes, computed as data.
#
# Same shape as modules/core/reconciler.nix: Nix computes the desired state,
# serializes it to JSON baked into the system closure, and a small Rust
# binary (crates/ferrum-dns, driven by ferrum-apply) reconciles the real
# world against it. Nothing here talks to Cloudflare; this file only decides
# WHICH names should exist and WHAT they should point at.
#
# Why the record set is exactly this set:
#
#   * publicApps only (decision D-03). The list reuses proxyLib.publicApps
#     and vhostNameFor -- the same helpers modules/proxy/acme.nix and
#     modules/proxy/nginx.nix already use -- so the record set cannot drift
#     from the certificate set. `lan` apps are deliberately excluded: they
#     get an nginx vhost and an IP allow-list but no ACME certificate
#     (nginx.nix's own lanRestriction), so a public record would hand an
#     external client a self-signed TLS handshake before nginx denies them,
#     publishing exactly what the LAN restriction exists to prevent. The
#     resulting "the lan hostname doesn't resolve from the LAN either" gap
#     is what A6's split-horizon disclaimer already covers; no new gap is
#     introduced here.
#
#   * auth.<baseDomain> under the SAME condition acme.nix issues its own
#     auth certificate under (ferrum.auth.enable && publicApps != { }),
#     mirrored deliberately rather than re-derived, because a host that gets
#     a certificate for a name that does not resolve is the exact incident
#     this requirement exists to fix (auth.thesyms.ca).
#
#   * the daemon's own <ferrum.daemon.subdomain>.<baseDomain>, on by default
#     (owner ruling H-01, option C). ferrumd has no vhost yet, so
#     nginx.nix's _ferrum_unmatched catch-all answers this name with
#     `return 444` -- a resolving hostname that closes the connection --
#     until Phase 1.7c R13 ships daemon web access. That is disclosed to the
#     operator rather than avoided, and ferrum.daemon.dns.includeRecord
#     exists so the ruling is a one-line change if it is ever revisited.
#     Standing up a daemon vhost is R13's work, explicitly not this file's.
#
#   * ferrum.proxy.dns.adoptedNames carried through verbatim (A3). ferrum
#     never overwrites a record it did not create; a name in this list is the
#     operator's explicit, per-name exception to that, collected by the
#     installer's pre-erase gate. Nothing is computed from it here -- the
#     whole point is that the list the operator approved is the list the
#     reconciler enforces, name for name. crates/ferrum-dns matches it per
#     record, so adopting one hostname cannot reach another, and it only ever
#     licenses a replacement, never a delete.
#
#   * proxied = false on every record (decision D-05). Cloudflare's orange
#     cloud makes every request arrive from a Cloudflare edge address, which
#     inverts nginx.nix's `allow ${net}; deny all;` against
#     ferrum.proxy.trustedNetworks into a total outage for the very apps the
#     restriction protects, and streaming Plex/Jellyfin through Cloudflare's
#     edge is a bandwidth and terms-of-service problem.
#
# The JSON document is emitted unconditionally, with its own `enable` field,
# rather than being omitted on a host that does not manage DNS: one file at
# one path that a consumer can always read and no-op on is simpler to reason
# about than "absent means disabled", and the installer's dry-run (A7)
# evaluates system.build.ferrumDnsConfig for a host it has not built yet.
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  dns = ferrum.proxy.dns;
  proxyLib = import ./lib.nix { inherit lib; };
  vhostNameFor = proxyLib.vhostNameFor ferrum;
  publicApps = proxyLib.publicApps ferrum;

  baseDomain = ferrum.proxy.baseDomain;
  haveDomain = baseDomain != "";

  dnsEnabled = ferrum.proxy.enable && dns.enable;
  ddnsEnabled = dnsEnabled && dns.ddnsUpdater.enable;

  credentialSecret = ferrum.proxy.acme.credentialSecret;
  credentialProvided = ferrum.secrets ? "${credentialSecret}";
  # The literal sops-nix output path rather than
  # config.sops.secrets."${credentialSecret}".path: that attribute is
  # declared by modules/proxy/acme.nix inside a lib.mkIf, so it simply does
  # not exist on a host that declares no credential, and reading it there
  # would be an eval error instead of the clear assertion below.
  # modules/core/reconciler.nix already names /run/secrets/<name> literally
  # for the same reason.
  credentialFile = "/run/secrets/${credentialSecret}";

  # A2: the record target is a decision the operator makes once (the
  # installer collects it), never a guess. One target for every record --
  # they all point at the same box.
  target =
    if dns.recordMode == "cname"
    then { mode = "cname"; hostname = dns.cnameTarget; }
    else { mode = "a"; address = dns.staticAddress; };

  mkRecord = source: name: {
    inherit name source;
    # Carried per record, not once at the top of the document, because the
    # reconciler's unit of work is one record and D-05 is a property of each
    # one it creates or corrects -- including when it finds that an operator
    # has switched a managed record to orange-cloud in the dashboard.
    proxied = false;
  };

  appRecords = lib.mapAttrsToList
    (id: app: mkRecord "app:${id}" (vhostNameFor app))
    publicApps;

  # Mirrors modules/proxy/acme.nix's own condition for the auth certificate
  # -- `ferrum.auth.enable && realCertsNeeded`, where realCertsNeeded is
  # `publicApps != { } || daemonPublished`. R13 widened the certificate side
  # of that and left this one keyed on the app catalog, which put the two
  # halves of the same fact back out of step: a host publishing only the
  # dashboard, with every app at lan/local, got a valid certificate for
  # auth.<baseDomain> and no record for it. Authelia then redirects the
  # browser to a name that does not resolve, so nobody can log in and the
  # dashboard R13 exists to publish is unreachable. A working certificate on
  # a name that does not resolve is the incident this whole file exists to
  # prevent, and it had come back one condition over.
  daemonPublished = proxyLib.daemonPublished ferrum;

  authRecords = lib.optional
    (ferrum.auth.enable && (publicApps != { } || daemonPublished))
    (mkRecord "auth" "auth.${baseDomain}");

  daemonRecords = lib.optional
    ferrum.daemon.dns.includeRecord
    (mkRecord "daemon" "${ferrum.daemon.subdomain}.${baseDomain}");

  # Sorted so a rebuild that changes nothing produces a byte-identical file,
  # and so a diff of two generations' documents is readable.
  records = lib.sort (a: b: a.name < b.name)
    (lib.optionals haveDomain (appRecords ++ authRecords ++ daemonRecords));

  dnsConfigFile = pkgs.writeText "ferrum-dns-config.json" (builtins.toJSON {
    enable = dnsEnabled;
    inherit baseDomain records target;
    credentialFile = if credentialProvided then credentialFile else null;
    # Sorted and de-duplicated for the same reason `records` is: a rebuild
    # that changes nothing must produce a byte-identical file, and a diff of
    # two generations' documents has to be readable.
    adoptedNames = lib.sort (a: b: a < b) (lib.unique dns.adoptedNames);
    ddnsUpdater = {
      enable = ddnsEnabled;
      intervalMinutes = dns.ddnsUpdater.intervalMinutes;
    };
  });

  adoptedNamesChecked = lib.unique dns.adoptedNames;

  configPath = "/etc/ferrum-dns-config.json";
in
{
  assertions = [
    {
      assertion = !dnsEnabled || haveDomain;
      message = ''
        ferrum.proxy.dns.enable is true but ferrum.proxy.baseDomain is empty
        -- every record name derives from it, so there is nothing to create.
        Set ferrum.proxy.baseDomain, or turn DNS management off.
      '';
    }
    {
      assertion = !dnsEnabled || dns.recordMode != "a" || dns.staticAddress != "";
      message = ''
        ferrum.proxy.dns.recordMode is "a" but ferrum.proxy.dns.staticAddress
        is empty. Guessing the address would publish every app at somewhere
        that is not this server; set the host's real public IPv4 address, or
        use recordMode = "cname".
      '';
    }
    {
      assertion = !dnsEnabled || dns.recordMode != "cname" || dns.cnameTarget != "";
      message = ''
        ferrum.proxy.dns.recordMode is "cname" but
        ferrum.proxy.dns.cnameTarget is empty -- set the hostname the records
        should follow (typically a dynamic-DNS name that already tracks this
        host's address).
      '';
    }
    {
      # Fail at evaluation with the procedure, rather than at runtime with a
      # Cloudflare 403 nobody is watching for. Same wording pattern as
      # modules/proxy/acme.nix's own credential assertion.
      assertion = !dnsEnabled || credentialProvided;
      message = ''
        ferrum.proxy.dns.enable is true but ferrum.secrets does not declare
        "${credentialSecret}". Record management uses the same Cloudflare API
        token as ACME DNS-01 (Zone:Read + DNS:Edit). Add it to ferrum.secrets
        in settings.json and encrypt the token to this host's own age
        recipient -- see README.md's reverse-proxy section -- then re-apply.
      '';
    }
    {
      # An adopted name that is not a record this host publishes cannot be
      # acted on -- the reconciler only ever converts a wanted name's
      # SkipForeign into an Adopt -- so it is an operator who believes a
      # takeover is configured when nothing will happen. Fail at evaluation
      # with the names, rather than at runtime with silence.
      assertion = !dnsEnabled
        || (lib.subtractLists (map (r: r.name) records) adoptedNamesChecked) == [ ];
      message = ''
        ferrum.proxy.dns.adoptedNames lists ${
          lib.concatStringsSep ", "
            (lib.subtractLists (map (r: r.name) records) adoptedNamesChecked)
        }, which this host does not publish a record for. Adoption only ever
        replaces a record at a name ferrum wants, so these entries would do
        nothing at all. Remove them, or enable the app that owns the name.
      '';
    }
    {
      assertion = !ddnsEnabled || dns.recordMode == "a";
      message = ''
        ferrum.proxy.dns.ddnsUpdater.enable is true but
        ferrum.proxy.dns.recordMode is "cname". The updater exists to correct
        an A record when this host's public address changes; a CNAME already
        delegates that job to whatever owns the target name, so the updater
        would have nothing to do.
      '';
    }
  ];

  system.build.ferrumDnsConfig = dnsConfigFile;

  # Present in the closure at a stable path so both a freshly built system
  # ({toplevel}/etc/ferrum-dns-config.json, read by ferrum-apply's in-process
  # reconcile step) and the currently-running one
  # (/etc/ferrum-dns-config.json, read by the updater unit below) find it
  # with no systemd Environment= plumbing to keep in sync.
  environment.etc."ferrum-dns-config.json".source = dnsConfigFile;

  # A8's optional updater: re-check the host's real public address on a
  # schedule and correct the records ferrum owns when it has moved. Opt-in,
  # but recommended, because the failure it prevents is invisible from the
  # host -- a stale A record leaves every app unreachable from outside while
  # the box is healthy and its certificates are valid.
  #
  # Deliberately NOT wantedBy ferrum-apps.target: that target's members are
  # what crates/ferrum-apply/src/apply.rs's all_managed_units_active() polls,
  # and a timer-driven oneshot that is legitimately inactive between runs
  # would be read there as a failed apply.
  systemd.services.ferrum-dns-updater = lib.mkIf ddnsEnabled {
    description = "Correct the DNS records ferrum owns against this host's current public address";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      # Runs as root to read the decrypted Cloudflare token, whose ownership
      # stays acme:acme (modules/proxy/acme.nix) -- the same trust level
      # ferrum-reconcile already runs at, and for the same reason:
      # privileged coordination over ferrum's own data, not privilege
      # escalation over untrusted input.
      ExecStart = "${pkgs.ferrum-apply}/bin/ferrum-apply reconcile-dns --config ${configPath}";

      # Containment hardening, same shape and for the same reason as
      # modules/core/daemon.nix's ferrumd block: none of this is what stops
      # this unit doing something privileged, it is what limits the blast
      # radius if the code it runs is ever subverted. The case for it here
      # is stronger than for the reconciler this unit was otherwise modelled
      # on (modules/core/reconciler.nix): that one only ever talks to
      # localhost, whereas this one runs unattended on a timer, reaches an
      # internet-facing API, and holds a Zone:Read + DNS:Edit credential for
      # the operator's real domain while it does.
      ProtectSystem = "strict";
      # The ONE path this unit writes, and the reason it must stay writable:
      # crates/ferrum-apply/src/main.rs's run_reconcile_dns records a
      # last-success timestamp at <stateDir>/dns-updater-last-success after
      # every clean cycle, and the AGE of that file is the whole of A8's
      # staleness signal -- a timer that has been erroring for six weeks is
      # otherwise indistinguishable from one that has never had anything to
      # do. ProtectSystem = "strict" makes the entire hierarchy read-only,
      # so removing this line does not tidy anything up: it silently turns
      # every successful reconcile into a failed write and takes the signal
      # with it. The directory itself already exists as root:root 0751 from
      # modules/core/storage.nix's tmpfiles rule. Named from the option
      # rather than hardcoded because modules/core/overlays.nix wraps
      # ferrum-apply with --set-default FERRUM_STATE_DIR
      # ${ferrum.storage.stateDir}, which is the path the binary actually
      # writes.
      ReadWritePaths = [ ferrum.storage.stateDir ];
      ProtectHome = true;
      PrivateTmp = true;
      NoNewPrivileges = true;
      # NOT the empty set daemon.nix uses, and the difference is
      # load-bearing: ferrumd runs as the `ferrum` user and owns everything
      # it reads, while this unit runs as root and must read
      # /run/secrets/${credentialSecret}, which sops-nix materializes 0400
      # acme:acme (modules/proxy/acme.nix keeps that ownership deliberately,
      # so that root is the only other principal that can read the token).
      # uid 0 bypasses those file modes solely by virtue of
      # CAP_DAC_OVERRIDE, and an empty bounding set takes that capability
      # away along with the rest -- measured, not assumed: uid 0 with
      # CapBnd = 0 gets EACCES on a 0400 file owned by another user, and the
      # same read succeeds with CapBnd = CAP_DAC_OVERRIDE alone. Every other
      # capability is dropped, so this is one capability away from the empty
      # set rather than a weaker posture than the house pattern.
      CapabilityBoundingSet = [ "CAP_DAC_OVERRIDE" ];
      # AF_INET/AF_INET6 for the Cloudflare HTTPS calls and for the `dig`
      # queries crates/ferrum-dns/src/dns_query.rs makes against the zone's
      # authoritative nameservers; AF_UNIX for nsswitch/NSS lookups on the
      # way there. Deliberately no AF_NETLINK and no AF_PACKET, matching
      # daemon.nix: nothing here has any business enumerating interfaces or
      # opening raw sockets.
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      SystemCallErrorNumber = "EPERM";
      SystemCallArchitectures = "native";
      LockPersonality = true;
      RestrictSUIDSGID = true;
      RestrictRealtime = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      ProtectClock = true;
    };
  };

  systemd.timers.ferrum-dns-updater = lib.mkIf ddnsEnabled {
    description = "Schedule for ferrum-dns-updater.service";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      # A first run shortly after boot catches the common real case: the
      # address changed while the box was down.
      OnBootSec = "5min";
      OnUnitActiveSec = "${toString dns.ddnsUpdater.intervalMinutes}min";
      # Run once on resume if the interval elapsed while the host was off,
      # rather than waiting a full interval with stale records published.
      Persistent = true;
      Unit = "ferrum-dns-updater.service";
    };
  };
}
