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
#     (owner ruling H-01, option C), under the SAME predicate the daemon's
#     vhost, Authelia rule and certificate use -- modules/proxy/lib.nix's
#     daemonPublished. This record was created for a year before there was
#     anything behind it -- nginx.nix's _ferrum_unmatched catch-all answered
#     the name with `return 444`, a resolving hostname that closed the
#     connection -- and the ruling was to create it anyway and disclose it.
#     Phase 1.7c R13 ended that: nginx.nix now builds a real vhost for the
#     daemon, so this record points at the dashboard. What R13 left behind
#     was this record still being created on hosts that build no vhost at
#     all, which is the pre-R13 dead name back again and is fixed where
#     daemonRecords is defined below. ferrum.daemon.dns.includeRecord
#     remains, so opting out on a host that IS publishing is still a
#     one-line change.
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
  #
  # F1/R1 qualified that in one direction only. With ddnsUpdater.enable this
  # value stops being the published address and becomes a cross-check:
  # crates/ferrum-apply/src/dns_reconcile.rs publishes the address three
  # independent services agreed on, and warns -- naming both -- when
  # staticAddress disagrees with what it measured. With the updater off,
  # which is the default, this is still the whole truth: what is written
  # here is what gets published, unchanged.
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

  # The same pairing the comment above authRecords describes, in the one
  # place that had not learned it. This was keyed on
  # ferrum.daemon.dns.includeRecord ALONE, which reads as "does the operator
  # want a record" and silently answered a question nobody asked: whether
  # this host publishes a dashboard at all. Every other consumer of
  # daemonPublished -- the vhost, the Authelia rule, the certificate --
  # already went absent together on an unpublished host, and this file
  # created a public record for the name anyway. Nothing answers it: nginx's
  # _ferrum_unmatched catch-all closes the connection with `return 444` when
  # the proxy is on, and when the proxy is off nothing is listening at all.
  #
  # It is the auth.thesyms.ca defect with the sign flipped -- a record with
  # nothing behind it rather than a certificate with nothing behind it --
  # and ferrum.daemon.publish is what turned it from a corner case into the
  # ordinary state of an installer's stage-1 host.
  #
  # includeRecord stays, and stays conjoined rather than replaced: it is the
  # operator's documented one-line way out of the H-01 option-C ruling on a
  # host that IS publishing, which is a different statement from "this host
  # publishes nothing".
  daemonRecords = lib.optional
    (daemonPublished && ferrum.daemon.dns.includeRecord)
    (mkRecord "daemon" "${ferrum.daemon.subdomain}.${baseDomain}");

  # R5/SEC-M02. The control plane's own Authelia portal.
  #
  # The dashboard has a session cookie scope of its own now, and Authelia
  # refuses an `authelia_url` outside the scope it serves, so the portal that
  # issues that cookie is at auth.<dashboard hostname> rather than
  # auth.<baseDomain>. modules/proxy/nginx.nix serves it and
  # modules/proxy/acme.nix orders its certificate on exactly these
  # conditions; this is the third of the three, and the pairing is the
  # auth.thesyms.ca lesson applied in advance rather than after the incident.
  #
  # Conjoined with includeRecord like daemonRecords above, not like
  # authRecords: this name exists only because the dashboard is published, so
  # an operator who has taken the dashboard's own record into their own hands
  # takes this one with it. The two always appear and disappear together.
  controlPortalRecords = lib.optional
    (daemonPublished && ferrum.auth.enable && ferrum.daemon.dns.includeRecord)
    (mkRecord "auth-control"
      (proxyLib.autheliaPortalFor "${ferrum.daemon.subdomain}.${baseDomain}"));

  # Sorted so a rebuild that changes nothing produces a byte-identical file,
  # and so a diff of two generations' documents is readable.
  records = lib.sort (a: b: a.name < b.name)
    (lib.optionals haveDomain
      (appRecords ++ authRecords ++ daemonRecords ++ controlPortalRecords));

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
      # The `|| ddnsEnabled` term is F1/R1 arriving. The original reasoning
      # -- "guessing the address would publish every app at somewhere that is
      # not this server" -- is still exactly right, and it is why this
      # assertion stays for every host that does NOT run the updater. What
      # changed is that with the updater on, ferrum no longer guesses: it
      # asks three independent services and refuses to act unless at least
      # two run by different parties agree (crates/ferrum-dns/src/public_ip.rs).
      # That is a better answer than a literal an operator typed once and has
      # no reason to revisit -- which is the literal that left seven records
      # pointing at 184.148.39.165 for an evening.
      #
      # staticAddress remains legal alongside the updater, and is then
      # advisory: crates/ferrum-apply/src/dns_reconcile.rs publishes what it
      # measured and warns, naming both values, when the two disagree.
      assertion = !dnsEnabled || dns.recordMode != "a"
        || dns.staticAddress != "" || ddnsEnabled;
      message = ''
        ferrum.proxy.dns.recordMode is "a" but ferrum.proxy.dns.staticAddress
        is empty and ferrum.proxy.dns.ddnsUpdater.enable is false, so nothing
        on this host knows where to point the records. Guessing would publish
        every app at somewhere that is not this server. Either set the host's
        real public IPv4 address, or turn the updater on and let ferrum
        discover it, or use recordMode = "cname".
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
        ferrum.proxy.dns.recordMode is "cname". The updater discovers this
        host's public IPv4 address and writes it into the A records ferrum
        owns; a CNAME has no address in it to correct, and already delegates
        the job to whatever owns the target name. Use recordMode = "a", or
        turn the updater off.
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

  # A8's optional updater: discover this host's real public IPv4 address on
  # a schedule and correct the records ferrum owns when it has moved. Opt-in,
  # but recommended, because the failure it prevents is invisible from the
  # host -- a stale A record leaves every app unreachable from outside while
  # the box is healthy and its certificates are valid.
  #
  # THIS COMMENT WAS FALSE UNTIL F1/R1, and that is worth leaving on the
  # record rather than quietly fixing. It said "re-check the host's real
  # public address" from the day the unit shipped, as did the unit
  # description below and the recordMode assertion above. No code anywhere in
  # crates/ queried a public address; the timer re-published
  # ferrum.proxy.dns.staticAddress on a schedule and nothing else. Three
  # security reviews and a 32-finding bug hunt read these three sentences and
  # took them as a description of the code. The owner's address then moved
  # from 184.148.39.165 to 142.180.179.64, seven records kept pointing at the
  # old one, every published app became unreachable from outside, and the
  # host reported itself healthy throughout.
  #
  # What it does now, for real:
  #
  #   * crates/ferrum-dns/src/public_ip.rs asks three address-echo services
  #     run by three different parties (Cloudflare, Amazon, ipify). At least
  #     two DISTINCT operators must answer and every answer that arrives must
  #     agree, or nothing is published -- a wrong address republishes every
  #     one of the operator's hostnames at somebody else's server, with
  #     certificates ferrum obtained itself, which is strictly worse than a
  #     stale record.
  #   * a private, loopback, CGNAT-shared or otherwise reserved answer is
  #     refused outright rather than written.
  #   * a discovery failure exits non-zero (1 could not find out, 4 found out
  #     and refused), so it can never read as "nothing to do" -- which is
  #     exactly how the original defect stayed invisible.
  #   * crates/ferrum-apply/src/address_history.rs caps published changes at
  #     3 per rolling 24 hours, so a flapping link cannot spend the
  #     Cloudflare quota rewriting every hostname every hour. A held change
  #     is disclosed with both addresses named, never silently dropped.
  #
  # Deliberately NOT wantedBy ferrum-apps.target: that target's members are
  # what crates/ferrum-apply/src/apply.rs's all_managed_units_active() polls,
  # and a timer-driven oneshot that is legitimately inactive between runs
  # would be read there as a failed apply.
  systemd.services.ferrum-dns-updater = lib.mkIf ddnsEnabled {
    description = "Discover this host's public IPv4 address and correct the DNS records ferrum owns";
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
      # The only directory this unit writes, and the reason it must stay
      # writable. Two files live in it, and both are signals rather than
      # caches:
      #
      #   * <stateDir>/dns-updater-last-success -- written by
      #     crates/ferrum-apply/src/main.rs's run_reconcile_dns after every
      #     clean cycle. Its AGE is the whole of A8's staleness signal.
      #   * <stateDir>/dns-public-address.json -- F1/R1's published-address
      #     history, read and written by
      #     crates/ferrum-apply/src/address_history.rs. It is what makes "the
      #     address moved from X to Y" a fact rather than a guess, and it
      #     carries the flap budget that stops an oscillating link spending
      #     the Cloudflare quota. Losing it costs at most one extra permitted
      #     change, which is why its own failures are disclosed rather than
      #     fatal.
      #
      # A timer that has been erroring for six weeks is
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
      # AF_INET/AF_INET6 for the Cloudflare HTTPS calls, for the three
      # address-echo HTTPS calls F1/R1 added
      # (crates/ferrum-dns/src/public_ip.rs), and for the `dig`
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
