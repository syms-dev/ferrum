# The cross-cutting ferrum.* namespaces, plus ferrum.apps -- the uniform
# app catalog built from modules/lib/app-submodule.nix.
#
# Every option under ferrum.* must stay JSON-expressible: this whole
# namespace is what a settings.json document can populate, and it is what
# checks.schema-uniformity (nix/modules/flake/checks.nix) walks to enforce
# that promise. Anything that needs a `path` or a `package` belongs in
# /etc/ferrum/custom/ instead, which the ferrum UI never touches.
{ config, lib, ... }:
let
  inherit (lib) mkOption mkEnableOption types;

  catalog = import ../lib/catalog.nix { inherit lib; };

  # The three options below that nginx reads as syntax rather than as data.
  # See modules/lib/hostnames.nix for the injection this refuses and why the
  # constraint lives in one file instead of at each option.
  hostnames = import ../lib/hostnames.nix { inherit lib; };

  appsType = import ../lib/app-submodule.nix {
    inherit lib catalog;
    stateRoot = config.ferrum.storage.stateDir;
    # Threaded the same way stateRoot is, so the exposure default can depend on
    # whether this host actually has a reverse proxy to publish through.
    proxyEnabled = config.ferrum.proxy.enable;
  };
in
{
  options.ferrum = {
    schemaVersion = mkOption {
      type = types.int;
      default = (import ../lib/migrations.nix { inherit lib; }).currentVersion;
      readOnly = true;
      description = "Version of the ferrum settings.json schema this module tree expects.";
    };

    storage = {
      stateDir = mkOption {
        # Not types.str: this lands unquoted in a systemd.tmpfiles.rules
        # entry (newline-separated, run as root at every activation) AND in
        # modules/proxy/dns.nix's ReadWritePaths, a systemd unit list-field
        # NixOS emits one unescaped line per element. See
        # modules/lib/hostnames.nix, which carries the rendered proof.
        type = hostnames.absolutePath;
        default = "/var/lib/ferrum/state";
        description = "Root of the btrfs subvolume that participates in snapshot/rollback.";
      };
      snapshotDir = mkOption {
        # Not types.str, same tmpfiles sink as stateDir above.
        type = hostnames.absolutePath;
        default = "/var/lib/ferrum/snapshots";
      };
      journalDir = mkOption {
        # Not types.str, same tmpfiles sink as stateDir above. The assertion
        # further down checks only that this path does not NEST inside the
        # other storage roots, which is a containment question and says
        # nothing about whether the string can carry a record separator.
        type = hostnames.absolutePath;
        default = "/var/lib/ferrum/journal";
        description = "Where ferrum-apply records one entry per generation, correlating it to its state snapshot. Lives on @root (not the snapshotted @state subvolume) -- see the plan's storage-layout rule that /var/lib/ferrum itself must survive a rollback.";
      };
      mediaDir = mkOption {
        # Not types.str: the tmpfiles sink above, once directly and once per
        # TRaSH subdirectory per pool root, plus the /etc/fstab mount point
        # in modules/core/pool.nix.
        type = hostnames.absolutePath;
        default = "/data";
        description = ''
          The single root under which downloads AND media both live.

          One root is not a stylistic choice. The *arr apps import by
          HARDLINKING from the download directory into the library, and a
          hardlink cannot cross a filesystem -- so if downloads and media
          sit on different mounts the import silently degrades to a copy:
          double the space while it runs, a long pause per import, and
          broken seeding when the original is moved rather than copied.
          That is the single most common misconfiguration the TRaSH guides
          exist to prevent, and ferrum had it by construction until this
          default changed: media on the data disks, downloads at
          /srv/media/downloads on the OS disk.

          `/data` follows the TRaSH convention, so an operator reading any
          *arr guide finds the paths where the guide says they are.

          On a host with data disks this is where they are mounted (or
          where their pool is presented); on a host without, it is a plain
          directory on the OS disk. The layout beneath it is the same
          either way, so a small install is not a different shape.
        '';
      };

      pool = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Present several data disks as one filesystem at mediaDir, so
            apps see a single library rather than one per disk.

            Set by the installer when it finds more than one data disk. A
            single disk needs no pool -- it is mounted at mediaDir
            directly.
          '';
        };

        branches = mkOption {
          # Not types.listOf types.str, and this one reaches two grammars
          # with two different separators: modules/core/storage.nix folds
          # branches into treeRoots and emits a NEWLINE-separated tmpfiles
          # rule per branch per subdirectory, while modules/core/pool.nix
          # emits `x-systemd.requires-mounts-for=${b}` into the /etc/fstab
          # OPTIONS field, where the separator is a COMMA. A value that was
          # safe for one was not safe for the other -- `/mnt/d1,suid,dev`
          # renders as real mount options on the filesystem every app
          # writes to. See modules/lib/hostnames.nix.
          type = types.listOf hostnames.absolutePath;
          default = [ ];
          example = [ "/mnt/ferrum-disk-0" "/mnt/ferrum-disk-1" ];
          description = ''
            The individual disk mount points the pool unions, in order.
            Their mounts are declared in /etc/ferrum/custom/, which is the
            operator's to edit; this list is what the pool is built from.
          '';
        };

        minFreeGiB = mkOption {
          type = types.int;
          default = 50;
          description = ''
            A branch with less than this free is skipped when placing a NEW
            file.

            This is what stops `epmfs` filling a disk. Without it, once a
            show lives on a disk every later season goes to that disk too,
            full or not, and the write fails inside an app that reports it
            badly or not at all. With it, the new seasons land elsewhere --
            the show is then split across disks, which is the honest trade:
            keeping a show together matters right up to the point where it
            would mean not writing it at all.
          '';
        };

        policy = mkOption {
          type = types.enum [ "epmfs" "mfs" ];
          default = "epmfs";
          description = ''
            Where a new file goes.

            epmfs -- existing path, most free space. Among the disks that
            already hold the target directory, pick the emptiest. Keeps a
            show's seasons on one disk, so losing a disk loses whole shows
            rather than gaps in every show, and idle disks can spin down.

            mfs -- most free space, ignoring what is already where.
            Balances new writes more evenly and scatters a series.

            NEITHER MOVES EXISTING DATA. This chooses where the next file
            is written; nothing rebalances what is already on the disks.
          '';
        };
      };
      mediaGroup = mkOption {
        # Not types.str: modules/core/storage.nix uses this as the ATTRIBUTE
        # NAME in `users.groups.${mediaGroup}`, so it becomes a row in
        # /etc/group -- where `\n` and `:` both separate -- as well as the
        # group field of every media tmpfiles rule. Nix attribute names are
        # arbitrary strings, so nothing before this type objects. See
        # modules/lib/hostnames.nix.
        type = hostnames.groupName;
        default = "ferrum-media";
      };
      minFreeGiB = mkOption {
        type = types.int;
        default = 10;
        description = "Apply refuses to run below this much free space on the state filesystem.";
      };
      keepGenerations = mkOption {
        type = types.int;
        default = 10;
        description = ''
          How many application-state snapshots `ferrum-apply gc` keeps.
          Every apply takes one snapshot, so this is roughly "how many
          applies back can I roll to".

          The snapshot belonging to the currently-running generation is
          ALWAYS kept, even when it falls outside this window -- on a host
          that has been rebooted into an older generation it can easily be
          older than `keepGenerations` newer ones, and pruning it would
          remove the way back. See crates/ferrum-apply/src/gc.rs.

          Snapshots are not free: btrfs pins the extents they reference, so
          a SQLite-heavy app rewritten in place keeps historical extents
          alive for as long as any snapshot references them. Raising this a
          lot on a host with busy *arr databases costs real disk.
        '';
      };
    };

    secretsDir = mkOption {
      # Not types.str, for two separate reasons: modules/core/bootstrap.nix
      # interpolates it unquoted into a root-executed tmpfiles rule, and
      # modules/proxy/{acme,authelia}.nix build each sops sopsFile as
      # `/. + "${secretsDir}/${name}.sops"`, where `..` walks out of the
      # secrets directory at eval time. See modules/lib/hostnames.nix.
      type = hostnames.absolutePath;
      default = "/etc/ferrum/secrets";
      description = ''
        Where per-secret .sops files live on a real deployed box (this is
        NOT the decrypted output -- that's sops-nix's own /run/secrets/,
        entirely outside ferrum's control). /etc/ferrum is the host's own
        flake root (see the Phase 1.3 design doc), so paths under here get
        copied into the Nix store at eval time same as settings.json --
        that's fine, since only ciphertext ever lives here.
      '';
    };

    proxy = {
      enable = mkEnableOption "the ferrum reverse proxy (nginx + ACME)";

      baseDomain = mkOption {
        # Not types.str: this lands in server_name, in an ACME certificate
        # name, and in modules/proxy/nginx.nix's `error_page 401 =302
        # https://auth.${baseDomain}/...`, and the settings API can write it.
        type = hostnames.dnsName;
        default = "";
        example = "home.example.com";
      };

      acme = {
        email = mkOption {
          # Not types.str: nixpkgs' security.acme escapes this properly for
          # lego and then interpolates the same value raw inside a
          # single-quoted shell word in the renewal script it generates, so
          # a `'` here is command execution in acme-<cert>.service. See
          # modules/lib/hostnames.nix, which carries the rendered proof.
          type = hostnames.emailAddress;
          default = "";
        };
        dnsProvider = mkOption {
          type = types.enum [ "cloudflare" ];
          default = "cloudflare";
        };
        # A ferrum.secrets key, never a path -- the UI can only ever name a
        # secret, not point at one on disk.
        credentialSecret = mkOption {
          # Not types.str: modules/proxy/acme.nix makes this a path
          # component of a sops sopsFile and modules/proxy/dns.nix makes it
          # one of `/run/secrets/${credentialSecret}`, which is where root
          # reads the live Cloudflare token. Neither re-validates it. The
          # type is the same allowlist
          # crates/ferrum-apply/src/put_secret.rs's validate_secret_name
          # applies at the other end of the same name -- see
          # modules/lib/hostnames.nix on why it must be the same rule and
          # not merely a similar one.
          type = hostnames.secretName;
          default = "acme-dns";
        };
        staging = mkOption {
          type = types.bool;
          default = false;
        };
      };

      trustedNetworks = mkOption {
        # Not types.str, for a sharper reason than baseDomain above. Each
        # entry lands in `allow ${net};` at the TOP of a lan app's
        # `location /`, ahead of the `deny all;` and the auth_request block
        # it is concatenated in front of -- so a `}` here does not corrupt
        # the allow-list, it closes the location and leaves the rest of the
        # payload as an ungated sibling. See modules/lib/hostnames.nix.
        type = types.listOf hostnames.networkLiteral;
        default = [ "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" ];
      };

      # ferrum creating the A/CNAME records for the hostnames it publishes.
      # Until this existed, ferrum used the Cloudflare token ONLY for ACME
      # DNS-01 challenge TXT records: certificates issued for names that had
      # no address record at all, and the install reported success while
      # auth.<baseDomain> -- the gate in front of every *arr -- did not
      # resolve. See modules/proxy/dns.nix.
      dns = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Whether ferrum creates and maintains the DNS records for the
            hostnames it publishes.

            Off by default only because it cannot work without a record
            target (staticAddress or cnameTarget below) that nobody can
            guess safely -- a wrong address publishes every app at someone
            else's server. The installer asks for the target and turns this
            on, so a normal install gets records without the operator
            touching a DNS console; a host upgrading in place keeps its
            existing behaviour until it sets one.
          '';
        };

        recordMode = mkOption {
          type = types.enum [ "a" "cname" ];
          default = "a";
          description = ''
            Whether records are A records pointing at a stated address, or
            CNAMEs following a stated hostname.

            This is a decision, not an assumption: a server on a static
            public address wants "a", while one behind a changing address
            wants "cname" onto a name something else already keeps current
            (or "a" plus ddnsUpdater below). Guessing wrong publishes an app
            at an address that is not this server.
          '';
        };

        staticAddress = mkOption {
          # Not types.str: this is the address every A record ferrum
          # publishes points at, sent to the Cloudflare API with a live
          # credential. The JSON serialiser makes injection impossible, so
          # this type is about the value being a real address rather than
          # about escaping -- a non-address here publishes every app at
          # something that is not this server. See modules/lib/hostnames.nix.
          type = hostnames.ipv4Literal;
          default = "";
          example = "203.0.113.10";
          description = ''
            The public IPv4 address every A record points at, used when
            recordMode = "a". The installer detects a candidate from the
            target host itself and shows it for confirmation rather than
            writing it silently -- an address detected from the operator's
            own machine can easily be a VPN or office egress, not the
            server's.

            IPv4 only: ferrum publishes no AAAA record today.
          '';
        };

        cnameTarget = mkOption {
          # Not types.str: same sink and same reasoning as staticAddress
          # above. dnsName rather than a new type because this is the same
          # kind of value as proxy.baseDomain, and the empty string means
          # the same thing at both -- "not configured".
          type = hostnames.dnsName;
          default = "";
          example = "myhost.dynamic-dns.example.net";
          description = ''
            The hostname every record follows, used when recordMode =
            "cname". Typically a dynamic-DNS name maintained outside ferrum,
            which is what makes this the right mode for a host whose address
            changes.
          '';
        };

        adoptedNames = mkOption {
          # Not types.listOf types.str: each entry authorises ferrum to
          # OVERWRITE a DNS record it did not create -- the single exception
          # to the ownership rule below. dnsLabel rather than dnsName
          # because an empty entry authorises nothing and can only be a
          # mistake, and because it is what makes this option's own
          # statement that "there is no value here that means all of them"
          # true: `*.example.com` is refused outright rather than merely
          # being a name no record happens to have.
          type = types.listOf hostnames.dnsLabel;
          default = [ ];
          example = [ "plex.example.com" ];
          description = ''
            The fully qualified record names the operator explicitly handed
            to ferrum, from the installer's pre-erase DNS gate.

            ferrum never overwrites a record it did not create. A name listed
            here is the one exception, and it is deliberately narrow: it
            authorises replacing THAT record and nothing else. Adopting
            plex.example.com says nothing about sonarr.example.com, and there
            is no value here that means "all of them" -- a wildcard string is
            just a name no record has.

            The list matters only once. The adopting write carries ferrum's
            ownership marker, so from the next reconcile onward the record is
            ferrum's under the ordinary rule and this list is not consulted
            for it. Leaving a name here therefore grants nothing the marker
            does not already grant; removing one does not hand the record
            back.

            It never authorises a DELETE. A record at a name this host no
            longer publishes is left alone whether it was adopted or not.
          '';
        };

        ddnsUpdater = {
          enable = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Whether a timer re-checks this host's real public address on a
              schedule and corrects the records ferrum owns when it has
              moved. Opt-in, but RECOMMENDED on any host whose address is
              not contractually static.

              The failure it prevents is the one an operator cannot observe:
              a stale A record leaves every app unreachable from outside
              while the host is healthy, its services are running and its
              certificates are valid, with no error anywhere. It only ever
              touches records ferrum created; a record it does not own is
              reported, never rewritten.
            '';
          };

          intervalMinutes = mkOption {
            type = types.int;
            default = 60;
            description = ''
              How often the updater re-checks the public address. Hourly is
              a deliberate compromise: an address change is rare and costs
              at most this long of outside-world downtime, while a shorter
              interval spends API calls and an address-echo lookup on a
              value that almost never changes.
            '';
          };
        };
      };
    };

    auth = {
      enable = mkEnableOption "Authelia forward-auth";
      adminEmail = mkOption {
        # Not types.str, and the sink is in the other language:
        # crates/ferrum-apply/src/secrets.rs builds Authelia's
        # users_database.yml with format!, interpolating this value inside a
        # double-quoted YAML scalar (`email: "{admin_email}"`). A `"` and a
        # newline therefore write arbitrary YAML into the file that decides
        # who may log in.
        #
        # Constraining it HERE does not make that formatting correct, and it
        # is not a substitute for fixing it -- it is the boundary control on
        # the write path ferrum actually owns, which is
        # modules/lib/settings-schema.json plus this type. The Rust-side
        # serialization is raised separately.
        type = hostnames.emailAddress;
        default = "";
      };
    };

    recyclarr = {
      enable = mkEnableOption "opinionated TRaSH-Guide quality-profile sync for Sonarr/Radarr via Recyclarr";
    };

    secrets = mkOption {
      type = types.attrsOf (types.submodule {
        options.description = mkOption {
          type = types.str;
          default = "";
        };
      });
      default = { };
      description = ''
        Names ferrumd is permitted to write a secret under. See
        modules/core/secrets.nix. Declaring a name here also gates whichever
        catalog app consumes it -- e.g. `qbittorrent-vpn` both permits that
        secret's existence AND enables qBittorrent's VPN-gated network
        namespace (see modules/apps/qbittorrent/service.nix's `vpnEnabled`).
        Declaring a name requires the corresponding
        `<ferrum.secretsDir>/<name>.sops` file to already exist on disk --
        this option does not create or generate one.
      '';
    };

    # `ferrum.backup` was declared here -- enable, repo, schedule,
    # passwordSecret -- and is DELETED rather than constrained, because a
    # forward sweep of every settings leaf to every sink found it reached
    # none. No module, no service, no timer, no crate ever read any of the
    # four. See docs/superpowers/specs/2026-09-21-phase-1-9-ship-it-design.md
    # R26, which is where backup gets built, and whose A5 is exactly this:
    # until it works, the settings UI must not present it as functional.
    #
    # Deleting is not tidying. An option with no sink is worse than an
    # absent one in both directions: an operator who sets backup.repo gets
    # no error and no backup, and a reviewer sweeping this file for values
    # that need a type reasonably assumes a declared option is consumed and
    # validated somewhere. This one had to be traced to nothing, twice.
    #
    # Reversible, and the way back is the point: reintroduce these four
    # TOGETHER WITH the module that reads them, at which point repo and
    # passwordSecret want hostnames.absolutePath and hostnames.secretName
    # respectively -- both of which now exist. `ferrum.apps.<id>.backup.enable`
    # in modules/lib/app-submodule.nix is a DIFFERENT option and is untouched.

    apply = {
      autoRollbackOnFailure = mkOption {
        type = types.bool;
        default = false;
        description = "Off by default: health checks aren't mature enough to trust with an automatic reboot yet.";
      };
      healthCheckTimeoutSec = mkOption {
        type = types.int;
        default = 120;
      };
    };

    daemon = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether ferrumd (the web UI) runs on this host at all.

          This is the RUNS question, not the REACHABLE one -- see `publish`
          below. modules/core/daemon.nix is wrapped in
          `lib.mkIf ferrum.daemon.enable`, so turning this off deletes the
          user, the unit and the polkit rule: there is nothing left to
          reach, over a tunnel or otherwise.
        '';
      };
      publish = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether the daemon this host runs is also reachable from the
          network, at `<ferrum.daemon.subdomain>.<ferrum.proxy.baseDomain>`.

          Split out of `enable` because the two were never the same
          question, and collapsing them cost a recovery route. `enable =
          false` does not unpublish ferrumd, it stops it existing (see
          above), and that was the only spelling of "do not publish the
          dashboard" -- so the installer's stage 1, which cannot enable
          Authelia because its sops secrets cannot exist before the host
          does, had to use it. A stage 2 that failed then left a host with
          no web UI at all and SSH-only recovery, on the product whose whole
          claim is that the UI works.

          With `publish = false` the daemon RUNS, bound to
          `ferrum.daemon.listenAddress` -- which modules/core/daemon.nix's
          A5 assertion holds to a loopback literal -- so it is reachable
          over an SSH tunnel and from nowhere else.
          modules/proxy/lib.nix's `daemonPublished` reads this, which is
          what keeps the vhost (modules/proxy/nginx.nix), the Authelia rule
          (modules/proxy/authelia.nix), the certificate
          (modules/proxy/acme.nix) and the DNS record (modules/proxy/dns.nix)
          absent together rather than one at a time.

          It is NOT an authentication boundary and must not be read as one:
          the tunnel still lands on ferrumd's own `__Host-ferrumd_session`
          login. What it removes is the network path, not the password.
        '';
      };
      port = mkOption {
        type = types.port;
        default = 7788;
      };
      listenAddress = mkOption {
        # A character-set bound only -- whether the value is a LOOPBACK
        # address is modules/core/daemon.nix's A5 assertion, which owns the
        # long operator-facing message. See modules/lib/hostnames.nix.
        type = hostnames.addressLiteral;
        default = "127.0.0.1";
      };
      subdomain = mkOption {
        type = hostnames.dnsLabel;
        default = "ferrum";
        description = "Hostname label under ferrum.proxy.baseDomain for the daemon's own web UI -- same mechanism as every app's own subdomain option, just not tied to the catalog since the daemon isn't a catalog app.";
      };

      dns.includeRecord = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether ferrum's DNS management creates a record for the daemon's
          own subdomain above.

          On by default. That default was taken while ferrumd had no vhost,
          when the record resolved to nginx's catch-all and a closed
          connection; the reasoning was that the record the operator will
          want should exist the moment the UI does. Phase 1.7c R13 shipped
          that UI, so the name now resolves to the dashboard itself. This
          option remains so that turning the record off is one line rather
          than a redesign.
        '';
      };
    };

    apps = mkOption {
      type = appsType;
      default = { };
      description = "The uniform application catalog. See modules/lib/app-submodule.nix.";
    };
  };

  # A uniform option has to be uniformly HONOURED, or it is a lie the UI
  # renders a text field for.
  #
  # ferrum.apps.<id>.port is one option shape across the whole catalog,
  # which is what lets the web UI render one form instead of seven. Four of
  # the seven apps wire it through to their service (sonarr, radarr,
  # prowlarr's `port`, qbittorrent's `webuiPort`). Plex and Jellyfin cannot:
  # nixpkgs' modules for them expose no port option at all, because neither
  # application has a configuration-file setting for it, so
  # modules/apps/*/service.nix has nothing to assign.
  #
  # The option is not inert on those two, which is what makes this a defect
  # rather than a documentation gap. modules/proxy/nginx.nix generates
  # `proxy_pass http://127.0.0.1:${port}` from the same value, so changing
  # it produces a vhost pointed at a port nothing listens on: measured,
  # plex.port = 9999 rendered `proxy_pass http://127.0.0.1:9999` while Plex
  # went on serving 32400, with zero failed assertions. The operator gets a
  # 502, a failing reconciler health check, and no explanation from the
  # layer that knew.
  #
  # Keyed on the catalog's own `portIsFixed` rather than on a list of app
  # ids here, for the reason every other per-app capability
  # (mediaCategory, downloadSubdir, unfreePackages, authBypassPaths) is
  # declared in meta.nix: adding an app must stay "add a directory under
  # modules/apps", and a second place to register one is a second place to
  # forget.
  #
  # It refuses a CHANGED port, not a fixed one, so the default keeps working
  # and the catalog default stays the single source of the real number.
  config.assertions =
    let
      fixedPortViolations = lib.mapAttrsToList
        (name: app:
          "ferrum.apps.${name}.port = ${toString app.port} "
          + "(${catalog.${name}.displayName} always listens on "
          + "${toString catalog.${name}.defaultPort})")
        (lib.filterAttrs
          (name: app:
            app.enable
            && (catalog.${name}.portIsFixed or false)
            && app.port != catalog.${name}.defaultPort)
          config.ferrum.apps);
    in
    [
      {
        assertion = fixedPortViolations == [ ];
        message = ''
          An app has been given a port it cannot honour, and ferrum would
          proxy to it anyway: ${lib.concatStringsSep "; " fixedPortViolations}.

          These applications have no port setting -- not in ferrum, and not
          in the NixOS modules underneath it, because the applications
          themselves have none. The process binds its own fixed port
          whatever this option says. What DOES follow the option is the
          reverse proxy: modules/proxy/nginx.nix generates
          `proxy_pass http://127.0.0.1:<this value>`, so the vhost ends up
          pointed at a port nothing is listening on. The result is a 502 in
          the browser and a failing health check, with nothing in the apply
          output to connect them to this setting.

          Leave the port at its catalog default. If you need the app on a
          different port, that is a change to the application's own
          configuration (Jellyfin's network settings, for instance), and
          ferrum has no way to make it declaratively today.
        '';
      }
    ];
}
