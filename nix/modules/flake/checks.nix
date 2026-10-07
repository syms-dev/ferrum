# The guardrail checks that keep the architecture honest, plus the trivial
# smoke VM test that answers Phase 1.0 probe 0.1 (does a NixOS VM test even
# run on a hosted GitHub runner?).
{ inputs, ... }:
{
  perSystem = { system, pkgs, lib, self', ... }:
    let
      ferrumLib = import ../../../modules/lib {
        nixpkgs = inputs.nixpkgs;
        sopsNix = inputs.sops-nix;
      };
      catalog = import ../../../modules/lib/catalog.nix { inherit lib; };
      appsDir = ../../../modules/apps;
      # Shared by migrationMechanism and mkHostAppliesMigration below, so
      # both real check bodies reference the one real currentVersion
      # rather than each importing (or worse, hardcoding) their own.
      realMigrations = import ../../../modules/lib/migrations.nix { inherit lib; };

      # One representative per equivalence class modules/core/daemon.nix's
      # A5 assertion accepts -- NOT the exact accepted set, which is not a
      # list at all: listenIsLoopback admits any four dot-separated octets
      # whose first is "127", i.e. the whole of 127.0.0.0/8, plus the single
      # literal "::1". So 127.0.0.1 is the default, 127.0.0.2 is here to
      # prove that class is a range rather than one blessed string, and ::1
      # is the only accepted spelling outside it. Named once because two
      # checks below have to agree about it and a drift between them is
      # silent: daemonVhostEnforced asserts every one of
      # these is LEGAL, and nginxConfigParses asserts nginx can actually
      # parse the config each one generates. An accept-set is a claim about
      # every downstream consumer, so widening it owes a test per value at
      # each -- which is how `::1` came to be blessed by the guard and
      # rejected by nginx (`proxy_pass http://::1:7788` -> [emerg] invalid
      # port) with both halves of the tree green.
      acceptedLoopbackSpellings = [ "127.0.0.1" "127.0.0.2" "::1" ];

      # The minimal example host, plus any extra modules a single check
      # needs layered on top.
      #
      # Parameterised rather than copied because `a-host-always-has-a-way-in`
      # needs a CONTROL host that differs from the real one in exactly one
      # declared way, and a second hand-written copy of this argument list
      # would let the two drift -- at which point the control stops
      # controlling for anything. `exampleHosts.minimal` below is this
      # function applied to no extra modules, so it is byte-for-byte the
      # host every other check already evaluates.
      mkMinimalHost = extraModules: ferrumLib.mkHost {
        inherit system;
        settings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
        modules = [
          ../../../examples/hosts/minimal/configuration.nix
          # This host is eval-only (see configuration.nix's own "NOT
          # BOOTABLE" comment) and has no real deployed box's
          # /etc/ferrum/secrets to read from. sops.validateSopsFiles
          # defaults to true and requires each sops.secrets.<name>.sopsFile
          # to be a genuine Nix path value pointing at a file that
          # physically exists at eval time (confirmed by reading
          # sops-nix's own source) -- disabling that check alone (an
          # earlier version of this override did just that) is NOT
          # sufficient, since Nix's own path-value semantics
          # independently require the referenced file to exist the
          # moment the value is touched, regardless of validateSopsFiles.
          # The real fix: point ferrum.secretsDir at real (throwaway,
          # non-production) placeholder secrets committed alongside this
          # example host, via a path LITERAL relative to this file's own
          # location -- that makes it part of ferrum's own flake source,
          # auto-imported into the store at parse time, genuinely
          # readable under pure evaluation (confirmed for real on
          # ferrum-dev: this exact override, with placeholders present,
          # makes checks.eval-example-hosts pass with the real default
          # validateSopsFiles = true, no override needed at all).
          { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
        ] ++ extraModules;
        revision = "ci";
      };

      exampleHosts = {
        minimal = mkMinimalHost [ ];
      };

      # Every app directory with a meta.nix must also have a service.nix, or
      # the module system silently no-ops it while the UI still advertises
      # it as available -- this is the check that would have caught that.
      catalogConsistency =
        let
          dirNames = builtins.attrNames (builtins.readDir appsDir);
          appIds = builtins.filter (id: builtins.pathExists (appsDir + "/${id}/meta.nix")) dirNames;
          missingService = builtins.filter (id: !builtins.pathExists (appsDir + "/${id}/service.nix")) appIds;
          notInCatalog = lib.subtractLists (builtins.attrNames catalog) appIds;
        in
        {
          ok = missingService == [ ] && notInCatalog == [ ];
          inherit missingService notInCatalog;
        };

      # Every option reachable under ferrum.* must stay JSON-expressible,
      # because the web UI can only ever write JSON scalars back into
      # settings.json. A `path`, `package`, or function-typed option here
      # would be an option the UI could describe but never actually set.
      # Deliberately checks the *rendered* type description (the same
      # human-readable string nixosOptionsDoc produces) rather than trying
      # to pattern-match compound type values, since `attrsOf`/`submodule`/
      # `oneOf` wrappers don't preserve a stable identity to compare against.
      forbiddenTypeSubstrings = [ "path" "package" "function" ];

      schemaUniformity =
        let
          allDocs = lib.optionAttrSetToDocList exampleHosts.minimal.options;
          ferrumDocs = builtins.filter
            (o: lib.hasPrefix "ferrum" (lib.elemAt o.loc 0))
            allDocs;
          isForbidden = o:
            lib.any (bad: lib.hasInfix bad (lib.toLower (o.type or ""))) forbiddenTypeSubstrings;
          offenders = builtins.filter isForbidden ferrumDocs;
        in
        {
          ok = offenders == [ ];
          offenders = map (o: lib.concatStringsSep "." o.loc) offenders;
        };

      # Regression guard for the bug documented in the plan's Global
      # Constraints (see docs/superpowers/plans/2026-08-20-phase-1-4a-
      # secrets-foundation.md): sops-nix's own assertion accepts sopsFile
      # if EITHER `builtins.isPath` is true OR it's a string already
      # prefixed with the Nix store dir -- and this host's own
      # `ferrum.secretsDir` override happens to evaluate to a `/nix/store`
      # string (a path literal converted via `toString`), which takes the
      # SECOND branch. That means a future edit reverting any
      # `sopsFile = /. + "${x}/y"` back to plain string interpolation
      # (`sopsFile = "${x}/y"`) would pass on THIS host and still break
      # every real deployed box, whose secretsDir is a plain
      # non-store path -- reading `.sops.secrets.*.sopsFile`'s own value
      # forces no realization (unlike system.build.toplevel below), so this
      # stays genuinely cheap.
      sopsFilesArePaths =
        let
          secrets = lib.attrValues exampleHosts.minimal.config.sops.secrets;
          offenders = builtins.filter (s: !builtins.isPath s.sopsFile) secrets;
        in
        {
          ok = offenders == [ ];
          offenders = map (s: s.sopsFile) offenders;
        };

      # Real test coverage for modules/lib/migrations.nix's own machinery
      # -- genuinely calling its real, exported `migrateWith` function
      # (never a second, independently-written copy of the same
      # recursion) against SYNTHETIC chains constructed inline here, so
      # this test doesn't depend on any real migration ever existing.
      # Proves: a no-op when already current, a single-step migration, a
      # multi-step chain applying in sequence, and a throwing migration
      # genuinely failing eval (via a real Nix `throw`, whose message text
      # reaches the operator through `ferrum-apply preview-migration`'s own
      # stderr passthrough -- this eval-level check can only prove failure
      # occurs, not the message's exact content; message accuracy is a
      # code-review discipline point, the same as this project already
      # treats other throw() messages, e.g. `checks.schema-uniformity`) --
      # all through the one real code path every real host's mkHost call
      # also uses.
      migrationMechanism =
        let
          testMigrations = [
            { from = 1; to = 2; description = "test: renames foo to bar";
              migrate = s: (removeAttrs s [ "foo" ]) // { bar = s.foo or null; }; }
            { from = 2; to = 3; description = "test: doubles baz";
              migrate = s: s // { baz = (s.baz or 0) * 2; }; }
          ];
          testMigrate = realMigrations.migrateWith testMigrations;

          alreadyCurrent = testMigrate { schemaVersion = 3; baz = 5; };
          oneStep = testMigrate { schemaVersion = 2; baz = 5; };
          twoStep = testMigrate { schemaVersion = 1; foo = "hello"; baz = 5; };

          throwingChain = [
            { from = 1; to = 2; description = "test: always throws";
              migrate = s: throw "this update needs your input: real reason here"; }
          ];
          throwingMigrate = realMigrations.migrateWith throwingChain;
          throwCaught = !(builtins.tryEval (throwingMigrate { schemaVersion = 1; })).success;
        in
        {
          ok = alreadyCurrent == { schemaVersion = 3; baz = 5; }
            && oneStep == { schemaVersion = 3; baz = 10; }
            && twoStep == { schemaVersion = 3; bar = "hello"; baz = 10; }
            && throwCaught;
          alreadyCurrent = alreadyCurrent;
          oneStep = oneStep;
          twoStep = twoStep;
          throwCaught = throwCaught;
        };

      # Honest about its own real scope: with modules/lib/migrations.nix's
      # real list empty, migrate is the identity function for any
      # already-current settings.json, so this check CANNOT distinguish
      # "mkHost really calls migrate()" from "mkHost never calls it at
      # all" -- both produce byte-identical output when there is nothing
      # to migrate, and no automated eval check can observe that
      # difference for an identity input. What this genuinely proves: the
      # real mkHost pipeline (mkHost's own removeAttrs-based fix) does not
      # corrupt or drop schemaVersion for the common case every real apply
      # hits (an already-current settings.json), and the result really is a
      # normal, well-typed NixOS config (config.ferrum.schemaVersion
      # actually resolves, nothing throws). The wiring itself -- that
      # mkHost's one-line change from `settings` to `migrate settings` is
      # actually present -- is a small, legible diff verified by ordinary
      # code review of the real diff, the same as any other one-line change
      # in this project.
      #
      # This assertion is tautologically true by construction, permanently --
      # not just "true today" -- because mkHost's removeAttrs strips any
      # input schemaVersion before merging, so config.ferrum.schemaVersion
      # can ONLY ever resolve to the readOnly option's own default (which IS
      # migrations.currentVersion). What this check actually guards against:
      # a future refactor that reintroduces the readOnly-collision bug Task 2
      # found and fixed (e.g. someone "simplifying" mkHost back to
      # `config.ferrum = migrate settings;`) would break this immediately,
      # with the same real error NixOS's module system throws today.
      mkHostAppliesMigration =
        let
          testSettings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
          migratedHost = ferrumLib.mkHost {
            inherit system;
            settings = testSettings;
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
            ];
            revision = "ci";
          };
        in
        {
          ok = migratedHost.config.ferrum.schemaVersion == realMigrations.currentVersion;
          actualSchemaVersion = migratedHost.config.ferrum.schemaVersion;
        };

      # Proof that modules/core/storage.nix's journalDir assertion is really
      # wired into an evaluated host config, not merely written down -- and
      # that the DEFAULT journalDir survives it. That second half is the part
      # worth a check: the assertion rejects anything nesting inside stateDir
      # (/var/lib/ferrum/state), and the default /var/lib/ferrum/journal sits
      # one directory away from it, so an over-broad rewrite of the condition
      # would brick every host rather than only the misconfigured ones.
      #
      # A false NixOS assertion becomes a hard error only when
      # system.build.toplevel is forced, which is far too expensive to do here
      # (eval-example-hosts below documents that cost). This inspects the same
      # config.assertions list top-level reads, one step before NixOS turns a
      # false entry into a throw. builtins.tryEval -- the throwCaught idiom
      # from migrationMechanism above -- keeps a genuine evaluation error on a
      # colliding value counting as "rejected" instead of taking the whole
      # flake down with it.
      journalDirCollision =
        let
          hostWith = journalDir: ferrumLib.mkHost {
            inherit system;
            settings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
            ] ++ lib.optional (journalDir != null) { ferrum.storage.journalDir = journalDir; };
            revision = "ci";
          };
          # Scoped to the journalDir assertion's own message on purpose, and
          # not negotiable: the example host carries OTHER failing assertions
          # unrelated to this one (its committed placeholder secrets under
          # examples/hosts/minimal/secrets/ have no *-apikey-raw.sops
          # counterparts, which modules/ asserts on). Confirmed for real by
          # running this check unscoped first. An unscoped version is not
          # merely noisy, it is worthless in BOTH directions: it reports the
          # legal default as rejected, and it reports every colliding value as
          # rejected for a reason that has nothing to do with journalDir --
          # so it would pass identically with this assertion deleted.
          # null means "leave journalDir at its declared default".
          failuresFor = journalDir:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "ferrum.storage.journalDir" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) (hostWith journalDir).config.assertions))
              );
            in
            if probe.success then probe.value else [ "evaluation threw" ];

          storage = (hostWith null).config.ferrum.storage;
          colliding = [
            "/var/lib/ferrum"
            storage.stateDir
            storage.snapshotDir
            storage.mediaDir
            "${storage.stateDir}/journal"
            "${storage.mediaDir}/journal"
          ];

          defaultFailures = failuresFor null;
          notRejected = builtins.filter (dir: failuresFor dir == [ ]) colliding;
        in
        {
          ok = defaultFailures == [ ] && notRejected == [ ];
          defaultJournalDir = storage.journalDir;
          inherit defaultFailures notRejected;
        };

      # The storage collision assertions ask about PATH NESTING, so they must
      # not be answered with a substring test.
      #
      # Both of them used `lib.hasInfix a b`, and it is wrong in both
      # directions. Measured against the module at 03d569f:
      #
      #   * snapshotDir = "<stateDir>-snaps" -- a SIBLING -- was rejected as
      #     nested, because the parent's string is a substring of the
      #     child's. Same for journalDir = "<mediaDir>-journal". Two legal
      #     layouts refused at apply time, with a message saying something
      #     untrue about them.
      #   * stateDir nested inside snapshotDir was missed entirely. That is
      #     the same hazard with the arguments swapped, and
      #     modules/core/state-restore.nix cares about it in both directions
      #     -- it swaps @state and @snapshots as two subvolumes of ONE
      #     volume, which one containing the other is not.
      #
      # Deliberately two lists rather than one. A check that only listed
      # values that must be REFUSED is passed by an assertion that refuses
      # everything, which is precisely the failure mode the old condition
      # had; a check that only listed values that must be ACCEPTED is passed
      # by deleting the assertion. Each list is the other's anti-vacuity
      # floor, and the `legal` list is the half this repo did not have.
      #
      # Scoped to these assertions' own messages, and to phrases they keep
      # on one line, for the reason journalDirCollision above spells out at
      # length.
      storagePathNesting =
        let
          hostWith = storage: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              inherit storage;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };

          phrases = [
            "ferrum.storage.journalDir must not be"
            "separate paths, with neither equal to nor nested"
          ];
          rejected = storage:
            let
              probe = builtins.tryEval (
                builtins.filter
                  (m: lib.any (phrase: lib.hasInfix phrase m) phrases)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) (hostWith storage).config.assertions))
              );
            in
            # A value the option TYPE refuses throws rather than returning a
            # message; that is still a refusal, and counting it as one keeps
            # a type-level control from reading as a missing assertion.
            if probe.success then probe.value != [ ] else true;

          defaults = (hostWith { }).config.ferrum.storage;

          # Siblings and unrelated paths. Every one of these is a legal
          # layout and must evaluate clean.
          legal = {
            "snapshotDir is a sibling of stateDir" = {
              snapshotDir = "${defaults.stateDir}-snaps";
            };
            "journalDir is a sibling of mediaDir" = {
              journalDir = "${defaults.mediaDir}-journal";
            };
            "journalDir is a sibling of stateDir" = {
              journalDir = "${defaults.stateDir}-journal";
            };
            "the declared defaults" = { };
          };

          # Real containment, in both directions, plus equality.
          illegal = {
            "snapshotDir inside stateDir" = {
              snapshotDir = "${defaults.stateDir}/snapshots";
            };
            "stateDir inside snapshotDir" = {
              stateDir = "${defaults.snapshotDir}/state";
              snapshotDir = defaults.snapshotDir;
            };
            "stateDir equals snapshotDir" = {
              stateDir = "/srv/ferrum-both";
              snapshotDir = "/srv/ferrum-both";
            };
            "journalDir inside mediaDir" = {
              journalDir = "${defaults.mediaDir}/journal";
            };
            "journalDir equals stateDir" = {
              journalDir = defaults.stateDir;
            };
          };

          wronglyRejected = builtins.attrNames (lib.filterAttrs (_: rejected) legal);
          wronglyAccepted = builtins.attrNames (lib.filterAttrs (_: s: !(rejected s)) illegal);
        in
        {
          ok = wronglyRejected == [ ] && wronglyAccepted == [ ];
          message =
            "modules/core/storage.nix's path-collision assertions do not "
            + "test path nesting";
          inherit wronglyRejected wronglyAccepted;
        };

      # Every schema shape the real settings-schema.json contains must have a
      # control in ui/forms.js.
      #
      # This is the mechanical guard on the phase's central claim -- that
      # adding a directory under modules/apps/ makes an app appear with no UI
      # change. Without it the claim decays silently: someone adds an option
      # shape the renderer has never seen, nothing fails, and an operator
      # eventually opens a form, saves it, and loses a field. forms.js's
      # UNSUPPORTED branch stops the data loss; this stops the gap existing.
      #
      # It reads forms.js's single exported SUPPORTED_TYPES literal rather than
      # parsing JavaScript. That is deliberate: one honest declaration a human
      # maintains beats a parser that would quietly disagree with the code it
      # claims to describe. The cost is that adding an entry there WITHOUT
      # adding the matching branch in control() turns this into a rubber stamp
      # -- a code-review discipline point, the same way schema-uniformity
      # treats its own throw() messages.
      # The installer offers the operator a list of apps to enable. That
      # list lives in Rust, on the operator's machine, and the catalog it
      # must match lives in Nix -- nothing connects them at compile time,
      # so a new catalog app would silently be un-installable: present on
      # a host that already has it, and absent from every new install.
      # Same mechanism as uiRendersEverySchemaType below, but NOT the same
      # one-line-literal constraint: rustfmt wraps this literal and no
      # comment can stop it, so the reader below takes the whole
      # declaration. See the note on `declLines`.
      #
      # It also asserts a second, narrower thing about the same pair of
      # files: that every catalog app's defaultSubdomain equals its id.
      # That is not tidiness -- it is the invariant that makes the
      # installer's R1 DNS gate correct. crates/ferrum-install/src/dns.rs's
      # desired_records() builds "<id>.<baseDomain>", as do main.rs's
      # url_report and verify.rs's reachability checks, while the host
      # itself builds "<subdomain>.<baseDomain>" via
      # modules/proxy/lib.nix's vhostNameFor. Today those agree, but only
      # because all seven meta.nix files happen to set the two equal. The
      # day one of them does not, the pre-erase dry run would check a
      # DIFFERENT record name than the apply creates: a foreign record at
      # the real name would never be listed, never offered for adoption,
      # and silently overwritten or stranded -- a quieter replay of the
      # auth.thesyms.ca incident R1 exists to close. Asserting the
      # invariant costs nothing and constrains nothing an operator can do
      # (ferrum.apps.<id>.subdomain stays freely overridable per host; only
      # the catalog *default* is pinned). If a future app genuinely needs a
      # differing default, this check is the thing that stops it shipping
      # until the installer is taught to read subdomains.
      #
      # HEADLESS APPS ARE EXEMPT FROM THE FIRST HALF, and the exemption is
      # narrower than it looks. The invariant above is about a NAME: the
      # installer must plan, publish and verify the same hostname the host
      # serves. An app whose meta.nix declares `headless = true` serves no
      # hostname at all -- modules/lib/app-submodule.nix defaults it to
      # exposure = "local", so modules/proxy/lib.nix's publicApps excludes
      # it and neither dns.nix nor acme.nix ever names it. There is nothing
      # for the two sides to agree about.
      #
      # It is also the SAFE direction. Adding such an app to CATALOG_APPS
      # would be the defect: crates/ferrum-install/src/dns.rs's
      # desired_records() maps every selected app to "<id>.<baseDomain>"
      # unconditionally, so a default "install everything" run would create
      # a public A record -- and main.rs's url_report would print an https
      # URL -- for a process with no socket. Keeping it out of that list
      # keeps "every app the installer selects gets a record and a URL" true
      # by construction, instead of adding a second list of exceptions in
      # Rust that nothing holds to the catalog.
      #
      # The cost, stated plainly: a headless app is not offered during
      # install and is enabled afterwards from the dashboard (or
      # settings.json). The upgrade path, if that ever stops being
      # acceptable, is to teach the installer to carry the headless set and
      # filter the three hostname-shaped consumers by it -- at which point
      # this exemption is deleted, not widened.
      #
      # The second half (defaultSubdomain == id) is deliberately NOT
      # exempted. A headless app still has a subdomain option, it still
      # participates in nginx.nix's collision detection over enabled apps,
      # and holding the whole catalog to one rule is cheaper than
      # remembering which half applies to whom.
      installerOffersEveryCatalogApp =
        let
          answersSrc = builtins.readFile ../../../crates/ferrum-install/src/answers.rs;
          # Read from the declaration's opening line to its closing `];`,
          # rather than from that one line alone.
          #
          # It used to read the single line, and answers.rs carried a comment
          # promising to keep the literal on one. That promise was
          # unkeepable: the seven names plus the type annotation run past
          # rustfmt's max_width, so rustfmt wraps them one per line and the
          # comment cannot stop it. The result was worse than a check that
          # did not exist -- the opening line holds no quoted names at all,
          # so `declared` was empty, every catalog app read as "missing",
          # and the check was UNCONDITIONALLY red. A check that always fails
          # reports nothing: it cannot distinguish the drift it was built to
          # catch from its own breakage.
          #
          # A line range rather than a multi-line regex for the reason the
          # original comment gives -- Nix's regex engine rejects the
          # bracket-negation forms that would be needed -- but taking the
          # range first and matching within it needs no such form.
          declLines =
            let
              lines = lib.splitString "\n" answersSrc;
              after = lib.sublist
                (let
                   indexed = lib.imap0 (i: l: { inherit i l; }) lines;
                   hits = builtins.filter (e: lib.hasInfix "pub const CATALOG_APPS" e.l) indexed;
                 in if hits == [ ] then
                      throw "crates/ferrum-install/src/answers.rs no longer declares CATALOG_APPS in a form this check can read"
                    else (builtins.head hits).i)
                (builtins.length lines)
                lines;
              # Everything up to and including the line closing the literal.
              # `];` is unambiguous here: it is the first one after the
              # declaration begins.
              take = acc: rest:
                if rest == [ ] then
                  throw "crates/ferrum-install/src/answers.rs declares CATALOG_APPS but this check cannot find the '];' that closes it"
                else
                  let head = builtins.head rest; in
                  if lib.hasInfix "];" head then acc ++ [ head ]
                  else take (acc ++ [ head ]) (builtins.tail rest);
            in
            builtins.concatStringsSep "\n" (take [ ] after);
          declared =
            map builtins.head
              (builtins.filter builtins.isList
                (builtins.split "\"([a-z0-9-]+)\"" declLines));

          catalog = import ../../../modules/lib/catalog.nix { inherit lib; };
          catalogApps = builtins.attrNames catalog;
          # The apps that have a front door, which is the set this half is
          # about. Read off the catalog's own `headless` mark, never a list
          # of ids here -- the same rule modules/core/options.nix's
          # headlessViolations follows.
          offerable = builtins.filter (a: !(catalog.${a}.headless or false)) catalogApps;
          missing = builtins.filter (a: !(builtins.elem a declared)) offerable;
          # Still measured against the WHOLE catalog: the installer offering
          # an app that does not exist is a bug whether or not that app
          # would have had a hostname. An entry naming a headless app is
          # caught by the explicit test below instead, which says why.
          extra = builtins.filter (a: !(builtins.elem a catalogApps)) declared;
          # The exemption, held to its own floor in both directions: a
          # headless app must NOT appear in CATALOG_APPS (it would get a DNS
          # record and a printed https URL -- see the header), and the
          # headless set must not be empty, or the three lines above are
          # testing nothing and the exemption is dead code that reads as
          # coverage.
          headlessApps = builtins.filter (a: catalog.${a}.headless or false) catalogApps;
          headlessOffered = builtins.filter (a: builtins.elem a declared) headlessApps;

          # The installer names records, urls and reachability checks after
          # the app id; the host names its vhost after the subdomain. See
          # the header above for why letting those two diverge is a silent
          # DNS defect rather than a cosmetic one.
          renamed = builtins.filter (id: catalog.${id}.defaultSubdomain != id) catalogApps;
        in
        {
          ok = missing == [ ] && extra == [ ] && renamed == [ ]
            && headlessApps != [ ] && headlessOffered == [ ];
          message =
            "crates/ferrum-install/src/answers.rs's CATALOG_APPS is out of step with "
            + "modules/lib/catalog.nix."
            + (lib.optionalString (missing != [ ])
                " In the catalog but not offered by the installer: ${lib.concatStringsSep ", " missing}.")
            + (lib.optionalString (headlessApps == [ ])
                (" No app in the catalog declares headless = true, so this check's"
                  + " headless exemption is now testing nothing: `missing` is"
                  + " measured over a set identical to the whole catalog and the"
                  + " exemption below is unreachable. Either an app lost its mark"
                  + " -- in which case it also lost its exposure default and now"
                  + " gets a vhost, a certificate and a DNS record -- or the"
                  + " exemption should be deleted along with this branch."))
            + (lib.optionalString (headlessOffered != [ ])
                (" These apps have no web interface and must NOT be in CATALOG_APPS: "
                  + lib.concatStringsSep ", " headlessOffered
                  + ". crates/ferrum-install/src/dns.rs's desired_records() maps every"
                  + " selected app to '<id>.<baseDomain>' unconditionally, and"
                  + " main.rs's url_report prints 'https://<id>.<baseDomain>' for each"
                  + " one. Offering a headless app there publishes a public DNS record"
                  + " and advertises a URL for a process that listens on nothing --"
                  + " which is the whole failure modules/lib/app-submodule.nix's"
                  + " headless exposure default exists to prevent, reintroduced from"
                  + " the installer side where the host's own checks cannot see it."))
            + (lib.optionalString (extra != [ ])
                " Offered by the installer but not in the catalog: ${lib.concatStringsSep ", " extra}.")
            + (lib.optionalString (renamed != [ ])
                (" These apps declare a defaultSubdomain that is not their id: "
                  + lib.concatMapStringsSep ", "
                      (id: "${id} -> ${catalog.${id}.defaultSubdomain}")
                      renamed
                  + ". The installer's pre-erase DNS gate"
                  + " (crates/ferrum-install/src/dns.rs desired_records), its url report"
                  + " (crates/ferrum-install/src/main.rs url_report) and its reachability"
                  + " checks all build '<id>.<baseDomain>', while the host builds"
                  + " '<subdomain>.<baseDomain>' (modules/proxy/lib.nix vhostNameFor)."
                  + " Those would now plan and verify a different name than the host"
                  + " publishes. Teach the installer to read defaultSubdomain before"
                  + " changing this."));
        };

      uiRendersEverySchemaType =
        let
          formsSrc = builtins.readFile ../../../ui/forms.js;
          # Find the one line declaring the literal, then pull the quoted
          # names out of it. Line-oriented rather than a multi-line regex:
          # Nix's regex engine rejects the bracket-negation forms that would
          # be needed, and a line lookup is clearer than working around it.
          declLine =
            let hits = builtins.filter (l: lib.hasInfix "SUPPORTED_TYPES = [" l)
                         (lib.splitString "\n" formsSrc);
            in if hits == [ ] then
                 throw "ui/forms.js no longer declares SUPPORTED_TYPES on a single line that this check can read"
               else builtins.head hits;
          declared =
            map builtins.head
              (builtins.filter builtins.isList
                (builtins.split "\"([a-z-]+)\"" declLine));

          schema = builtins.fromJSON (builtins.readFile ../../../modules/lib/settings-schema.json);

          # The shape vocabulary must match forms.js's control() branches
          # exactly: an enum'd string and a plain string are different
          # controls, and so is an array by its item type.
          shapeOf = node:
            let t = node.type or null; in
            if t == "string" && node ? enum then [ "string-enum" ]
            else if t == "array" then
              [ ("array-of-" + (((node.items or { }).type or "unknown"))) ]
            else if t != null && builtins.isString t then [ t ]
            else [ ];

          walk = node:
            if !(builtins.isAttrs node) then [ ]
            else
              shapeOf node
              ++ lib.concatMap walk (builtins.attrValues (node.properties or { }))
              ++ lib.concatMap walk (builtins.attrValues (node.patternProperties or { }))
              ++ (if builtins.isAttrs (node.items or null) then walk node.items else [ ])
              ++ (if builtins.isAttrs (node.additionalProperties or null)
                  then walk node.additionalProperties else [ ]);

          present = lib.unique (walk schema);
          missing = builtins.filter (t: !(builtins.elem t declared)) present;
        in
        {
          ok = missing == [ ];
          inherit missing declared;
          schemaShapes = present;
        };

      # modules/lib/settings-schema.json is not documentation: ferrumd
      # compiles it and validates every PUT /api/settings against it
      # (crates/ferrumd/src/settings.rs), and every object in it is
      # `additionalProperties: false`. So an option added under ferrum.*
      # without a matching schema entry is not a doc gap -- it is a 400 on
      # the next settings save for every host that sets it, including a save
      # that only round-trips the block back unchanged.
      #
      # That is not hypothetical. This check was written after R1 added
      # ferrum.proxy.dns.* and ferrum.daemon.dns.includeRecord and touched
      # nothing here, which broke saving settings from the web UI on the
      # default shape of a domain install; it immediately found a second,
      # older instance in ferrum.storage.pool.*, unschema'd since the
      # mergerfs work and reached by any multi-disk install. Both were
      # confirmed against a real JSON Schema validator.
      #
      # NEITHER existing guardrail catches this class, so do not delete it as
      # redundant with them: schema-uniformity only forbids non-JSON option
      # TYPES, and ui-renders-every-schema-type only asks whether a shape
      # ALREADY in the schema has a UI control. Both were green against a
      # schema that rejected real documents.
      #
      # The direction is options -> schema deliberately. A schema property
      # with no option is caught loudly at evaluation by the module system
      # itself; an option with no schema property is caught by nothing until
      # an operator hits Save.
      schemaCoversEveryOption =
        let
          schema = builtins.fromJSON (builtins.readFile ../../../modules/lib/settings-schema.json);

          # `internal`, because every submodule carries the module system's
          # own `_module.*` plumbing under it -- options no settings.json
          # ever contains and no schema should name.
          ferrumDocs = builtins.filter
            (o:
              lib.elemAt o.loc 0 == "ferrum"
              && builtins.length o.loc > 1
              && !(o.internal or false))
            (lib.optionAttrSetToDocList exampleHosts.minimal.options);

          # Walks the schema alongside one option path, mirroring how the
          # validator itself descends. A node declaring no child vocabulary
          # at all is OPAQUE and covers everything beneath it -- that is the
          # `apps` escape hatch, whose per-app shape the schema defers on
          # purpose (see its own description there).
          covers = node: path:
            if path == [ ] then true
            else if !(node ? properties || node ? additionalProperties || node ? patternProperties)
            then true
            else
              let
                key = builtins.head path;
                rest = builtins.tail path;
                props = node.properties or { };
                extra = node.additionalProperties or null;
              in
              # optionAttrSetToDocList renders an attrsOf/submodule key as
              # the literal "<name>", which is the validator's
              # additionalProperties slot.
              if key == "<name>" then builtins.isAttrs extra && covers extra rest
              else if props ? ${key} then covers props.${key} rest
              # `additionalProperties: true` is JSON Schema for "and
              # anything else is fine", which is precisely the partial
              # deferral the apps node now expresses: it names
              # auth.bypassPaths so that value gets its pattern, and leaves
              # every sibling open. Before SEC-02 the apps node declared no
              # child vocabulary at all and was opaque by the clause above,
              # so this case could not arise. It is a narrowing of coverage
              # ONLY where a schema author writes the keyword deliberately;
              # a node with additionalProperties: false that misses an
              # option still fails, which is the case this check was
              # written for.
              else if (node.additionalProperties or null) == true then true
              else false;

          uncovered = builtins.filter (o: !(covers schema (builtins.tail o.loc))) ferrumDocs;
        in
        {
          ok = uncovered == [ ];
          missingFromSchema = map (o: lib.concatStringsSep "." o.loc) uncovered;
        };

      # The auth model, asserted against the GENERATED nginx config rather
      # than against the metadata that describes it.
      #
      # This exists because the metadata and the behaviour disagreed for
      # three phases. Every app's meta.nix declared authBypassPaths, the
      # app submodule exposed it as an option, the UI mentioned it -- and
      # modules/proxy/nginx.nix put auth_request on locations."/" and
      # generated nothing else. Reading any one of those files suggested
      # the feature worked. Only the rendered vhost shows that it did not.
      authModelEnforced =
        let
          host = ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = true; baseDomain = "example.test"; acme.email = "a@example.test"; };
              auth = { enable = true; adminEmail = "a@example.test"; };
              apps = {
                plex.enable = true;
                sonarr.enable = true;
              };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          vhosts = host.config.services.nginx.virtualHosts;
          plexV = vhosts."plex.example.test" or null;
          sonarrV = vhosts."sonarr.example.test" or null;
          hasAuth = v: loc:
            v != null && (v.locations.${loc} or null) != null
            && lib.hasInfix "auth_request /authelia" (v.locations.${loc}.extraConfig or "");
          problems =
            lib.optional (plexV == null) "no vhost generated for plex"
            ++ lib.optional (sonarrV == null) "no vhost generated for sonarr"
            # Plex authenticates itself; forward-auth in front of it breaks
            # every native client.
            ++ lib.optional (hasAuth plexV "/")
                 "plex's / is behind forward-auth, which breaks Roku/TV/mobile clients"
            # Sonarr has no real login of its own, so its UI must be gated.
            ++ lib.optional (!(hasAuth sonarrV "/"))
                 "sonarr's / is NOT behind forward-auth, so it is published unauthenticated"
            # ...but its API must not be, or Prowlarr, mobile clients and
            # ferrum's own reconciler all break.
            ++ lib.optional (sonarrV != null && (sonarrV.locations."/api" or null) == null)
                 "sonarr has no /api location, so its API is behind forward-auth"
            ++ lib.optional (hasAuth sonarrV "/api")
                 "sonarr's /api is behind forward-auth, which breaks Prowlarr and ferrum-reconcile"
            # No app may DEFAULT to two_factor. Authelia demands TOTP
            # enrolment before a first login and ferrum's notifier writes
            # the enrolment link to a file on the host, so a two_factor
            # default locks the operator out of a working system. Caught
            # only by an operator failing to log in, on real hardware.
            ++ map (a: "${a} defaults to two_factor, which locks the operator out: the TOTP enrolment link goes to a file on the host")
                 (lib.filter (a: (catalog.${a}.defaultAuthPolicy or "") == "two_factor")
                   (builtins.attrNames catalog));
        in
        {
          ok = problems == [ ];
          message = "the generated nginx config does not match the declared auth model";
          inherit problems;
        };

      # R13: the control plane is actually published, actually gated, and
      # actually absent when it should be.
      #
      # Like authModelEnforced above, this reads the GENERATED config -- the
      # nginx virtualHosts, the Authelia access_control rules and the
      # security.acme.certs entries a real host ends up with -- not the
      # metadata that is supposed to produce them. That distinction is the
      # entire point here: ferrum.daemon.subdomain has existed and been
      # described as the daemon's hostname since Phase 1.5, while nothing
      # anywhere turned it into a vhost. An assertion over the option would
      # have passed the whole time.
      daemonVhostEnforced =
        let
          mkProxyHost =
            { proxy ? true
            , baseDomain ? "example.test"
            , apps ? { plex.enable = true; sonarr.enable = true; }
            , secrets ? { }
              # Every fixture in this check took ferrum.daemon.* at its
              # defaults, and three separate holes lived in that gap: the
              # daemon.enable term of daemonPublished could be deleted with
              # both this check and dns-record-set still green; the
              # proxyPass assertion below compared two expressions built
              # from the same defaulted constants, so substituting the
              # literal "http://127.0.0.1:7788" passed; and A5's loopback
              # clause had no Nix-side guard at all. A fixture that never
              # moves an option cannot tell a value being READ from a value
              # being ASSUMED.
            , daemon ? { }
              # Every fixture here also took auth.enable = true, which is
              # the value that hides H-03: ferrum.auth.enable is an
              # mkEnableOption and so defaults to FALSE, while
              # ferrum.daemon.enable defaults to true. The configuration this
              # check never built is the one a real host lands on by doing
              # nothing.
            , auth ? true
              # SEC-01. Left null so every existing fixture keeps the option
              # at its default -- the point of the fixtures below is that
              # this value MOVES, and a fixture that never moves an option
              # cannot tell a value being read from a value being assumed.
            , trustedNetworks ? null
              # The ACME contact address, which reaches a generated SHELL
              # word rather than a config directive. Same reason as above:
              # the fixture has to be able to MOVE it.
            , acmeEmail ? "a@example.test"
              # Authelia's first user, which reaches a format!-built YAML
              # scalar in crates/ferrum-apply/src/secrets.rs.
            , adminEmail ? "a@example.test"
            }: ferrumLib.mkHost {
              inherit system;
              settings = {
                schemaVersion = realMigrations.currentVersion;
                proxy = { enable = proxy; inherit baseDomain; acme.email = acmeEmail; }
                  // lib.optionalAttrs (trustedNetworks != null) { inherit trustedNetworks; };
                auth = { enable = auth; adminEmail = adminEmail; };
                inherit apps secrets daemon;
              };
              modules = [ ../../../examples/hosts/minimal/configuration.nix ];
            };

          published = mkProxyHost { };
          daemonSub = published.config.ferrum.daemon.subdomain;
          daemonPort = published.config.ferrum.daemon.port;
          daemonAddr = published.config.ferrum.daemon.listenAddress;
          daemonName = "${daemonSub}.example.test";
          vhosts = published.config.services.nginx.virtualHosts;
          daemonV = vhosts.${daemonName} or null;
          # R5/SEC-M02. The control plane's own Authelia portal, which the
          # daemon vhost's 401 redirect now points at.
          controlPortalV = vhosts."auth.${daemonName}" or null;
          # `or { }` rather than `or null` so a missing location degrades to an
          # empty config string and produces a specific "directive missing"
          # problem, instead of throwing before any of them are reported.
          locOf = loc: (daemonV.locations.${loc} or { }).extraConfig or "";
          rootLoc = locOf "/";
          apiLoc = locOf "/api/";
          loginLoc = locOf "/api/login";
          hasIn = needle: hay: lib.hasInfix needle hay;

          # ROAD-TO-PUBLIC item 22. The ONLY daemon-vhost locations that are
          # allowed to reach ferrumd without Authelia in front of them, named
          # one by one.
          #
          # `/authelia` is the forward-auth subrequest itself (it is `internal`
          # and cannot be requested from outside) and `@ferrum_api_401` is a
          # named error location, so neither is a reachable bypass. The two
          # health paths are, and that is the deliberate decision recorded in
          # modules/proxy/nginx.nix: a health endpoint behind SSO answers a
          # monitor with the portal's own 200 and reports a dead box healthy.
          healthLocationNames = [ "= /api/health" "= /api/ready" ];
          authExemptLocations = healthLocationNames ++ [ "/authelia" "@ferrum_api_401" ];
          # Every location that reaches the daemon WITHOUT forward-auth, minus
          # the ones named above. This is the general form of the /api/login
          # guard below -- that one catches a single known path losing its
          # auth_request, this catches ANY new location being added without
          # one, which is the mistake the health endpoints make cheap.
          unexpectedlyUnauthed = builtins.filter
            (loc: !(builtins.elem loc authExemptLocations)
              && !(hasIn "auth_request /authelia" (locOf loc)))
            (builtins.attrNames (if daemonV == null then { } else daemonV.locations or { }));

          # The daemon vhost's SERVER-level config, and the http-level block
          # every vhost inherits. Both are read because nginx's add_header
          # makes them interdependent in a way that reading either alone
          # would miss: a child block that sets any add_header REPLACES the
          # inherited set rather than extending it, so the moment the daemon
          # sets its frame headers at server level it stops emitting the
          # http-level pair unless it repeats them. Measured on a real nginx
          # -- the vhost asking for more protection got strictly less. The
          # per-location checks below then rely on the daemon's locations
          # setting no add_header of their own, which is what lets them
          # inherit these four.
          daemonServer = if daemonV == null then "" else (daemonV.extraConfig or "");
          commonHttp = published.config.services.nginx.commonHttpConfig or "";
          locationsWithAddHeader = builtins.filter
            (loc: hasIn "add_header" (locOf loc))
            (builtins.attrNames (if daemonV == null then { } else daemonV.locations or { }));

          # A7: no baseDomain, or no proxy, means NO vhost -- not a vhost on a
          # hostname that will never resolve.
          #
          # The two halves are NOT symmetrical, and the comment that used to
          # claim they were ("both hosts still generate other vhosts") was
          # false for the first of them. modules/proxy/nginx.nix is wrapped in
          # `lib.mkIf proxyEnabled`, so with the proxy off this fixture's
          # services.nginx.virtualHosts is nixpkgs' own untouched default and
          # holds no ferrum vhost of any kind. An `absentWhenProxyOff ?
          # "<daemon>"` over that scans an EMPTY corpus: it passed, and it
          # would have gone on passing with the daemon vhost emitted
          # unconditionally. A scan over nothing finds nothing -- the same
          # vacuity failure nginx-emits-no-cors-headers below guards against
          # explicitly, arrived at from the other direction.
          #
          # So nginx is asked only what its corpus can actually answer -- the
          # proxy module emits nothing at all here, daemon and catalog app
          # alike -- and A7's real proxy-off assertion moves to a corpus this
          # fixture is PROVED to have populated (proxyOffRules below).
          #
          # The apps carry an EXPLICIT exposure, and finding out why is what
          # that guard was for. app-submodule.nix defaults exposure to
          # `if proxyEnabled then "public" else "local"`, so a bare
          # `sonarr.enable = true` silently becomes a LOCAL app once the
          # proxy is off: exposedApps is empty, Authelia emits no rules at
          # all, and the second corpus would have been every bit as vacuous
          # as the nginx one. Stating the exposure keeps the generator
          # running, so its output is a real list with a real absence in it.
          proxyOff = mkProxyHost {
            proxy = false;
            apps = {
              plex = { enable = true; exposure = "public"; };
              sonarr = { enable = true; exposure = "public"; };
            };
          };
          proxyOffVhosts = proxyOff.config.services.nginx.virtualHosts;
          # Named rather than "everything except nginx's own default": these
          # are the five names modules/proxy/nginx.nix generates for this
          # fixture when the proxy IS on, so the list is exactly the thing
          # whose absence is being claimed.
          ferrumVhostNames = [
            daemonName
            "auth.example.test"
            "plex.example.test"
            "sonarr.example.test"
            "_ferrum_unmatched"
          ];
          proxyOffFerrumVhosts = builtins.filter (n: proxyOffVhosts ? ${n}) ferrumVhostNames;

          # The corpus that IS populated with the proxy off.
          # modules/proxy/authelia.nix is wrapped in `lib.mkIf authEnabled`,
          # NOT proxyEnabled, so a proxy-off/auth-on host really does run the
          # access_control generator and really does emit a rule per catalog
          # app. That makes it the place where losing daemonPublished's proxy
          # term would be VISIBLE: Authelia would authorize a hostname with no
          # vhost behind it (and modules/proxy/dns.nix's authRecords would
          # publish a record for it -- asserted in dns-record-set), while
          # nginx, switched off wholesale, says nothing either way.
          # scannedARealAppRule is what makes the absence below a finding
          # rather than an empty list.
          proxyOffRules =
            proxyOff.config.services.authelia.instances.main.settings.access_control.rules;
          proxyOffDaemonRules = builtins.filter (r: r.domain or "" == daemonName) proxyOffRules;
          scannedARealAppRule =
            builtins.any (r: r.domain or "" == "sonarr.example.test") proxyOffRules;

          # The no-domain half, by contrast, really does leave the proxy
          # module running: nginx.nix gates on ferrum.proxy.enable alone, so
          # this host generates "plex.", "sonarr.", "auth." and the catch-all,
          # and the absence of "<daemon>." among them is a real finding.
          # scannedTheCatchAll pins that, so the day nginx.nix grows a
          # baseDomain gate this fails loudly instead of quietly turning into
          # the vacuous check above.
          #
          # Recorded rather than fixed: baseDomain = "" is a configuration
          # modules/proxy/acme.nix asserts against, and this check reads
          # .config.services.nginx.virtualHosts without ever touching
          # .config.assertions -- so the host it evaluates is one a real build
          # would refuse. That is deliberate here. The assertion itself is
          # reserved-subdomain-collision's business (it has the tryEval
          # machinery for reading assertions); what A7 needs at this site is
          # what the GENERATOR does with an empty domain, which is precisely
          # what an unasserted eval shows.
          absentWhenNoDomain =
            (mkProxyHost { baseDomain = ""; }).config.services.nginx.virtualHosts;
          scannedTheCatchAll = absentWhenNoDomain ? "_ferrum_unmatched";

          # ferrum.daemon.enable = false: the operator who does not want the
          # control plane on this box at all. daemonPublished's first term is
          # the only thing that expresses it, and nothing varied it -- so the
          # term could be deleted outright with every check still green,
          # leaving a host that runs no ferrumd advertising a vhost, an
          # Authelia rule and a certificate for one.
          #
          # scannedASiblingVhost is the guard: the proxy is ON here, so this
          # fixture really does generate vhosts, and the daemon's absence
          # among them is a finding rather than an empty corpus.
          daemonOff = mkProxyHost { daemon.enable = false; };
          daemonOffVhosts = daemonOff.config.services.nginx.virtualHosts;
          daemonOffRules =
            daemonOff.config.services.authelia.instances.main.settings.access_control.rules;
          scannedASiblingVhost = daemonOffVhosts ? "sonarr.example.test";

          # ...and the host that MOVES the daemon. Every one of these three
          # values is a default in modules/core/options.nix, which is what
          # made the assertions that read them unfalsifiable: a check whose
          # expected value is computed from the same default it is checking
          # passes whether the module consulted the option or hardcoded the
          # literal. The expectations below are written out by hand for that
          # reason, and they are deliberately values nothing else in the tree
          # uses.
          movedAddress = "127.0.0.2";
          movedPort = 9999;
          movedSub = "panel";
          moved = mkProxyHost {
            daemon = {
              listenAddress = movedAddress;
              port = movedPort;
              subdomain = movedSub;
            };
          };
          movedName = "${movedSub}.example.test";
          movedVhosts = moved.config.services.nginx.virtualHosts;
          movedV = movedVhosts.${movedName} or null;
          movedRules =
            moved.config.services.authelia.instances.main.settings.access_control.rules;

          # ...and the same fixture at the IPv6 spelling of loopback, which
          # the A5 guard blesses and which nginx cannot parse unbracketed.
          # nginxConfigParses below settles that with a real `nginx -t`; this
          # pins the exact string cheaply, at evaluation, so the regression
          # is named here rather than only inside a parser's error message.
          v6 = mkProxyHost { daemon.listenAddress = "::1"; };
          v6Pass =
            (((v6.config.services.nginx.virtualHosts.${daemonName} or { }).locations."/"
              or { }).proxyPass or "");
          v6Expected = "http://[::1]:${toString daemonPort}";

          # A5's other half, and the one nothing in either language held:
          # that ferrumd is not ALLOWED to bind a public interface.
          # modules/lib/settings-schema.json types daemon.listenAddress as a
          # bare string, so ferrum's own web UI can write "0.0.0.0" into
          # settings.json; modules/core/daemon.nix now refuses that at
          # evaluation, and this is what proves the refusal is real in both
          # directions.
          #
          # Same builtins.tryEval + message-scoping idiom as
          # reservedSubdomainCollision below, and scoped for the same
          # non-negotiable reason: these fixtures carry other failing
          # assertions (the example host's placeholder secrets have no
          # *-apikey-raw.sops counterparts), so an unscoped version would
          # report every host as rejected and would pass identically with
          # the assertion deleted. The phrase matched is kept on ONE line of
          # daemon.nix's message for the same reason it is in that check:
          # an infix spanning a multi-line Nix string's line break never
          # matches.
          loopbackFailuresFor = addr:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "is not a loopback address" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion)
                      (mkProxyHost { daemon.listenAddress = addr; }).config.assertions)));
            in
            if probe.success then probe.value else [ "evaluation threw" ];
          # Not just 127.0.0.1: the recovery route A5 protects is an SSH
          # tunnel to wherever ferrumd listens, so every loopback spelling
          # has to keep working or the assertion is a regression dressed as
          # a control. The same list drives nginxConfigParses below, which
          # is what makes "accepted" mean "the generated config loads".
          wronglyRejected = builtins.filter (a: loopbackFailuresFor a != [ ])
            acceptedLoopbackSpellings;
          wronglyAccepted = builtins.filter (a: loopbackFailuresFor a == [ ])
            [ "0.0.0.0" "192.168.1.10" "::" "127.0.0.1.example.test" ];
          # The same guard, asked the adversarial question instead of the
          # careless one. Every value above is an operator misconfiguring a
          # box. These are an attacker holding the settings API, which is a
          # write path that really exists: modules/lib/settings-schema.json
          # typed listenAddress as a bare string, so `PUT /api/settings`
          # chose the bytes that modules/proxy/nginx.nix then interpolates
          # into proxy_pass with no quoting of any kind.
          #
          # The first payload was proved end to end against a real nginx
          # before this line was written. The pre-parse guard split it on
          # "." into [ "127" "0" "0" "1 ; return 200 \"pwned\" ; #" ], found
          # four parts whose head is "127", and accepted it; nginx then read
          #   proxy_pass http://127.0.0.1 ; return 200 "pwned" ; #:7788;
          # with EXIT 0 -- the injected `return` live, the trailing `#`
          # swallowing only the `:7788;` behind it. A shape heuristic is not
          # an address parse, and nginx's parser cannot tell you so, because
          # what comes out the other side is valid nginx.
          #
          # The second is the newline spelling of the same attack. `;` is not
          # nginx's only directive separator, and an anchored pattern whose
          # `$` is the multiline kind stops at the line break and blesses
          # everything after it.
          wronglyAcceptedInjection = builtins.filter (a: loopbackFailuresFor a == [ ])
            [
              "127.0.0.1 ; return 200 \"pwned\" ; #"
              "127.0.0.1\nreturn 200 \"pwned\";"
            ];
          # Refused too, but for a different reason, and carrying its own
          # message for that reason -- "the world can reach it" is simply
          # untrue of localhost, and a guard that reports the wrong cause
          # sends the next operator to the wrong file. It is refused because
          # it is a NAME: nginx resolves it at config load and balances
          # across every address it yields, while ferrumd binds only the
          # first (modules/core/daemon.nix says so at length).
          wronglyAcceptedNames = builtins.filter (a: loopbackFailuresFor a == [ ])
            [ "localhost" ];
          # And the third refusal, which until now only a COMMENT claimed.
          # modules/proxy/nginx.nix brackets any listenAddress containing a
          # colon, unconditionally, and says in as many words that it needs
          # no "already bracketed?" branch because A5 refuses "[::1]" so one
          # can never arrive. That was true, and nothing asserted it: adding
          # the one obvious clause to listenIsLoopback leaves
          # daemon-vhost-enforced, nginx-config-parses and
          # auth-model-enforced all green while the generated config becomes
          # `proxy_pass http://[[::1]]:7788` -- `[emerg] invalid host in
          # upstream`, and nginx refuses the whole FILE, so every vhost on
          # the host is down at nginx.service start after an apply that
          # reported success. This is that comment, made load-bearing.
          wronglyAcceptedBracketed = builtins.filter (a: loopbackFailuresFor a == [ ])
            [ "[::1]" ];

          # The sweep's own finding, and the only sink in this check whose
          # consumer is a SHELL rather than a config parser.
          # ferrum.proxy.acme.email was types.str with an unconstrained
          # schema node. nixpkgs' security.acme escapes it correctly for
          # lego and then interpolates the SAME value raw inside a
          # single-quoted word in the renewal script:
          #
          #   [ -n "$(find accounts -name '${data.email}.key')" ]
          #
          # Rendered, one character apart, read out of the two generated
          # scripts:
          #
          #   find accounts -name 'a@example.test.key')" ]; then
          #   find accounts -name 'a'@example.test.key')" ]; then
          #
          # so the payload below runs a command in acme-<cert>.service as
          # the acme user on every renewal.
          acmeEmailAccepted = email:
            let
              probe = builtins.tryEval (
                let v = (mkProxyHost { acmeEmail = email; }).config.security.acme.defaults.email;
                in builtins.deepSeq v v);
            in
            probe.success;

          # The control. The empty string is load-bearing -- it is the
          # option's default, and modules/proxy/acme.nix is what decides an
          # address is required, in a message this type must not swallow --
          # and a plus-addressed contact is a real thing operators use.
          wronglyRejectedEmail = builtins.filter (e: !(acmeEmailAccepted e))
            [ "" "a@example.test" "ops+ferrum@example.co.uk" "first.last@sub.example.test" ];
          wronglyAcceptedEmail = builtins.filter acmeEmailAccepted
            [
              "a'@example.test"
              "a'; touch /tmp/pwned; '@example.test"
              "a b@example.test"
              "a$(id)@example.test"
            ];

          # ferrum.auth.adminEmail, whose sink is in the other language:
          # crates/ferrum-apply/src/secrets.rs writes Authelia's
          # users_database.yml with format!, interpolating this inside
          # `email: "{admin_email}"`. A quote and a newline write arbitrary
          # YAML into the file that decides who may log in -- a second
          # `admins` member, or a replacement password hash. The Rust-side
          # serialization is raised separately; this is the boundary control
          # on the write path, asserted so it cannot quietly go back to
          # types.str.
          adminEmailAccepted = email:
            let
              probe = builtins.tryEval (
                let v = (mkProxyHost { adminEmail = email; }).config.ferrum.auth.adminEmail;
                in builtins.deepSeq v v);
            in
            probe.success;
          wronglyRejectedAdminEmail = builtins.filter (e: !(adminEmailAccepted e))
            [ "" "a@example.test" "ops+ferrum@example.co.uk" ];
          wronglyAcceptedAdminEmail = builtins.filter adminEmailAccepted
            [
              ''a"@example.test''
              "a@example.test\"\n  attacker:\n    groups:\n      - admins"
            ];

          # SEC-08. The /authelia subrequest must tell Authelia who is
          # knocking. It writes its own proxy_pass inside extraConfig, so
          # nixpkgs' recommendedProxySettings generates no
          # proxy_set_header include for it, and nginx replaces rather than
          # extends an inherited set -- so the headers are absent unless
          # this block sets them itself, and Authelia attributes every
          # attempt on every vhost to nginx's own loopback address.
          #
          # Both vhost shapes, because they are built by different code:
          # mkVhost for a catalog app, the hand-built daemonVhost for the
          # control plane. Fixing one and not the other is the shape of
          # SEC-02 itself.
          autheliaSubrequests = [
            { where = "the daemon vhost"; conf = locOf "/authelia"; }
            {
              where = "a catalog app vhost (sonarr.example.test)";
              conf = (vhosts."sonarr.example.test".locations."/authelia" or { }).extraConfig or "";
            }
          ];
          missingClientHeaders = lib.concatMap
            (sub: map (h: "${sub.where} sets no ${h}")
              (builtins.filter (h: !(lib.hasInfix h sub.conf))
                [ "proxy_set_header X-Forwarded-For" "proxy_set_header X-Real-IP" ]))
            autheliaSubrequests;
          # Anti-vacuity: an /authelia block that does not exist has no
          # missing headers either, and would pass the clause above in
          # silence.
          autheliaSubrequestsScanned = builtins.filter
            (sub: !(lib.hasInfix "proxy_pass http://127.0.0.1:9091/api/verify" sub.conf))
            autheliaSubrequests;

          # SEC-01/SEC-02. The same injection class as
          # wronglyAcceptedInjection above, in the two settings-writable
          # values that reach an nginx directive and were NOT covered when
          # listenAddress, baseDomain and the two subdomains were fixed.
          #
          # These need probes of their own rather than another entry in the
          # list above, because the refusal is a different mechanism:
          # listenAddress is refused by an ASSERTION carrying a message, so
          # loopbackFailuresFor can scope itself to that message, while
          # these are refused by their option TYPE and so simply fail to
          # evaluate. "It threw" is therefore the whole signal, which makes
          # the accepted-controls below non-negotiable: a probe that throws
          # for some unrelated reason reads as a refusal, and every fixture
          # here would then pass with the new types deleted.
          #
          # Both probes read the GENERATED nginx config rather than the
          # option, for the same reason authModelEnforced does: the option
          # value is not what nginx parses.

          # ferrum.proxy.trustedNetworks[] -> `allow ${net};` in
          # modules/proxy/nginx.nix's lanRestriction. Returns the "/"
          # location's rendered extraConfig, or null if the value was
          # refused at evaluation.
          lanRestrictionFor = net:
            let
              probe = builtins.tryEval (
                let
                  conf = (mkProxyHost {
                    apps.sonarr = { enable = true; exposure = "lan"; };
                    trustedNetworks = [ net ];
                  }).config.services.nginx.virtualHosts."sonarr.example.test"
                    .locations."/".extraConfig;
                in
                builtins.deepSeq conf conf);
            in
            if probe.success then probe.value else null;

          # The control, and the reason none of this is a scan over nothing:
          # the SHIPPED default has to keep rendering, as the directive it
          # is supposed to render. A type that refused RFC1918 space would
          # take every lan-exposure app on every existing host offline,
          # which is a worse outage than the finding.
          defaultTrustedNetworks = published.config.ferrum.proxy.trustedNetworks;
          brokenTrustedNetwork = builtins.filter
            (net:
              let c = lanRestrictionFor net; in
              c == null || !(lib.hasInfix "allow ${net};" c))
            defaultTrustedNetworks;

          # The attack. `}` closes `location /` before nginx ever reads the
          # `deny all;` and the `auth_request` block that lanRestriction is
          # concatenated in FRONT of, so the injected location serves the
          # app with forward-auth absent entirely. Proved end to end against
          # a real nginx with an Authelia stub that always returns 401: the
          # injected arm answered 200 with the application's body while the
          # benign control answered 403.
          wronglyAcceptedTrustedNetwork = builtins.filter
            (net: lanRestrictionFor net != null)
            [
              "127.0.0.1; } location /anything { proxy_pass http://127.0.0.1:8989; #"
              # The newline spelling of the same attack: `;` is not nginx's
              # only directive separator.
              "127.0.0.1;\n}\nlocation /anything { proxy_pass http://127.0.0.1:8989;"
            ];

          # ferrum.apps.<id>.auth.bypassPaths[] -> `location ${path} {` in
          # modules/proxy/nginx.nix, AND `resources = [ "^${path}.*$" ]` --
          # an Authelia REGEX -- in modules/proxy/authelia.nix. Returns the
          # generated location names, or null if refused at evaluation.
          bypassLocationsFor = path:
            let
              probe = builtins.tryEval (
                let
                  names = builtins.attrNames
                    (mkProxyHost {
                      apps.sonarr = {
                        enable = true;
                        exposure = "public";
                        auth.bypassPaths = [ path ];
                      };
                    }).config.services.nginx.virtualHosts."sonarr.example.test".locations;
                in
                builtins.deepSeq names names);
            in
            if probe.success then probe.value else null;

          # The control, derived from the catalog rather than restated, so
          # an app added later with a path this type refuses fails HERE
          # rather than on the operator's host. This is the clause that
          # matters most: `/api` behind forward-auth takes out Prowlarr ->
          # *arr, every native client, and ferrum's own reconciler, so a
          # type that over-tightens disables the self-setup SSO exists to
          # protect. That has been a real bug in this repo before.
          catalogBypassPaths = lib.unique
            (lib.concatMap (a: a.authBypassPaths or [ ]) (builtins.attrValues catalog));
          brokenCatalogBypassPath = builtins.filter
            (path:
              let n = bypassLocationsFor path; in
              n == null || !(builtins.elem path n))
            catalogBypassPaths;

          # The attack, and it is worse than SEC-01's: a bypass path is a
          # LOCATION NAME, so the injected block is a sibling of "/" rather
          # than something spliced into it, and it deletes auth_request from
          # a catalog app outright.
          wronglyAcceptedBypassPath = builtins.filter
            (path: bypassLocationsFor path != null)
            [
              "/api { proxy_pass http://127.0.0.1:8989; } location /anything"
              "/api;\n}\nlocation /anything { proxy_pass http://127.0.0.1:8989;"
              # Not an nginx injection but an Authelia one: authelia.nix
              # wraps this value in `^${path}.*$`, so a regex metacharacter
              # widens the bypass RULE even where the nginx location is
              # harmless. `.*` makes the bypass match every resource on the
              # vhost, which is the whole app unauthenticated.
              "/.*"
            ];


          # H-03. The host that publishes the control plane with no gate in
          # front of it -- proxy on, a real baseDomain, and auth.enable left
          # at the FALSE it defaults to, against ferrum.daemon.enable's
          # default of true. That combination is what a host reaches by
          # doing nothing, and until now nothing in either language said a
          # word about it: the vhost, the Authelia-less auth_request, and a
          # real Let's Encrypt certificate all appeared, and the apply
          # reported success.
          #
          # Same builtins.tryEval + single-line message scoping as
          # loopbackFailuresFor above, and scoped for the identical
          # non-negotiable reason: this fixture carries other failing
          # assertions of its own (the example host's placeholder secrets
          # have no *-apikey-raw.sops counterparts), so an unscoped probe
          # would report it "rejected" and would pass just as happily with
          # the new assertion deleted. The phrase matched is kept whole on
          # ONE line of nginx.nix's message, because an infix spanning a
          # multi-line Nix string's line break never matches.
          authOffFailures =
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "so there is no login in front of it" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion)
                      (mkProxyHost { auth = false; }).config.assertions)));
            in
            if probe.success then probe.value else [ "evaluation threw" ];
          # ...and the other direction, which is what stops the assertion
          # being written as `true` and passing. The ordinary published host
          # HAS auth on, and must not be stopped.
          authOnFailures =
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "so there is no login in front of it" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) published.config.assertions)));
            in
            if probe.success then probe.value else [ "evaluation threw" ];
          # And the third: auth off is only a problem for a host that
          # PUBLISHES. A daemon reached over an SSH tunnel on a box with no
          # domain is the safest configuration ferrum offers, and refusing
          # to build it would make this assertion a bug rather than a guard.
          authOffUnpublishedFailures =
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "so there is no login in front of it" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion)
                      (mkProxyHost { auth = false; baseDomain = ""; }).config.assertions)));
            in
            if probe.success then probe.value else [ "evaluation threw" ];

          # A2/D1: the Authelia rule. Without it, default_policy = "deny"
          # applies and the auth_request wiring asserted above denies every
          # request forever -- the dashboard would not be weakly protected, it
          # would be unopenable. A rule whose policy is "bypass" is the
          # opposite failure and is rejected just as hard.
          rules = published.config.services.authelia.instances.main.settings.access_control.rules;
          daemonRules = builtins.filter (r: r.domain or "" == daemonName) rules;

          # A6/D6: the dashboard-only host. Every catalog app is deliberately
          # "local", so publicApps == { } and every pre-R13 ACME branch was
          # false. This is the configuration that silently got no certificate.
          dashboardOnly = mkProxyHost {
            apps = { plex = { enable = true; exposure = "local"; }; };
            secrets = { "acme-dns" = { }; };
          };
          dashboardCerts = dashboardOnly.config.security.acme.certs;
          daemonCert = dashboardCerts.${daemonName} or null;
          expectedDnsProvider = dashboardOnly.config.ferrum.proxy.acme.dnsProvider;
          dashboardPublicApps = lib.filterAttrs
            (_: app: app.enable && app.exposure == "public")
            dashboardOnly.config.ferrum.apps;

          problems =
            lib.optional (daemonV == null)
              "no vhost generated at ${daemonName}: ferrum.daemon.subdomain is still decorative (A1)"
            # A1: it must reach the daemon where the daemon actually listens,
            # not a hardcoded 127.0.0.1 that a changed listenAddress breaks.
            ++ lib.optional
              (daemonV != null
                && (daemonV.locations."/".proxyPass or "") != "http://${daemonAddr}:${toString daemonPort}")
              "the daemon vhost's / does not proxy to ferrum.daemon.listenAddress:port (A1/A5)"
            # A2: gated exactly like a catalog app, on BOTH locations. /api/
            # is the one a compromised sibling would aim at.
            ++ lib.optional (!(hasIn "auth_request /authelia" rootLoc))
              "the daemon vhost's / is NOT behind forward-auth: the control plane is published unauthenticated (A2)"
            ++ lib.optional (!(hasIn "auth_request /authelia" apiLoc))
              "the daemon vhost's /api/ is NOT behind forward-auth (A2)"
            ++ lib.optional (daemonV != null && (daemonV.locations."/authelia" or null) == null)
              "the daemon vhost has no /authelia subrequest location, so auth_request has nothing to call (A2)"
            # D8, leg 1 and 2. jobs.rs's SSE stream outlives the 60s
            # proxy_read_timeout recommendedProxySettings supplies, and gets
            # batched by the buffering it also leaves on.
            ++ lib.optional (!(hasIn "proxy_buffering off" apiLoc))
              "the daemon vhost's /api/ leaves proxy_buffering on, so the job SSE stream is batched (D8)"
            ++ lib.optional (!(hasIn "proxy_read_timeout 300s" apiLoc))
              "the daemon vhost's /api/ does not raise proxy_read_timeout above apply.healthCheckTimeoutSec, so a long apply is cut off (D8)"
            # D8, leg 3. A browser navigation should redirect to Authelia; an
            # XHR must not, or the SPA cannot tell an expired session from a
            # dead daemon.
            # R5/SEC-M02 moved the target. The dashboard now has an Authelia
            # cookie scope of its own, and Authelia refuses to issue a cookie
            # for a scope from a portal outside it -- so a redirect to
            # auth.example.test lands the operator on a portal that
            # authenticates them for the APPS and sends them back to a
            # dashboard that is still unauthenticated. An infinite redirect
            # loop on the control plane, reported by nothing.
            #
            # Asserted on the full `auth.ferrum.example.test` rather than a
            # substring of it, because "auth.example.test" IS a substring of
            # "auth.ferrum.example.test" in neither direction -- but
            # `https://auth.` is in both, and a laxer match here would pass on
            # exactly the regression this names.
            ++ lib.optional
              (!(hasIn "error_page 401 =302 https://auth.${daemonName}" rootLoc))
              "the daemon vhost's / does not redirect an unauthenticated navigation to the control plane's own Authelia portal (A2/SEC-M02). It must be auth.${daemonName}: a redirect to auth.example.test authenticates the caller for the apps' cookie scope, which is not the dashboard's, so the browser comes back with no cookie Authelia will accept here and loops"
            # And the portal it redirects to must exist, on a real
            # certificate, and must NOT be behind forward-auth itself -- a
            # login page gated by the thing it exists to log you into is the
            # same unopenable-dashboard failure the Authelia rule above
            # prevents, one hostname over.
            ++ lib.optional (controlPortalV == null)
              "the daemon vhost redirects to auth.${daemonName} and no vhost is generated for it: the control plane's login page is a name with nothing behind it (SEC-M02)"
            ++ lib.optional
              (controlPortalV != null
                && (controlPortalV.locations."/".proxyPass or "") != "http://127.0.0.1:9091")
              "the control plane's Authelia portal does not proxy to Authelia (SEC-M02)"
            ++ lib.optional
              (controlPortalV != null
                && hasIn "auth_request" ((controlPortalV.locations."/".extraConfig or "")
                  + (controlPortalV.extraConfig or "")))
              "the control plane's Authelia portal is itself behind forward-auth, so logging in requires already being logged in (SEC-M02)"
            ++ lib.optional
              (controlPortalV != null && (controlPortalV.useACMEHost or null) != "auth.${daemonName}")
              "the control plane's Authelia portal has no real certificate of its own: the very first redirect out of the dashboard lands on a certificate the browser refuses, which is SSO unusable on the configuration R5 exists to make work (SEC-M02)"
            ++ lib.optional (hasIn "=302" apiLoc)
              "the daemon vhost's /api/ redirects a 401 instead of returning it, so the SPA sees an opaque cross-origin redirect (D8)"
            ++ lib.optional (!(hasIn "error_page 401 = @ferrum_api_401" apiLoc))
              "the daemon vhost's /api/ does not override the 401 redirect with a plain 401 (D8)"
            # M-02, the edge half. The application-side lockout is ferrumd's.
            ++ lib.optional (!(hasIn "limit_req zone=ferrum_login" loginLoc))
              "the daemon vhost puts no limit_req on /api/login, so nothing at the edge slows a password guesser -- and ferrumd's own lockout is keyed on the submitted USERNAME, which means an attacker can hold the sole admin account locked out indefinitely rather than being locked out themselves (M-02)"
            ++ lib.optional (!(hasIn "limit_req_zone $binary_remote_addr zone=ferrum_login" commonHttp))
              "limit_req zone=ferrum_login is referenced but the zone is never declared in http context, so nginx refuses the WHOLE config file at nginx.service start -- every vhost on the host down after a successful apply (M-02)"
            # The trade this location exists to make must not cost the one
            # it was already making. A rate limiter that dropped
            # auth_request would have opened a hole while narrowing one.
            ++ lib.optional (daemonV != null && (daemonV.locations."/api/login" or null) != null
                && !(hasIn "auth_request /authelia" loginLoc))
              "the daemon vhost's /api/login is NOT behind forward-auth, though /api/ is -- a longer prefix wins in nginx, so adding this location for its rate limit has published the login endpoint unauthenticated (A2/M-02)"
            ++ lib.optional (daemonV != null && (daemonV.locations."/api/login" or null) != null
                && !(hasIn "error_page 401 = @ferrum_api_401" loginLoc))
              "the daemon vhost's /api/login does not override the 401 redirect, so the SPA's own login request comes back as an opaque cross-origin redirect instead of a readable 401 (D8/M-02)"
            # ROAD-TO-PUBLIC item 22, all four legs.
            #
            # The health endpoints are the first locations on this vhost that
            # Authelia deliberately does not gate, which makes "a location
            # with no auth_request" stop being self-evidently a bug. These
            # assertions are what keeps it from becoming a place to hide one:
            # the exemption is a NAMED LIST, not a shape.
            ++ lib.optional (daemonV != null
                && !(builtins.all (loc: (daemonV.locations.${loc} or null) != null) healthLocationNames))
              "the daemon vhost does not publish ${lib.concatStringsSep " and " healthLocationNames}, so an external monitor has no way to ask this host whether it is well -- which was the whole of ROAD-TO-PUBLIC item 22"
            ++ lib.optional (daemonV != null
                && builtins.any (loc: hasIn "auth_request" (locOf loc)) healthLocationNames)
              "a health endpoint is behind forward-auth. That does not secure it, it breaks it: a monitor follows the 302 to the Authelia portal, gets the portal's own HTML with a 200, and reports this box healthy forever -- including while ferrumd is down (item 22)"
            ++ lib.optional (daemonV != null
                && !(builtins.all (loc: hasIn "limit_req zone=ferrum_health" (locOf loc)) healthLocationNames))
              "a health endpoint has no rate limit, though it is unauthenticated and every readiness probe does real work (a SQLite query, two JSON parses, a D-Bus connect) -- so anyone on the internet can use it to amplify load against the daemon (item 22)"
            ++ lib.optional (!(hasIn "limit_req_zone $binary_remote_addr zone=ferrum_health" commonHttp))
              "limit_req zone=ferrum_health is referenced but the zone is never declared in http context, so nginx refuses the WHOLE config file at nginx.service start -- every vhost on the host down after a successful apply (item 22)"
            ++ lib.optional (unexpectedlyUnauthed != [ ])
              "these daemon-vhost locations reach ferrumd with NO forward-auth and are not on the exemption list: ${lib.concatStringsSep ", " unexpectedlyUnauthed}. A longer or exact-match location wins in nginx, so adding one without auth_request publishes whatever it proxies to, unauthenticated. If it is deliberate, add it to authExemptLocations here and say why (A2/item 22)"
            # H-03, all three directions.
            ++ lib.optional (authOffFailures == [ ])
              "a host with ferrum.proxy.enable, a real ferrum.proxy.baseDomain and ferrum.auth.enable = false evaluates cleanly: the control plane is published on a real ACME certificate with auth_request absent entirely, and nothing tells the operator. ferrum.auth.enable is an mkEnableOption (default FALSE) while ferrum.daemon.enable defaults to TRUE, so this is the configuration a host reaches by doing nothing (H-03)"
            ++ lib.optional (authOnFailures != [ ])
              "the ordinary published host -- auth ON -- is refused by the auth-off assertion, so that assertion is not reading ferrum.auth.enable at all (H-03)"
            ++ lib.optional (authOffUnpublishedFailures != [ ])
              "a host with auth off and NO baseDomain is refused, but that host publishes nothing: the daemon is reachable only over the SSH tunnel ferrum.daemon.listenAddress exists for, which is the safest configuration ferrum offers. The assertion is keyed on auth alone instead of on publication (H-03)"
            # H-02/M-04: the response headers. Asserted on the server-level
            # block rather than on the locations because that is where they
            # are set, and on ALL FOUR at that level because of the
            # replacement rule described where daemonServer is bound.
            ++ lib.optional (!(hasIn "X-Frame-Options \"DENY\"" daemonServer))
              "the daemon vhost sets no X-Frame-Options: a compromised sibling app on the same baseDomain is SAME-SITE, so the browser attaches ferrumd's session cookie to a framed ferrum.<baseDomain>, the real dashboard renders authenticated, and it supplies the CSRF token itself -- one framed click reaches POST /api/jobs, which is apply and rollback (H-02)"
            ++ lib.optional (!(hasIn "frame-ancestors 'none'" daemonServer))
              "the daemon vhost sets no Content-Security-Policy frame-ancestors: X-Frame-Options is the legacy spelling and this is the standard one, and a browser that honours only the latter frames the control plane (H-02)"
            ++ lib.optional (!(hasIn "X-Content-Type-Options \"nosniff\"" commonHttp))
              "services.nginx.commonHttpConfig sets no X-Content-Type-Options, so no vhost on this host sends nosniff (M-04)"
            ++ lib.optional (!(hasIn "Referrer-Policy" commonHttp))
              "services.nginx.commonHttpConfig sets no Referrer-Policy, so an outbound link leaks the path it was clicked from -- a *arr URL carries the library layout in it (M-04)"
            # ...and the two that make the pair above reach the daemon at
            # all. This is the half a reviewer reading either file alone
            # would call redundant, and it is the half that actually breaks:
            # the daemon vhost sets add_header at server level, so unless it
            # REPEATS the http-level pair, the most sensitive vhost on the
            # host is the one vhost without nosniff.
            ++ lib.optional
              (!(hasIn "X-Content-Type-Options \"nosniff\"" daemonServer)
                || !(hasIn "Referrer-Policy" daemonServer))
              "the daemon vhost sets add_header at server level but does not repeat the http-level pair, and nginx's add_header REPLACES the inherited set rather than extending it -- so the control plane is the one vhost on this host that sends no nosniff and no Referrer-Policy (M-04)"
            ++ lib.optional (!(hasIn "always" daemonServer))
              "the daemon vhost's security headers are not marked `always`, so nginx omits them from exactly the responses that matter: a bare add_header skips 401 and 5xx (H-02/M-04)"
            ++ map (loc: "the daemon vhost's location \"${loc}\" sets its own add_header, which REPLACES the server-level set rather than extending it -- that location now serves the control plane with whichever of the four security headers it did not re-list (H-02/M-04)")
              locationsWithAddHeader
            # A7, both halves -- each preceded by the guard that keeps its
            # absence proof from being a scan over nothing.
            ++ lib.optional (proxyOffFerrumVhosts != [ ])
              "ferrum.proxy.enable = false still generated nginx vhosts (${lib.concatStringsSep ", " proxyOffFerrumVhosts}): the proxy module is no longer off wholesale, so every absence claimed of this fixture has to be rebuilt (A7)"
            ++ lib.optional (!scannedARealAppRule)
              "the proxy-off fixture carries no Authelia rule for sonarr.example.test, so its rule list is not the generated one and finding no daemon rule in it would prove nothing (A7)"
            ++ lib.optional (proxyOffDaemonRules != [ ])
              "with ferrum.proxy.enable = false, Authelia still carries an access_control rule for ${daemonName} -- authorization for a vhost that does not exist (A7)"
            ++ lib.optional (!scannedTheCatchAll)
              "the empty-baseDomain fixture generated no _ferrum_unmatched vhost, so modules/proxy/nginx.nix did not run on it and the absence below is vacuous (A7)"
            ++ lib.optional (absentWhenNoDomain ? "${daemonSub}.")
              "a daemon vhost exists with an empty baseDomain, on a hostname that cannot resolve (A7)"
            # daemonPublished's first term, which nothing else varies.
            ++ lib.optional (!scannedASiblingVhost)
              "the daemon.enable = false fixture generated no sonarr.example.test vhost, so its proxy config is not the generated one and the absences below are vacuous"
            ++ lib.optional (daemonOffVhosts ? ${daemonName})
              "a daemon vhost exists with ferrum.daemon.enable = false, advertising a dashboard this host does not run"
            ++ lib.optional
              (builtins.any (r: r.domain or "" == daemonName) daemonOffRules)
              "Authelia carries an access_control rule for ${daemonName} with ferrum.daemon.enable = false"
            ++ lib.optional
              ((daemonOff.config.security.acme.certs.${daemonName} or null) != null)
              "an ACME certificate is issued for ${daemonName} with ferrum.daemon.enable = false -- a real Let's Encrypt order for a name nothing serves"
            # A1/A5/D7 against options that have actually MOVED. The
            # expected strings are literals on purpose: the assertions above
            # derive theirs from the same host they are checking, so they
            # cannot tell a module reading the option from one hardcoding
            # the default.
            ++ lib.optional (movedV == null)
              "ferrum.daemon.subdomain = \"${movedSub}\" produced no vhost at ${movedName}: the daemon's hostname is hardcoded, not read (D7)"
            ++ lib.optional (movedVhosts ? "ferrum.example.test")
              "moving ferrum.daemon.subdomain left a vhost behind at ferrum.example.test (D7)"
            ++ lib.optional
              (movedV != null
                && (movedV.locations."/".proxyPass or "") != "http://${movedAddress}:${toString movedPort}")
              "with ferrum.daemon.listenAddress = ${movedAddress} and port = ${toString movedPort}, the vhost still proxies elsewhere -- nginx reaches a daemon that is not listening there (A1/A5)"
            ++ lib.optional
              (!(builtins.any (r: r.domain or "" == movedName) movedRules))
              "Authelia has no access_control rule for ${movedName}, so a moved dashboard is unopenable under default_policy = deny (D1/D7)"
            ++ lib.optional (v6Pass != v6Expected)
              "with ferrum.daemon.listenAddress = \"::1\" the daemon vhost proxies to \"${v6Pass}\", not \"${v6Expected}\" -- nginx splits a proxy_pass authority at its LAST colon, so an unbracketed IPv6 literal is read as port \"1:${toString daemonPort}\" and the WHOLE config file is refused, taking every other vhost down with it (A1/A5)"
            # A5, enforced.
            ++ map (a: "ferrum.daemon.listenAddress = \"${a}\" is refused at evaluation, and it is a loopback address -- the SSH-tunnel recovery route A5 protects is broken (A5)")
              wronglyRejected
            ++ map (a: "ferrum.daemon.listenAddress = \"${a}\" evaluates cleanly, so ferrumd may be told to bind an interface the world can reach with nginx and Authelia bypassed entirely (A5)")
              wronglyAccepted
            ++ map (a: "ferrum.daemon.listenAddress = \"${a}\" evaluates cleanly, and it is not an address at all -- it is an nginx DIRECTIVE, smuggled through an option the settings API can write and interpolated unquoted into proxy_pass by modules/proxy/nginx.nix. The rendered config parses (EXIT 0, proved against a real nginx), so nothing downstream refuses it: whatever the payload says, the control plane's own vhost now says too (A5)")
              wronglyAcceptedInjection
            ++ map (a: "ferrum.daemon.listenAddress = \"${a}\" evaluates cleanly, and it is a NAME rather than a literal -- nginx resolves it at config load and load-balances across every address it yields, while ferrumd's TcpListener::bind takes only the first, so roughly half the dashboard's requests hit a port nothing is listening on. An intermittent 502 with no cause in either program's log (A5)")
              wronglyAcceptedNames
            ++ map (a: "ferrum.daemon.listenAddress = \"${a}\" evaluates cleanly, and it is an ALREADY-BRACKETED IPv6 literal -- modules/proxy/nginx.nix brackets any address containing a colon unconditionally, with no \"already bracketed?\" branch, because this refusal is what guarantees one never arrives. Accepting it renders `proxy_pass http://[[::1]]:7788`, which nginx rejects as an invalid host, refusing the WHOLE config file: every vhost on the host down at nginx.service start, after an apply that reported success (A5)")
              wronglyAcceptedBracketed
            # SEC-01. The allow-list is concatenated in FRONT of the gate,
            # so this is not "a malformed allow directive" -- it is the
            # deletion of `deny all` and `auth_request` from the location
            # they were guarding.
            ++ map (net: "ferrum.proxy.trustedNetworks contains \"${net}\", and it is not a network -- it is an nginx DIRECTIVE, smuggled through an option modules/lib/settings-schema.json lets `PUT /api/settings` write and interpolated unquoted into `allow ${net};` by modules/proxy/nginx.nix. modules/proxy/nginx.nix concatenates lanRestriction BEFORE the auth_request block, so a `}` in this value closes `location /` and the app is served with `deny all` and forward-auth both absent. Proved against a real nginx with an always-401 Authelia stub: 200 with the application body, where the benign control answered 403 (SEC-01)")
              wronglyAcceptedTrustedNetwork
            ++ map (net: "ferrum.proxy.trustedNetworks default entry \"${net}\" no longer renders as `allow ${net};` in the lan vhost. Either the option type now refuses RFC1918 space -- which takes every lan-exposure app on every existing host offline -- or lanRestriction stopped emitting it, in which case every injection fixture above is a scan over a config that is not generated (SEC-01)")
              brokenTrustedNetwork
            # SEC-02. Worse than SEC-01, because a bypass path is a location
            # NAME: the injected block is a sibling of "/" rather than
            # something spliced into it.
            ++ map (path: "ferrum.apps.sonarr.auth.bypassPaths contains \"${path}\", and it is not a path -- modules/proxy/nginx.nix interpolates it unquoted as `location ${path} {` and modules/proxy/authelia.nix wraps it in the REGEX `^${path}.*$`. The `apps` node in modules/lib/settings-schema.json defers on per-app shape, so `PUT /api/settings` composes this value. An injected location deletes auth_request from a catalog app; an injected regex metacharacter widens the Authelia bypass rule to resources the app never meant to exempt (SEC-02)")
              wronglyAcceptedBypassPath
            ++ map (path: "the catalog declares authBypassPaths = \"${path}\" and it no longer generates a location of that name. A bypass-path type that over-tightens is not a safe failure: `/api` behind forward-auth takes out Prowlarr -> Sonarr/Radarr, every native client, and ferrum's OWN reconciler -- enabling SSO would again disable the self-setup SSO exists to protect (SEC-02)")
              brokenCatalogBypassPath
            # SEC-08.
            ++ map (sub: "${sub.where} generated no /authelia subrequest at all, so the header assertions below are a scan over nothing (SEC-08)")
              autheliaSubrequestsScanned
            ++ map (m: "${m}. The /authelia block writes its own proxy_pass inside extraConfig, so nixpkgs' recommendedProxySettings adds no proxy_set_header include to it, and nginx REPLACES an inherited set rather than extending it. Authelia therefore sees every verification request as coming from nginx's own loopback connection: its log attributes every attempt to 127.0.0.1, and its regulation counts one global bucket instead of one per source, so an attacker anywhere is indistinguishable from the operator at home (SEC-08)")
              missingClientHeaders
            # The sweep's finding.
            ++ map (e: "ferrum.proxy.acme.email = \"${e}\" evaluates cleanly, and it is not an address -- nixpkgs' security.acme interpolates it raw inside a single-quoted shell word in the renewal script it generates (`find accounts -name '<email>.key'`), so a quote here closes that word and the rest runs as a COMMAND in acme-<cert>.service, as the acme user, on every renewal. lego's own arguments are escaped; this second use of the same value is not. Settings-API writable")
              wronglyAcceptedEmail
            ++ map (e: "ferrum.proxy.acme.email = \"${e}\" is refused at evaluation, and it is a legitimate contact address. The empty string in particular is the option's DEFAULT and the sentinel modules/proxy/acme.nix tests to produce its own operator-facing \"Let's Encrypt requires a real contact address\" message -- refusing it here would replace that explanation with a pattern mismatch, and would break every host that needs no real certificate")
              wronglyRejectedEmail
            ++ map (e: "ferrum.auth.adminEmail = \"${e}\" evaluates cleanly, and crates/ferrum-apply/src/secrets.rs writes Authelia's users_database.yml with format!, interpolating it inside `email: \"{admin_email}\"`. A quote and a newline here write arbitrary YAML into the file that decides who may log in -- a second admins member, or a replacement password hash. Settings-API writable")
              wronglyAcceptedAdminEmail
            ++ map (e: "ferrum.auth.adminEmail = \"${e}\" is refused at evaluation, and it is a legitimate address. The empty string is the option's default and the sentinel modules/proxy/authelia.nix tests to produce its own \"the generated first user needs a real email address\" message")
              wronglyRejectedAdminEmail
            # A2/D1.
            ++ lib.optional (daemonRules == [ ])
              "Authelia has no access_control rule for ${daemonName}, so default_policy = deny makes the dashboard unopenable (D1)"
            ++ lib.optional (builtins.any (r: r.policy or "" == "bypass") daemonRules)
              "Authelia's rule for ${daemonName} is policy = bypass, so the control plane is published unauthenticated (A2)"
            # ...and every OTHER legal value of the enum is wrong too, which
            # is why this asserts the value rather than excluding one. A rule
            # of "existed, and was not bypass" passed cleanly with policy =
            # "deny" -- a documented member of the enum at
            # modules/proxy/authelia.nix, and exactly the "wired vhost,
            # denied for everyone" non-functional ship the rule exists to
            # prevent, since access_control.default_policy is already "deny".
            # "two_factor" passed too, and the daemon is deliberately outside
            # the catalog loop above that protects real apps from a
            # two_factor lockout, so nothing else would have caught it
            # either.
            ++ map (r: "Authelia's rule for ${daemonName} has policy = \"${r.policy or "<unset>"}\", not \"one_factor\": the control plane must be gated exactly like a catalog app (A2/D1)")
              (builtins.filter (r: (r.policy or "") != "one_factor") daemonRules)
            # A6/D6.
            ++ lib.optional (dashboardPublicApps != { })
              "the dashboard-only fixture has a public app, so it no longer tests the publicApps == {} path"
            # Asserting the KEY EXISTS is not enough here, and finding that
            # out is the reason this check is mutation-tested. nginx's own
            # module auto-creates a security.acme.certs stub for any vhost
            # naming a useACMEHost, so with acme.nix's daemon entry deleted
            # the key is still present -- with dnsProvider = null and
            # environmentFile = null, i.e. a certificate that would try
            # HTTP-01 with no credential and never issue. An existence check
            # passed that mutation cleanly. A6 asks for the certificate to
            # come through the SAME ACME path as every other vhost, so that
            # is what is checked: ferrum's DNS-01 provider, and the
            # Cloudflare token lego actually needs.
            ++ lib.optional (daemonCert == null)
              "with no public catalog app, the dashboard gets no ACME certificate entry at all (A6/D6)"
            ++ lib.optional
              (daemonCert != null && (daemonCert.dnsProvider or null) != expectedDnsProvider)
              "the dashboard's certificate is not on ferrum's DNS-01 path -- it is nginx's bare useACMEHost stub, which would never issue (A6/D6)"
            ++ lib.optional
              (daemonCert != null && (daemonCert.environmentFile or null) == null)
              "the dashboard's certificate has no environmentFile, so lego gets no Cloudflare credential (A6/D6)";
        in
        {
          ok = problems == [ ];
          message = "the generated config does not publish the control plane as R13 requires";
          inherit problems;
          # Diagnostics, printed by mkAssertionCheck on failure: the cert
          # findings above are otherwise very hard to read from the message
          # alone, because the failure is a present-but-inert entry rather
          # than a missing one.
          dashboardCertNames = builtins.attrNames dashboardCerts;
          daemonCertDnsProvider = if daemonCert == null then "<no entry>" else daemonCert.dnsProvider;
        };

      # SEC-M02, closed. The dashboard's Authelia cookie is not the apps'.
      #
      # Until this check existed, modules/proxy/authelia.nix set
      # `session.domain = <baseDomain>`, so ONE cookie covered every
      # published name on the host -- including ferrum.<baseDomain>, the
      # control plane. Several catalog apps deliberately carry
      # unauthenticated bypass locations, so a cookie obtained in one app's
      # context was presentable at the control plane's edge gate. That was
      # accepted as a Medium only because ferrumd's own
      # `__Host-ferrumd_session` sat underneath it as a compensating
      # control, and that control is exactly what R5 spends.
      #
      # Authelia 4.38+ fixes it with a multi-domain `session.cookies` list.
      # Three properties of that list are load-bearing and NONE of them is
      # obvious from the configuration, which is why this check runs
      # Authelia's own validator rather than reading the attrset:
      #
      #   1. `authelia_url` must sit INSIDE its own entry's cookie scope.
      #      Measured against authelia 4.39.19: a `ferrum.example.test`
      #      entry pointing at `https://auth.example.test` is refused with
      #      "option 'authelia_url' does not share a cookie scope with
      #      domain 'ferrum.example.test'". That single rule is why the
      #      control plane needs a portal hostname of its own
      #      (auth.ferrum.<baseDomain>) rather than reusing the apps' one,
      #      and therefore why it needs its own certificate and its own DNS
      #      record. A design that skipped them would be refused by Authelia
      #      at startup, on a host whose apply reported success.
      #
      #   2. The MORE SPECIFIC domain must come FIRST. Measured: listing
      #      example.test before ferrum.example.test is refused with
      #      "option 'domain' shares the same cookie domain scope as another
      #      configured session domain", while the reverse order validates.
      #      Nix attribute/list order is otherwise invisible, so nothing
      #      else in this repository would have noticed an edit that
      #      reordered them.
      #
      #   3. The two entries must have DIFFERENT cookie NAMES, and Authelia
      #      does NOT enforce this -- measured: two entries sharing the name
      #      `authelia_session` validate cleanly. They are both sent to
      #      ferrum.<baseDomain> by the browser (one by domain match, one by
      #      subdomain match) under one name, and RFC 6265 leaves it
      #      unspecified which a server reads. That is the SEC-M02 ambiguity
      #      reintroduced through the fix for it, so ferrum asserts the
      #      distinctness Authelia is content to leave open.
      #
      # The validator is run on the config file the REAL unit names, with
      # the real binary the REAL unit names -- the same discipline
      # nginxConfigParses uses, and for the same reason: an attrset that
      # looks right is one layer short of the thing that actually refuses to
      # start.
      autheliaCookieScope =
        let
          mkCookieHost = { publish }: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = {
                enable = true;
                baseDomain = "example.test";
                acme.email = "a@example.test";
              };
              auth = { enable = true; adminEmail = "a@example.test"; };
              apps.sonarr.enable = true;
              daemon = { inherit publish; };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          # The ordinary host: dashboard published, so the control plane
          # needs a cookie scope of its own.
          published = (mkCookieHost { publish = true; }).config;
          # The control. ferrum.daemon.publish = false is the installer's
          # stage-1 shape and the tunnel-only host: there is no
          # ferrum.<baseDomain> vhost, so a second cookie scope would be an
          # entry for a name nothing serves. It also proves the published
          # fixture's extra entry comes from publication rather than from
          # this check simply always finding two.
          unpublished = (mkCookieHost { publish = false; }).config;
          unitOf = cfg: cfg.systemd.units."authelia-main.service".unit;
        in
        pkgs.runCommand "ferrum-check-authelia-cookie-scope"
          { nativeBuildInputs = [ pkgs.yq-go ]; }
          ''
            set -eu

            fail() {
              echo "authelia-cookie-scope: $1" >&2
              exit 1
            }

            # The three secrets the real unit supplies from /run/secrets.
            # Stand-ins, because this check is about the cookie list and not
            # about secret material; every one is long enough to satisfy
            # Authelia's own minimum-length rules.
            printf '%s' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > jwt.key
            printf '%s' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > session.key
            printf '%s' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc > storage.key
            export AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=$PWD/jwt.key
            export AUTHELIA_SESSION_SECRET_FILE=$PWD/session.key
            export AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=$PWD/storage.key

            # Both halves come out of the unit, so this validates the exact
            # file systemd will hand the exact binary it will exec, rather
            # than a reconstruction that could drift from either.
            read_unit() {
              unit="$1/authelia-main.service"
              execstart=$(grep -m1 '^ExecStart=' "$unit" | cut -d= -f2-)
              bin=$(printf '%s' "$execstart" | cut -d' ' -f1)
              cfg=$(printf '%s' "$execstart" | sed -n 's/.* --config \([^ ]*\).*/\1/p')
              case "$bin" in
                /nix/store/*/bin/authelia) ;;
                *) fail "authelia-main.service's ExecStart does not name an authelia binary ($bin) -- this check no longer knows what it is testing" ;;
              esac
              case "$cfg" in
                /nix/store/*) ;;
                *) fail "authelia-main.service's ExecStart passes no store config path (--config '$cfg'), so there is nothing for this check to read" ;;
              esac
            }

            # --- the published host -------------------------------------
            read_unit ${unitOf published}
            pub_bin=$bin
            pub_cfg=$cfg

            # Anti-vacuity, before any assertion about the list: a config
            # with no cookies key at all would make every `yq` query below
            # return `null`, and a comparison against `null` is not a
            # finding. This is also the assertion that fails on the
            # pre-R5 tree, where the key is `session.domain`.
            yq -e '.session | has("cookies")' "$pub_cfg" > /dev/null \
              || fail "the generated Authelia config has no session.cookies list at all, so the control plane shares one cookie with every published app (SEC-M02). Start at modules/proxy/authelia.nix."

            count=$(yq '.session.cookies | length' "$pub_cfg")
            [ "$count" = "2" ] \
              || fail "the published host's session.cookies has $count entries, expected 2 (the control plane's own scope, then the apps')"

            first_domain=$(yq -r '.session.cookies[0].domain' "$pub_cfg")
            second_domain=$(yq -r '.session.cookies[1].domain' "$pub_cfg")
            first_name=$(yq -r '.session.cookies[0].name' "$pub_cfg")
            second_name=$(yq -r '.session.cookies[1].name' "$pub_cfg")
            first_url=$(yq -r '.session.cookies[0].authelia_url' "$pub_cfg")

            # Property 2. Authelia itself refuses the other order, so this
            # assertion is belt to its braces -- but it names the control
            # plane specifically, which the validator's message does not.
            [ "$first_domain" = "ferrum.example.test" ] \
              || fail "session.cookies[0].domain is \"$first_domain\", expected the control plane's own hostname. Authelia requires the more specific scope first and refuses the reverse with \"shares the same cookie domain scope\"."
            [ "$second_domain" = "example.test" ] \
              || fail "session.cookies[1].domain is \"$second_domain\", expected the base domain the catalog apps share"

            # Property 3, the one Authelia does not check. Two cookies of
            # the same name are BOTH sent to ferrum.example.test and RFC
            # 6265 does not say which the server reads -- which is SEC-M02
            # rebuilt inside its own fix.
            [ "$first_name" != "$second_name" ] \
              || fail "both session cookies are named \"$first_name\". The browser sends both to ferrum.example.test and RFC 6265 leaves it unspecified which Authelia reads, so a cookie obtained in an app's context can still be presented at the control plane -- which is SEC-M02 itself (Authelia's own validator accepts this; only this check does not)."
            [ -n "$first_name" ] && [ "$first_name" != "null" ] \
              || fail "the control plane's cookie entry has no name, so this check compared two absences"

            # Property 1, named rather than left to the validator, because
            # the validator's message does not say what it costs: a portal
            # hostname outside the scope means the control plane needs its
            # own certificate and DNS record, and those live in two other
            # files.
            case "$first_url" in
              https://*.ferrum.example.test|https://ferrum.example.test) ;;
              *) fail "the control plane's authelia_url is \"$first_url\", which is outside the cookie scope \"ferrum.example.test\". Authelia refuses this outright; see modules/proxy/nginx.nix's control-plane portal vhost, modules/proxy/acme.nix and modules/proxy/dns.nix, which must all name the same hostname." ;;
            esac

            # --- the control: an unpublished dashboard ------------------
            read_unit ${unitOf unpublished}
            unpub_cfg=$cfg
            yq -e '.session | has("cookies")' "$unpub_cfg" > /dev/null \
              || fail "the unpublished host's config has no session.cookies list, so comparing its length against the published host's proves nothing"
            unpub_count=$(yq '.session.cookies | length' "$unpub_cfg")
            [ "$unpub_count" = "1" ] \
              || fail "ferrum.daemon.publish = false produced $unpub_count cookie scopes, expected 1. Nothing serves ferrum.example.test on that host, so a cookie scope for it is a portal URL pointing at a name with no vhost, no certificate and no record."

            # --- and now Authelia's own opinion of both -----------------
            for cfg_path in "$pub_cfg" "$unpub_cfg"; do
              if ! "$pub_bin" validate-config --config "$cfg_path" > validate.log 2>&1; then
                cat validate.log >&2
                fail "authelia's own validator refuses the config this host generates (above). It refuses to START on it, so the apply succeeds and every published app on the box loses its login. Start at modules/proxy/authelia.nix's session.cookies."
              fi
            done

            echo ok > $out
          '';

      # R5, the join between its two halves -- and the only check here that
      # runs a REAL Authelia rather than reading what Nix told one.
      #
      # `crates/ferrumd/src/sso.rs` rests its entire security argument on a
      # claim about somebody else's software: that an `authelia_session`
      # cookie obtained in a catalog app's context is refused when presented
      # at the control plane's URL. If that claim is false, ferrumd's SSO
      # exchange hands a session to any app that can reach loopback -- and
      # every Rust test in the crate would still pass, because they drive a
      # FAKE Authelia that answers whatever they scripted.
      #
      # So the claim is measured, on the configuration this repository
      # actually generates, with the binary this repository actually ships.
      # The five rows below are the ones sso.rs's own module header states;
      # this is what keeps that header from becoming the kind of comment F1
      # was about -- a feature described in prose and absent in fact.
      #
      # Row (b) is the load-bearing one: it is precisely what R5's first half
      # buys its second, and it is why shipping the second alone would have
      # been a regression. Row (d) is its control -- the same apps cookie
      # succeeding at an app's own URL, so (b) is a finding about scope rather
      # than about a cookie that was never valid. Row (e) is revocation at the
      # source, which is what `require_session`'s re-check relies on.
      #
      # The config comes from the generated unit; only the paths a build
      # sandbox cannot provide are overridden, through Authelia's own
      # environment-variable mechanism, so `session.cookies` and
      # `access_control` reach the running process exactly as
      # modules/proxy/authelia.nix wrote them.
      autheliaAssertsOnlyItsOwnScope =
        let
          host = ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = {
                enable = true;
                baseDomain = "example.test";
                acme.email = "a@example.test";
              };
              auth = { enable = true; adminEmail = "a@example.test"; };
              apps.sonarr.enable = true;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          unit = host.config.systemd.units."authelia-main.service".unit;
          daemonHost = "${host.config.ferrum.daemon.subdomain}.example.test";
          appHost = "${host.config.ferrum.apps.sonarr.subdomain}.example.test";
        in
        pkgs.runCommand "ferrum-check-authelia-asserts-only-its-own-scope"
          { nativeBuildInputs = [ pkgs.curl ]; }
          ''
            set -eu

            fail() {
              echo "authelia-asserts-only-its-own-scope: $1" >&2
              [ -f authelia.log ] && tail -40 authelia.log >&2
              exit 1
            }

            execstart=$(grep -m1 '^ExecStart=' ${unit}/authelia-main.service | cut -d= -f2-)
            bin=$(printf '%s' "$execstart" | cut -d' ' -f1)
            cfg=$(printf '%s' "$execstart" | sed -n 's/.* --config \([^ ]*\).*/\1/p')
            case "$bin" in
              /nix/store/*/bin/authelia) ;;
              *) fail "authelia-main.service's ExecStart does not name an authelia binary ($bin)" ;;
            esac

            # Anti-vacuity, before anything is started: this check is about
            # the two cookie scopes and the two access_control rules that make
            # them observable. Without any one of them the probes below would
            # all answer 401 and the check would pass having proved nothing.
            grep -q 'ferrum_control_session' "$cfg" \
              || fail "the generated config has no control-plane session cookie, so every probe below is about one scope"
            grep -q "${daemonHost}" "$cfg" \
              || fail "the generated config never mentions ${daemonHost}, so it is not the config for this host"
            grep -q "${appHost}" "$cfg" \
              || fail "the generated config has no rule for ${appHost}, so the control probe (d) cannot distinguish a scope refusal from a policy refusal"

            printf '%s' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > jwt.key
            printf '%s' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > session.key
            printf '%s' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc > storage.key
            export AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=$PWD/jwt.key
            export AUTHELIA_SESSION_SECRET_FILE=$PWD/session.key
            export AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=$PWD/storage.key
            # The paths a build sandbox cannot provide, and ONLY those. Each
            # one is state, not policy: nothing here touches session.cookies
            # or access_control, which are what this check exists to exercise.
            export AUTHELIA_AUTHENTICATION_BACKEND_FILE_PATH=$PWD/users.yml
            export AUTHELIA_STORAGE_LOCAL_PATH=$PWD/db.sqlite3
            export AUTHELIA_NOTIFIER_FILESYSTEM_FILENAME=$PWD/notifications.txt
            export AUTHELIA_SERVER_ADDRESS=tcp://127.0.0.1:9091
            export AUTHELIA_LOG_FILE_PATH=$PWD/authelia.log
            export HOME=$PWD

            password='correct horse battery staple'
            hash=$("$bin" crypto hash generate argon2 --password "$password" --no-confirm 2>/dev/null \
                     | sed -n 's/^Digest: //p')
            [ -n "$hash" ] || fail "could not generate a password hash with authelia's own hasher"
            cat > users.yml <<YAML
            users:
              admin:
                disabled: false
                displayname: admin
                password: "$hash"
                email: a@example.test
                groups: []
            YAML
            # The heredoc above is indented to match this file; Authelia's YAML
            # parser is not, so strip the common prefix back off.
            sed -i 's/^            //' users.yml

            "$bin" --config "$cfg" &
            authelia_pid=$!
            trap 'kill $authelia_pid 2>/dev/null || true' EXIT
            up=no
            for _ in $(seq 1 60); do
              if curl -fsS -o /dev/null http://127.0.0.1:9091/api/health; then up=yes; break; fi
              sleep 1
            done
            [ "$up" = yes ] || fail "the generated config did not produce an Authelia that starts"

            login() {
              curl -sS -o "$2" -D "$2.h" -X POST http://127.0.0.1:9091/api/firstfactor \
                -H "Host: $1" -H 'Content-Type: application/json' \
                -H 'X-Forwarded-Proto: https' -H "X-Forwarded-Host: $1" \
                -d "{\"username\":\"admin\",\"password\":\"$password\",\"keepMeLoggedIn\":false}"
              sed -n 's/.*[Ss]et-[Cc]ookie: \([^;]*\);.*/\1/p' "$2.h" | head -1
            }

            control_cookie=$(login ${daemonHost} ctl.json)
            app_cookie=$(login ${appHost} app.json)
            # Only the cookie NAMES are ever printed. The values are real
            # session identifiers for this throwaway instance and there is no
            # reason to put one in a build log.
            case "$control_cookie" in
              ferrum_control_session=*) ;;
              *) fail "logging in at ${daemonHost} did not issue a ferrum_control_session cookie (got \"''${control_cookie%%=*}\"), so the two scopes are not separate" ;;
            esac
            case "$app_cookie" in
              authelia_session=*) ;;
              *) fail "logging in at ${appHost} did not issue an authelia_session cookie (got \"''${app_cookie%%=*}\")" ;;
            esac

            # Returns the HTTP status of one verify, and writes the headers to
            # $PWD/v.h so the identity can be read on a 200.
            verify() {
              if [ -n "$2" ]; then
                curl -sS -o /dev/null -D v.h -w '%{http_code}' http://127.0.0.1:9091/api/verify \
                  -H "X-Original-URL: $1" -H "Cookie: $2"
              else
                curl -sS -o /dev/null -D v.h -w '%{http_code}' http://127.0.0.1:9091/api/verify \
                  -H "X-Original-URL: $1"
              fi
            }

            # (a) the dashboard's own cookie, at the dashboard's URL.
            status=$(verify "https://${daemonHost}/" "$control_cookie")
            [ "$status" = 200 ] \
              || fail "(a) the control plane's own session cookie was refused at https://${daemonHost}/ with $status -- POST /api/sso could never succeed, so the dashboard has no single sign-on at all"
            grep -qi '^remote-user: *admin' v.h \
              || fail "(a) Authelia allowed the request but named no identity, so crates/ferrumd/src/sso.rs has nothing to exchange for a session"

            # (b) THE ROW R5's ORDERING EXISTS FOR.
            status=$(verify "https://${daemonHost}/" "$app_cookie")
            [ "$status" = 401 ] \
              || fail "(b) a session cookie obtained in ${appHost}'s context was ACCEPTED at https://${daemonHost}/ with $status. This is SEC-M02, live: crates/ferrumd/src/sso.rs would exchange it for a control-plane session, so any catalog app that can reach loopback owns apply, rollback, settings and the secrets API"

            # (c) nothing at all.
            status=$(verify "https://${daemonHost}/" "")
            [ "$status" = 401 ] \
              || fail "(c) an anonymous verify at https://${daemonHost}/ answered $status"

            # (d) the control for (b): the same apps cookie, at an app's URL.
            status=$(verify "https://${appHost}/" "$app_cookie")
            [ "$status" = 200 ] \
              || fail "(d) the apps cookie was refused at its OWN url (https://${appHost}/) with $status, so (b) above proves nothing about scope -- that cookie may simply never have been valid"

            # (e) revocation at the source, which is what require_session's
            # per-request re-check in crates/ferrumd/src/main.rs relies on.
            curl -sS -o /dev/null -X POST http://127.0.0.1:9091/api/logout \
              -H "Host: ${daemonHost}" -H "Cookie: $control_cookie"
            status=$(verify "https://${daemonHost}/" "$control_cookie")
            [ "$status" = 401 ] \
              || fail "(e) a cookie logged out at Authelia still verified at https://${daemonHost}/ with $status, so logging out of single sign-on leaves the ferrumd session it vouched for alive"

            echo ok > $out
          '';

      # The one check in this file that asks nginx, rather than asking Nix
      # what it told nginx.
      #
      # Every other proxy check above asserts the GENERATOR's output: an
      # attrset, read by Nix, one layer short of the thing that actually
      # breaks a host. `proxy_pass http://::1:7788;` is a well-formed Nix
      # string, a correct-looking attrset value, and a fatal nginx config --
      # nginx splits the authority at its LAST colon and reports `[emerg]
      # invalid port in upstream "::1:7788"`. It then refuses the WHOLE
      # file, so plex, sonarr, auth.<baseDomain> and the catch-all go down
      # with the dashboard, at nginx.service start, on a host whose apply
      # reported success. Nothing in this repository had ever rendered the
      # config, so the defect was invisible to `nix flake check` and visible
      # only to the operator.
      #
      # nixpkgs' own services.nginx.validateConfigFile does not close this:
      # it runs `gixy`, a security linter, over the text. It never invokes
      # nginx's parser.
      #
      # Run for every address modules/core/daemon.nix accepts, because an
      # accept-set is a claim about every downstream consumer and this is
      # the consumer that was making a different claim.
      nginxConfigParses =
        let
          hostFor = addr: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = true; baseDomain = "example.test"; acme.email = "a@example.test"; };
              auth = { enable = true; adminEmail = "a@example.test"; };
              apps = { plex.enable = true; sonarr.enable = true; };
              daemon.listenAddress = addr;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          # The generated UNIT, not the config path read out of it in Nix: a
          # string pulled out with builtins.match would carry no store
          # reference, and the file would not exist in the sandbox. Taking
          # the unit as a build input brings its whole closure -- nginx.conf
          # and the nginx package ExecStart names -- along with it.
          reference = hostFor "127.0.0.1";
          daemonVhostName = "${reference.config.ferrum.daemon.subdomain}.example.test";
          daemonPort = toString reference.config.ferrum.daemon.port;
          probes = map (addr: { inherit addr; unit = (hostFor addr).config.systemd.units."nginx.service".unit; })
            acceptedLoopbackSpellings;
        in
        pkgs.runCommand "ferrum-check-nginx-config-parses"
          { nativeBuildInputs = [ pkgs.openssl ]; }
          ''
            set -eu

            fail() {
              echo "nginx-config-parses: $1" >&2
              exit 1
            }

            # nginx opens every certificate named in the file during `-t`,
            # and the real paths are /var/lib/acme/<name>/..., which exist
            # only on a deployed host after a real ACME order. A throwaway
            # self-signed pair stands in for them. Nothing else in the file
            # is rewritten -- in particular every proxy_pass reaches the
            # parser exactly as modules/proxy/nginx.nix wrote it, which is
            # the whole point of the exercise.
            openssl req -x509 -newkey rsa:2048 -noenc -keyout key.pem -out cert.pem \
              -days 1 -subj /CN=example.test > openssl.log 2>&1 \
              || { cat openssl.log >&2; fail "could not generate a stand-in certificate"; }

            ${lib.concatMapStrings (p: ''
              addr=${lib.escapeShellArg p.addr}
              unit=${p.unit}/nginx.service

              # Both halves come out of the unit, so this tests the exact
              # binary systemd will exec on the exact file it will hand it,
              # rather than a reconstruction that could drift from either.
              execstart=$(grep -m1 '^ExecStart=' "$unit" | cut -d= -f2-)
              bin=$(printf '%s' "$execstart" | cut -d' ' -f1)
              cfg=$(printf '%s' "$execstart" | grep -o -- "-c '[^']*'" | cut -d"'" -f2)

              case "$bin" in
                /nix/store/*/bin/nginx) ;;
                *) fail "nginx.service's ExecStart does not name an nginx binary ($bin) -- this check no longer knows what it is testing" ;;
              esac
              case "$cfg" in
                /nix/store/*) ;;
                *) fail "nginx.service's ExecStart does not pass a store config path (-c $cfg) -- services.nginx.enableReload is probably on, and the file under test is now /etc/nginx/nginx.conf, which this check cannot see" ;;
              esac

              # Anti-vacuity, in that order: a config with no daemon vhost
              # at all would parse perfectly and prove nothing about the
              # upstream this check exists to exercise. These locate the
              # corpus; nginx's own parser below is the assertion.
              grep -q "server_name ${daemonVhostName}" "$cfg" \
                || fail "the config generated for listenAddress=$addr has no ${daemonVhostName} vhost, so parsing it says nothing about the daemon upstream"
              grep -q "proxy_pass http://.*:${daemonPort};" "$cfg" \
                || fail "the config generated for listenAddress=$addr has no proxy_pass to the daemon's port ${daemonPort}, so parsing it says nothing about the daemon upstream"

              # The pid path and the access log join the certificates for
              # the same reason: `nginx -t` really opens /run/nginx/nginx.pid
              # and the compiled-in /var/log/nginx/access.log, and a build
              # sandbox has neither directory. Every edit here is about a
              # capability the HOST has and this sandbox does not. None of
              # them touches a directive whose parse is under test -- the
              # proxy_pass lines reach the parser byte-for-byte as
              # modules/proxy/nginx.nix wrote them, which the mutation test
              # in this commit's message demonstrates.
              #
              # The listen ports are the newest member of that family, and
              # the one that made this check useless for a day. `nginx -t`
              # does not merely parse: it BINDS every listen address, to
              # prove the config could actually start. A Nix builder runs
              # unprivileged, so 443 and 80 come back EACCES and the whole
              # test fails -- on a config nginx had already reported as
              # syntactically fine, with a message blaming daemon
              # listenAddress for a permission problem.
              #
              # It passed locally throughout, because a local container runs
              # as root and root may bind low ports. That is the failure
              # mode this repository keeps meeting from a new direction: a
              # check that is green on the machine that wrote it and red
              # everywhere else. It had never once passed in CI.
              #
              # Rewriting to high ports keeps every directive under test
              # intact. The port a vhost listens on is not what this check
              # exercises -- server_name, the daemon upstream and every
              # proxy_pass are, and all of them are untouched.
              sed -e "s|ssl_certificate .*|ssl_certificate $PWD/cert.pem;|" \
                  -e "s|ssl_certificate_key .*|ssl_certificate_key $PWD/key.pem;|" \
                  -e "s|ssl_trusted_certificate .*|ssl_trusted_certificate $PWD/cert.pem;|" \
                  -e "s|^pid .*|pid $PWD/nginx.pid;|" \
                  -e "s|^http {|http {\n\taccess_log off;|" \
                  -e "/^[[:space:]]*listen /s|:443\([ ;]\)|:8443\1|" \
                  -e "/^[[:space:]]*listen /s|:80\([ ;]\)|:8080\1|" \
                  -e "/^[[:space:]]*listen /s| 443\([ ;]\)| 8443\1|" \
                  -e "/^[[:space:]]*listen /s| 80\([ ;]\)| 8080\1|" \
                  "$cfg" > test.conf

              # Anti-vacuity for the rewrite above, and a guard against the
              # next privileged port somebody adds. If a `listen` line still
              # names a port below 1024, the rewrite missed a spelling and
              # nginx is about to fail on EACCES again -- which would look
              # exactly like a parse error and send the next reader to
              # daemonUpstream for a problem that is not there.
              if grep -nE '^[[:space:]]*listen ([0-9.]+:|\[[^]]*\]:)?([0-9]|[1-9][0-9]|[1-9][0-9]{2}|10[01][0-9]|102[0-3])[[:space:];]' test.conf; then
                fail "a listen directive still names a privileged port after rewriting (above) -- nginx -t binds every listen address and this sandbox is unprivileged, so the parse result would be meaningless"
              fi
              grep -q '^[[:space:]]*listen ' test.conf \
                || fail "the rewritten config has no listen directive at all, so nginx -t would bind nothing and prove nothing"

              mkdir -p prefix/logs
              "$bin" -p "$PWD/prefix" -t -c "$PWD/test.conf" > nginx.log 2>&1 || {
                cat nginx.log >&2
                fail "ferrum.daemon.listenAddress = \"$addr\" is accepted by modules/core/daemon.nix and produces an nginx config nginx itself refuses (above). nginx rejects the whole FILE, so this takes every vhost on the host down at nginx.service start -- after a successful apply. Start at modules/proxy/nginx.nix's daemonUpstream."
              }
              echo "nginx-config-parses: $addr ok"
            '') probes}

            echo ok > $out
          '';

      # A8/D7: the daemon's hostname is reserved, and a collision is a
      # configuration error reported at EVALUATION time.
      #
      # Same builtins.tryEval idiom as journalDirCollision above, and scoped
      # to this assertion's own message for the same non-negotiable reason:
      # an unscoped version would report a host as "rejected" for any
      # reason at all and would pass identically with the assertion deleted.
      # (Until 2026-09-23 the example host also carried unmatched servarr
      # sops pairs, which is what originally made the scoping non-optional;
      # those secrets have since been deleted and the example now evaluates
      # cleanly, but scoping a tryEval assertion to its own message is
      # correct on its own terms and stays.)
      reservedSubdomainCollision =
        let
          hostWith = appSubdomain: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = true; baseDomain = "example.test"; acme.email = "a@example.test"; };
              auth = { enable = true; adminEmail = "a@example.test"; };
              apps = {
                plex.enable = true;
                sonarr = { enable = true; }
                  // lib.optionalAttrs (appSubdomain != null) { subdomain = appSubdomain; };
              };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };

          failuresFor = appSubdomain:
            let
              probe = builtins.tryEval (
                # Must be a phrase the assertion keeps on ONE line: the
                # message is a multi-line Nix string, so an infix spanning its
                # line break never matches and the check reports every host as
                # "not rejected". Caught exactly that way while writing this.
                builtins.filter (m: lib.hasInfix "reserves for its control plane" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) (hostWith appSubdomain).config.assertions))
              );
            in
            if probe.success then probe.value else [ "evaluation threw" ];

          # Read off the host rather than hardcoded, so this still tests the
          # right thing if the default subdomain ever changes -- and so it
          # fails loudly if someone hardcodes "ferrum" in the assertion
          # instead of reading the option (D7 is explicit about that).
          daemonSub = (hostWith null).config.ferrum.daemon.subdomain;
          colliding = [ daemonSub "auth" ];

          defaultFailures = failuresFor null;
          notRejected = builtins.filter (s: failuresFor s == [ ]) colliding;

          # The message has to be actionable: an operator who hits this needs
          # to know WHICH app and WHICH name, or the assertion is a riddle.
          collisionMessages = failuresFor daemonSub;
          namesTheApp = builtins.any (m: lib.hasInfix "ferrum.apps.sonarr.subdomain" m) collisionMessages;
          namesTheReservedName = builtins.any (m: lib.hasInfix "\"${daemonSub}\"" m) collisionMessages;
        in
        {
          ok = defaultFailures == [ ] && notRejected == [ ] && namesTheApp && namesTheReservedName;
          message = "the reserved-subdomain assertion does not protect the control plane's hostname";
          inherit defaultFailures notRejected namesTheApp namesTheReservedName;
          reserved = colliding;
        };

      # The app-vs-app half of the same hazard, which the check above never
      # covered: two ENABLED apps claiming one hostname.
      #
      # Proven before the assertion existed, by evaluating a host with
      # sonarr.subdomain = radarr.subdomain = "tv": exactly ONE vhost
      # (tv.example.test) whose `locations."/".proxyPass` was
      # http://127.0.0.1:7878 -- Radarr's port -- while Sonarr was enabled,
      # certificated and reported as published on that same name.
      # lib.listToAttrs keeps the FIRST entry for a duplicated key and
      # attribute sets iterate sorted, so the alphabetically-earlier app
      # always wins. Same evaluation produced ten Authelia access_control
      # rules for the one domain.
      #
      # Three properties, and the third is the one that would have been
      # easiest to omit:
      #
      #   1. a host with distinct subdomains is NOT rejected (the
      #      anti-vacuity floor -- without it this check passes with the
      #      assertion inverted, or with `subdomain` ignored entirely),
      #   2. a host with two apps on one name IS rejected, by a message
      #      naming both apps and the hostname,
      #   3. both of the above hold with ferrum.proxy.enable = FALSE.
      #
      # (3) is the regression guard for the hoist out of `lib.mkIf
      # proxyEnabled`. The assertion's own reasoning is that a collision
      # must be reported before it is published -- "a trap armed for
      # whenever someone publishes it" -- and while it lived inside that
      # mkIf, that was true across the exposure axis and false across the
      # proxy axis, which is the axis an operator actually crosses when
      # they turn the proxy on. A check that only ever built proxy-on hosts
      # could not see the difference.
      duplicateSubdomainCollision =
        let
          hostWith = { proxy, sonarrSubdomain }: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = proxy; }
                // lib.optionalAttrs proxy {
                baseDomain = "example.test";
                acme.email = "a@example.test";
              };
              apps = {
                radarr = { enable = true; subdomain = "tv"; };
                sonarr = { enable = true; subdomain = sonarrSubdomain; };
              };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };

          # Scoped to this assertion's own message, and to a phrase it keeps
          # on ONE line, for both reasons the reserved check above gives: an
          # unscoped filter reports a host as "rejected" for any reason at
          # all, and an infix spanning a line break in a multi-line Nix
          # string never matches.
          failuresFor = args:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "claim the same hostname" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) (hostWith args).config.assertions))
              );
            in
            if probe.success then probe.value else [ "evaluation threw" ];

          axes = [ true false ];

          # (1) Distinct names must pass. This is the floor that makes the
          # rest of the check mean something.
          distinctRejected = builtins.filter
            (proxy: failuresFor { inherit proxy; sonarrSubdomain = "shows"; } != [ ])
            axes;

          # (2)+(3) One name, two apps, on a proxy-on AND a proxy-off host.
          collidingAccepted = builtins.filter
            (proxy: failuresFor { inherit proxy; sonarrSubdomain = "tv"; } == [ ])
            axes;

          # The message has to name both apps and the hostname, or an
          # operator cannot act on it. Checked on the proxy-ON host, where
          # the vhost name is a real one rather than the bare "tv." a host
          # with no baseDomain renders.
          collisionMessages = failuresFor { proxy = true; sonarrSubdomain = "tv"; };
          namesBothApps = builtins.any
            (m: lib.hasInfix "ferrum.apps.sonarr.subdomain" m
              && lib.hasInfix "ferrum.apps.radarr.subdomain" m)
            collisionMessages;
          namesTheHostname = builtins.any (m: lib.hasInfix "tv.example.test" m) collisionMessages;
        in
        {
          ok = distinctRejected == [ ]
            && collidingAccepted == [ ]
            && namesBothApps
            && namesTheHostname;
          message =
            "two enabled apps may claim one hostname, and only the "
            + "alphabetically-earlier one is published";
          inherit distinctRejected collidingAccepted namesBothApps namesTheHostname;
        };

      # A3/D5, leg 2: nginx emits no CORS header either.
      #
      # ferrumd's own test matrix cannot see this. After R13 nginx is a
      # serving boundary in front of the daemon, and an `add_header
      # Access-Control-Allow-Origin $http_origin;` in a location block would
      # hand a compromised sibling exactly the read access A3 exists to
      # deny -- with every crate test still green, because no crate test
      # ever sees a response nginx has touched.
      #
      # The failure mode for an ABSENCE check is the mirror of the one that
      # made daemon-vhost-enforced vacuous: not a key that exists when it
      # should not, but a corpus that is empty when it should not be. A scan
      # over nothing finds nothing. So the check proves it really read the
      # generated config -- the daemon vhost is present, and the corpus
      # contains directives only the real generator writes -- before it is
      # allowed to conclude anything from finding no CORS.
      nginxEmitsNoCorsHeaders =
        let
          host = ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = true; baseDomain = "example.test"; acme.email = "a@example.test"; };
              auth = { enable = true; adminEmail = "a@example.test"; };
              # A catalog app alongside the daemon on purpose: the threat is
              # a SIBLING subdomain, so a fixture with only the dashboard
              # would not be the configuration A3 is about.
              apps = { plex.enable = true; sonarr.enable = true; };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          nginx = host.config.services.nginx;
          vhosts = nginx.virtualHosts;

          textOf = value: if value == null then "" else value;

          # Every fragment of generated nginx config, each carrying where it
          # came from, so a finding names the exact block rather than only
          # saying that something somewhere emits CORS.
          vhostFragments = lib.concatLists (lib.mapAttrsToList
            (name: vhost:
              [{
                where = ''services.nginx.virtualHosts."${name}".extraConfig'';
                text = textOf (vhost.extraConfig or null);
              }]
              ++ lib.mapAttrsToList
                (loc: location: {
                  where = ''services.nginx.virtualHosts."${name}".locations."${loc}".extraConfig'';
                  text = textOf (location.extraConfig or null);
                })
                (vhost.locations or { }))
            vhosts);

          # The http-level blocks matter as much as the per-vhost ones: an
          # add_header here applies to every vhost at once, and is the
          # cheapest possible way for this to go wrong.
          httpFragments = [
            { where = "services.nginx.commonHttpConfig"; text = textOf (nginx.commonHttpConfig or null); }
            { where = "services.nginx.appendHttpConfig"; text = textOf (nginx.appendHttpConfig or null); }
            { where = "services.nginx.httpConfig"; text = textOf (nginx.httpConfig or null); }
          ];

          fragments = vhostFragments ++ httpFragments;
          corpus = lib.concatStringsSep "\n" (map (f: lib.toLower f.text) fragments);

          # Matched on the "access-control-" prefix rather than on
          # Allow-Origin alone, and lowercased first: nginx directives are
          # free-form text, header names are case-insensitive, and an
          # Allow-Credentials or Expose-Headers line is already a CORS layer
          # somebody is part-way through wiring up.
          emitsCors = f: lib.hasInfix "access-control-" (lib.toLower f.text);
          offending = map (f: f.where) (builtins.filter emitsCors fragments);

          daemonName = "${host.config.ferrum.daemon.subdomain}.example.test";
          # The anti-vacuity guards.
          scannedTheDaemonVhost = vhosts ? ${daemonName};
          scannedASiblingApp = vhosts ? "sonarr.example.test";
          # Directives only the real generator produces. If these are
          # missing, the corpus is not the generated config and a clean scan
          # means nothing.
          scannedRealDirectives =
            lib.hasInfix "auth_request /authelia" corpus && lib.hasInfix "proxy_pass" corpus;
        in
        {
          ok = offending == [ ]
            && scannedTheDaemonVhost
            && scannedASiblingApp
            && scannedRealDirectives;
          message = "the generated nginx config does not hold A3's no-CORS invariant";
          inherit offending scannedTheDaemonVhost scannedASiblingApp scannedRealDirectives;
          fragmentsScanned = builtins.length fragments;
          vhostsScanned = builtins.attrNames vhosts;
        };

      # The apps are told where media lives, and told the SAME place the
      # storage module created.
      #
      # This reads the config the reconciler will actually receive, not the
      # metadata that produces it. The whole class of bug it guards against
      # is the two disagreeing: on the first real install every app was
      # pointed at /srv/media while the disks were mounted at /mnt/media-N,
      # so 7TB was present, mounted, and invisible.
      rootFoldersReachTheApps =
        let
          host = ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              apps = {
                sonarr.enable = true;
                radarr.enable = true;
                qbittorrent.enable = true;
                sabnzbd.enable = true;
              };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          cfgPath = host.config.systemd.services.ferrum-reconcile.environment.FERRUM_RECONCILE_CONFIG;
          mediaDir = host.config.ferrum.storage.mediaDir;
        in
        pkgs.runCommand "ferrum-check-root-folders" { } ''
          set -eu
          cfg=${cfgPath}
          fail() { echo "root-folder check: $1" >&2; echo "--- config ---" >&2; cat "$cfg" >&2; exit 1; }

          ${pkgs.jq}/bin/jq -e '.rootFolders | length == 2' "$cfg" > /dev/null \
            || fail "expected one root folder each for sonarr and radarr"

          ${pkgs.jq}/bin/jq -e --arg p "${mediaDir}/media/tv" \
            '.rootFolders[] | select(.app == "sonarr") | select(.path == $p)' "$cfg" > /dev/null \
            || fail "sonarr's root folder is not ${mediaDir}/media/tv"

          ${pkgs.jq}/bin/jq -e --arg p "${mediaDir}/media/movies" \
            '.rootFolders[] | select(.app == "radarr") | select(.path == $p)' "$cfg" > /dev/null \
            || fail "radarr's root folder is not ${mediaDir}/media/movies"

          # And the path must be under the root the storage module builds,
          # which is the half that actually failed before.
          case "${mediaDir}" in
            /data) ;;
            *) fail "mediaDir is ${mediaDir}, not the /data root the TRaSH layout assumes" ;;
          esac

          # THE HARDLINK INVARIANT, which is the reason any of this is
          # shaped the way it is. Every download path and every root
          # folder must sit under ONE root: the *arrs import by
          # hardlinking, a hardlink cannot cross a filesystem, and a
          # download client left elsewhere turns every import into a
          # silent copy. Asserting the paths individually would not catch
          # a layout where each is internally sensible and they are on
          # different mounts.
          ${pkgs.jq}/bin/jq -e --arg r "${mediaDir}/" \
            '[.rootFolders[].path, .downloadPaths[].path, (.downloadPaths[].incompletePath // empty)]
             | length > 0 and all(startswith($r))' "$cfg" > /dev/null \
            || fail "a download or library path is outside ${mediaDir}, so imports would copy instead of hardlink"

          ${pkgs.jq}/bin/jq -e --arg p "${mediaDir}/torrents" \
            '.downloadPaths[] | select(.app == "qbittorrent") | select(.path == $p)' "$cfg" > /dev/null \
            || fail "qbittorrent does not write to ${mediaDir}/torrents"

          ${pkgs.jq}/bin/jq -e --arg p "${mediaDir}/usenet/complete" --arg i "${mediaDir}/usenet/incomplete" \
            '.downloadPaths[] | select(.app == "sabnzbd") | select(.path == $p) | select(.incompletePath == $i)' "$cfg" > /dev/null \
            || fail "sabnzbd's complete/incomplete directories are wrong"

          echo ok > $out
        '';

      # modules/proxy/dns.nix decides WHICH hostnames ferrum publishes a
      # record for, and that decision was proven correct exactly once -- by
      # hand-evaluating ferrumDnsConfig and reading the JSON. That is good
      # evidence for that run and no protection at all against the next edit,
      # on a file whose four rulings are each a real incident or a real
      # decision:
      #
      #   * a `lan` app gets NO record (D-03). It has an nginx vhost and an
      #     IP allow-list but no ACME certificate, so a public record would
      #     hand an external client a self-signed handshake before nginx
      #     denies them -- publishing the very thing the LAN restriction
      #     exists to prevent.
      #   * auth.<baseDomain> appears exactly when acme.nix issues its
      #     certificate -- ferrum.auth.enable && (a public app OR the
      #     published dashboard) -- because a certificate for a name that
      #     does not resolve is the incident R1 exists to fix, and the two
      #     conditions had already drifted apart once.
      #   * the daemon's own record is present when the daemon is actually
      #     published (owner ruling H-01, option C) and absent when it is
      #     not -- proxyLib.daemonPublished, the same predicate the vhost,
      #     the Authelia rule and the certificate all read. This file was
      #     the one consumer that did not read it, so an unpublished daemon
      #     got a record for a hostname nginx answers with `return 444`.
      #   * EVERY record carries proxied = false (D-05). Cloudflare's orange
      #     cloud makes every request arrive from a Cloudflare edge address,
      #     which inverts nginx.nix's allow/deny against trustedNetworks into
      #     a total outage for the apps that restriction protects.
      #
      # Cheap by construction: it realizes one `writeText` JSON file, never a
      # system closure, so this stays a genuinely runnable CI check rather
      # than the disk-hungry eval-example-hosts below.
      dnsRecordSet =
        let
          # `apps` is a parameter because the record set has to be proven on
          # a host with NO public app as well as on one with an app: that is
          # the configuration on which the auth record and the auth
          # certificate disagreed.
          mkDnsHost = { auth, proxy ? true, daemon ? { }, apps ? {
            # Deliberately `lan`: this is the app that must NOT appear.
            sonarr = { enable = true; exposure = "lan"; };
            radarr.enable = true;
          } }: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = {
                enable = proxy;
                baseDomain = "example.invalid";
                acme.email = "admin@example.invalid";
                dns = {
                  enable = true;
                  recordMode = "a";
                  staticAddress = "203.0.113.10";
                };
              };
              auth.enable = auth;
              inherit apps daemon;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          withAuth = (mkDnsHost { auth = true; }).config.system.build.ferrumDnsConfig;
          withoutAuth = (mkDnsHost { auth = false; }).config.system.build.ferrumDnsConfig;
          # The dashboard-only host: SSO on, and every catalog app left at
          # lan, so publicApps == { }. modules/proxy/lib.nix calls this "the
          # safest configuration available", and it is the one where an
          # app-keyed condition silently stops describing reality.
          dashboardOnly = (mkDnsHost {
            auth = true;
            apps = { sonarr = { enable = true; exposure = "lan"; }; };
          }).config.system.build.ferrumDnsConfig;
          # The proxy-off/auth-on host, and the other half of A7.
          #
          # modules/proxy/authelia.nix and this file are gated differently
          # from modules/proxy/nginx.nix -- neither is wrapped in
          # `lib.mkIf proxyEnabled` -- so the proxy term of
          # proxyLib.daemonPublished is the ONLY thing standing between this
          # configuration and an auth.example.invalid record for a login page
          # that has no vhost. Its counterpart assertion, on Authelia's own
          # access_control rules, lives in daemon-vhost-enforced; nginx can
          # say nothing about either, because with the proxy off its module
          # never runs.
          #
          # Every app is at `lan` so publicApps == { }: with a public app
          # present the auth record is created by the app term regardless,
          # and the daemonPublished term would be unobservable here.
          proxyOff = (mkDnsHost {
            auth = true;
            proxy = false;
            apps = { sonarr = { enable = true; exposure = "lan"; }; };
          }).config.system.build.ferrumDnsConfig;
          # ferrum.daemon.dns.includeRecord = false, which had no fixture at
          # all. Creating the daemon record is the owner's H-01 option-C
          # ruling and this option is the documented one-line way back out of
          # it, so "it remains, so turning the record off is still a one-line
          # change" was a claim about behaviour that nothing exercised.
          # radarr stays public so the document still has a record in it: an
          # absence found in an empty list is not a finding.
          recordExcluded = (mkDnsHost {
            auth = true;
            daemon.dns.includeRecord = false;
          }).config.system.build.ferrumDnsConfig;
          # ferrum.daemon.publish = false: the daemon RUNS but is reachable
          # only over the SSH tunnel modules/core/daemon.nix's A5 assertion
          # protects. Every other consumer of proxyLib.daemonPublished --
          # the vhost, the Authelia rule, the certificate -- already reads
          # it through that one predicate, and this file was the single
          # consumer that did not: daemonRecords was keyed on
          # ferrum.daemon.dns.includeRecord ALONE, so an unpublished daemon
          # still got a public record for a hostname nginx's catch-all
          # answers with `return 444`.
          #
          # That is the auth.thesyms.ca defect with the sign flipped -- a
          # record with nothing behind it rather than a certificate with
          # nothing behind it -- and it is exactly what a stage-1 installer
          # host now looks like, so it stopped being a hypothetical the
          # moment ferrum.daemon.publish existed.
          #
          # radarr stays public, as in recordExcluded above, so the document
          # still has a record in it: an absence found in an empty list is
          # not a finding.
          publishOff = (mkDnsHost {
            auth = true;
            daemon.publish = false;
          }).config.system.build.ferrumDnsConfig;
        in
        pkgs.runCommand "ferrum-check-dns-record-set" { } ''
          set -eu
          with_auth=${withAuth}
          without_auth=${withoutAuth}
          dashboard_only=${dashboardOnly}
          proxy_off=${proxyOff}
          record_excluded=${recordExcluded}
          publish_off=${publishOff}
          fail() {
            echo "dns record-set check: $1" >&2
            echo "--- with auth ---" >&2; cat "$with_auth" >&2
            echo "--- without auth ---" >&2; cat "$without_auth" >&2
            echo "--- dashboard only ---" >&2; cat "$dashboard_only" >&2
            echo "--- proxy off ---" >&2; cat "$proxy_off" >&2
            echo "--- record excluded ---" >&2; cat "$record_excluded" >&2
            echo "--- publish off ---" >&2; cat "$publish_off" >&2
            exit 1
          }

          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "app:radarr") | select(.name == "radarr.example.invalid")' \
            "$with_auth" > /dev/null \
            || fail "the public app radarr has no record"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "app:sonarr")] | length == 0' \
            "$with_auth" > /dev/null \
            || fail "the lan-exposure app sonarr got a public record -- it has no certificate, so that publishes a self-signed handshake to the internet"

          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "auth") | select(.name == "auth.example.invalid")' \
            "$with_auth" > /dev/null \
            || fail "auth.example.invalid has no record while ferrum.auth.enable is true -- that is the original incident"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "auth")] | length == 0' \
            "$without_auth" > /dev/null \
            || fail "an auth record was created on a host with SSO off"

          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "daemon") | select(.name == "ferrum.example.invalid")' \
            "$with_auth" > /dev/null \
            || fail "the daemon record is missing (owner ruling H-01, option C)"

          # R5/SEC-M02. The control plane's own Authelia portal.
          #
          # The dashboard has a session cookie scope of its own now, and
          # Authelia refuses to serve a scope from a portal outside it, so the
          # dashboard's 401 redirect goes to auth.ferrum.<baseDomain> rather
          # than auth.<baseDomain>. modules/proxy/acme.nix orders a
          # certificate for that name on the same condition. Without the
          # record, that is a valid certificate on a name that does not
          # resolve and a dashboard nobody can log in to -- the
          # auth.thesyms.ca incident exactly, one hostname over, which is why
          # this assertion sits beside the one that encodes it.
          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "auth-control") | select(.name == "auth.ferrum.example.invalid")' \
            "$with_auth" > /dev/null \
            || fail "auth.ferrum.example.invalid has no record, while modules/proxy/acme.nix issues its certificate and the dashboard's 401 redirect points at it -- nobody can log in to the control plane"

          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "auth-control") | select(.name == "auth.ferrum.example.invalid")' \
            "$dashboard_only" > /dev/null \
            || fail "the dashboard-only host has no record for the dashboard's own Authelia portal, which is the one host where that portal is the only way in"

          # And the three hosts that must NOT have it. Each has its own
          # anti-vacuity partner above: $without_auth is asserted to be a
          # generated document by the auth-record assertion, $publish_off and
          # $record_excluded by their radarr assertions below, and $proxy_off
          # by its baseDomain assertion. Without those, "no auth-control
          # record" would be satisfied by an empty file.
          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "auth-control")] | length == 0' \
            "$without_auth" > /dev/null \
            || fail "a control-plane Authelia portal record was created on a host with SSO off, where no Authelia runs at all"

          # The dashboard-only host. Its auth certificate is issued
          # (acme.nix gates that on publicApps != { } || daemonPublished),
          # so without the matching record Authelia redirects the browser to
          # a hostname that does not resolve: a valid certificate on a dead
          # name, and no way to log in to the dashboard the host exists to
          # publish.
          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source | startswith("app:"))] | length == 0' \
            "$dashboard_only" > /dev/null \
            || fail "the dashboard-only fixture has a public app record, so it no longer tests the publicApps == { } case at all"

          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "auth") | select(.name == "auth.example.invalid")' \
            "$dashboard_only" > /dev/null \
            || fail "a host that publishes only the dashboard has no auth.example.invalid record, while acme.nix issues its certificate -- Authelia would redirect the browser to a name that does not resolve"

          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "daemon") | select(.name == "ferrum.example.invalid")' \
            "$dashboard_only" > /dev/null \
            || fail "the dashboard-only host has no record for the dashboard itself"

          # A7, the proxy-off half.
          #
          # The anti-vacuity guard here USED TO BE "this document contains a
          # daemon record", and that only ever worked because daemonRecords
          # ignored proxyLib.daemonPublished -- an absence proof propped up
          # by the very gap the publishOff fixture above closes. With the
          # daemon record moving on the same predicate as the auth record,
          # this fixture's record list is legitimately EMPTY, and "no auth
          # record in an empty list" proves nothing on its own.
          #
          # So the guard is a differential instead of a presence.
          # $dashboard_only is this exact fixture with ferrum.proxy.enable =
          # true -- same auth, same lan-only app set, same everything else --
          # and it is asserted above to carry BOTH the auth record and the
          # daemon record. The only difference between a document with two
          # records and a document with none is therefore the proxy term,
          # which is the claim. The baseDomain assertion pins that this is a
          # generated document rather than an empty default: a file that
          # failed to describe this host would have no records either.
          ${pkgs.jq}/bin/jq -e '.baseDomain == "example.invalid"' \
            "$proxy_off" > /dev/null \
            || fail "the proxy-off document does not carry this fixture's baseDomain, so it is not the generated config and every absence claimed of it is vacuous"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "auth")] | length == 0' \
            "$proxy_off" > /dev/null \
            || fail "a host with ferrum.proxy.enable = false got an auth.example.invalid record -- nginx builds no vhost for it, so that publishes a name with nothing behind it (A7)"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "daemon")] | length == 0' \
            "$proxy_off" > /dev/null \
            || fail "a host with ferrum.proxy.enable = false got a daemon record -- nginx never runs on it, so the name resolves to a box serving nothing at all (A7)"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "auth-control")] | length == 0' \
            "$proxy_off" > /dev/null \
            || fail "a host with ferrum.proxy.enable = false got a control-plane Authelia portal record -- nginx never runs on it (A7/SEC-M02)"

          # ferrum.daemon.dns.includeRecord = false, the only behaviour that
          # option has. The radarr assertion first, for the same reason as
          # above: it proves this document has records at all.
          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "app:radarr")' \
            "$record_excluded" > /dev/null \
            || fail "the includeRecord = false document has no records at all, so finding no daemon record in it proves nothing"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "daemon")] | length == 0' \
            "$record_excluded" > /dev/null \
            || fail "ferrum.daemon.dns.includeRecord = false still produced a daemon record -- the documented one-line way to opt out of the H-01 ruling does nothing"

          # The portal record follows the dashboard's own record out, not the
          # apps' auth record: the name exists only because the dashboard is
          # published, so an operator managing the dashboard's record by hand
          # manages its login page's record with it. Leaving one behind would
          # hand them half a pair with no way to tell.
          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "auth-control")] | length == 0' \
            "$record_excluded" > /dev/null \
            || fail "ferrum.daemon.dns.includeRecord = false took the dashboard's record out and left its Authelia portal's behind"

          # ferrum.daemon.publish = false. radarr first, same anti-vacuity
          # reason as above, and it is also the positive half of the claim:
          # unpublishing the DASHBOARD must not unpublish the APPS.
          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "app:radarr")' \
            "$publish_off" > /dev/null \
            || fail "the publish = false document has no app records at all -- either it is not the generated config, so finding no daemon record in it proves nothing, or unpublishing the dashboard has unpublished the apps too"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "auth-control")] | length == 0' \
            "$publish_off" > /dev/null \
            || fail "ferrum.daemon.publish = false still produced a control-plane Authelia portal record. The dashboard is deliberately tunnel-only on that host, so nginx builds no vhost for either name"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "daemon")] | length == 0' \
            "$publish_off" > /dev/null \
            || fail "ferrum.daemon.publish = false still produced a daemon record. Nothing serves that name -- nginx builds no vhost for an unpublished daemon, so its catch-all answers with a 444 and closes -- and acme.nix issues no certificate for it, so this is a public record pointing at a closed connection on a host whose dashboard is deliberately tunnel-only"

          # D-05, over every fixture whose record list is non-empty.
          # $proxy_off is deliberately absent from this list and must stay
          # absent: its records are now legitimately zero, and the
          # `(.records | length) > 0` term below is the anti-vacuity half of
          # this loop -- including it would turn "no record is proxied" into
          # a hard failure on a document that has nothing to proxy, and
          # dropping that term to accommodate it would let this loop pass
          # over five empty lists.
          for cfg in "$with_auth" "$without_auth" "$dashboard_only" "$record_excluded" "$publish_off"; do
            ${pkgs.jq}/bin/jq -e '(.records | length) > 0 and all(.records[]; .proxied == false)' \
              "$cfg" > /dev/null \
              || fail "a record is proxied -- orange-cloud proxying makes every request arrive from a Cloudflare edge address"
          done

          echo ok > $out
        '';

      # F1/R1. `ferrum.proxy.dns.ddnsUpdater` shipped as a timer that
      # re-published `ferrum.proxy.dns.staticAddress` on a schedule.
      # modules/proxy/dns.nix said three separate times that it re-checked
      # this host's real public address; no code in crates/ ever queried one.
      # The owner's address moved from 184.148.39.165 to 142.180.179.64,
      # seven records kept pointing at the old one, every published app
      # became unreachable from outside, and the host reported itself healthy
      # throughout.
      #
      # The Rust half of the fix -- the three-source quorum, the refusal on
      # disagreement, the flap budget -- is proved in
      # crates/ferrum-dns/src/public_ip.rs and
      # crates/ferrum-apply/src/dns_reconcile.rs, which is where behaviour
      # belongs. What only Nix can prove is the part of the fix that lives in
      # the option surface: a host that has turned the updater on must no
      # longer be required to write an address down by hand, because the
      # hand-written address is exactly what went stale. That is the first
      # probe below.
      #
      # The other two are its anti-vacuity half, and they are not decoration:
      # a probe reporting "no staticAddress assertion fired" would pass
      # identically if the assertion had simply been deleted, or if the
      # message scoping were wrong and the probe could never see any failure
      # at all. So the same probe, on the same example host, must still
      # REJECT the two configurations that remain genuinely unusable -- the
      # updater off with no address, and the updater on with a CNAME it has
      # no address to correct inside.
      #
      # Same builtins.tryEval + message-scoping idiom as journalDirCollision
      # above, and scoped for the same measured reason: the example host
      # carries other failing assertions (its committed placeholder secrets
      # have no *-apikey-raw.sops counterparts), so an unscoped probe reports
      # every configuration as rejected and would pass with this whole
      # requirement reverted.
      ddnsUpdaterNeedsNoStaticAddress =
        let
          hostWith = { updater, recordMode ? "a", staticAddress ? "", cnameTarget ? "" }:
            ferrumLib.mkHost {
              inherit system;
              settings = {
                schemaVersion = realMigrations.currentVersion;
                proxy = {
                  enable = true;
                  baseDomain = "example.invalid";
                  acme.email = "admin@example.invalid";
                  dns = {
                    enable = true;
                    inherit recordMode staticAddress cnameTarget;
                    ddnsUpdater.enable = updater;
                  };
                };
                apps.radarr.enable = true;
              };
              modules = [ ../../../examples/hosts/minimal/configuration.nix ];
            };

          failuresMatching = infix: args:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix infix m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) (hostWith args).config.assertions))
              );
            in
            if probe.success then probe.value else [ "evaluation threw" ];

          # 1. The requirement itself: the updater on, nothing written down.
          updaterNoAddress =
            failuresMatching "ferrum.proxy.dns.staticAddress" { updater = true; };

          # 2. Anti-vacuity: the identical configuration with the updater OFF
          #    is still refused, because then nothing on the host knows where
          #    to point the records.
          noUpdaterNoAddress =
            failuresMatching "ferrum.proxy.dns.staticAddress" { updater = false; };

          # 3. Anti-vacuity: the updater on with recordMode = "cname" is
          #    still refused -- a CNAME carries no address to correct.
          updaterWithCname = failuresMatching "ferrum.proxy.dns.ddnsUpdater.enable" {
            updater = true;
            recordMode = "cname";
            cnameTarget = "box.dyn.example.net";
          };

          # 4. Evaluating is not the same as working: the relaxed
          #    configuration must still build the unit and the timer that do
          #    the discovering.
          relaxed = (hostWith { updater = true; }).config.systemd;
          unitExists = relaxed.services ? ferrum-dns-updater;
          timerExists = relaxed.timers ? ferrum-dns-updater;
        in
        {
          ok = updaterNoAddress == [ ]
            && noUpdaterNoAddress != [ ]
            && updaterWithCname != [ ]
            && unitExists
            && timerExists;
          inherit updaterNoAddress noUpdaterNoAddress updaterWithCname unitExists timerExists;
        };

      # The other half of the two-layer control, and the half nothing in the
      # repo pinned until now.
      #
      # modules/lib/hostnames.nix refuses a bad value at EVALUATION;
      # modules/lib/settings-schema.json refuses the WRITE, which is what
      # stops ferrumd's PUT /api/settings composing it in the first place.
      # The difference matters to an operator: refused at the schema they
      # get an error and their old settings; refused at evaluation they get
      # a saved settings.json and an apply that fails.
      #
      # crates/ferrumd/src/settings.rs does test these patterns, but against
      # constants TRANSCRIBED into Rust -- its own comment says so, and
      # explains why: every Rust derivation in nix/ filters `src` down to
      # crates/ + examples/ + flake.lock, so a test there cannot reach the
      # real schema file at all. The consequence was that deleting a
      # `pattern` from settings-schema.json broke nothing anywhere. This
      # check reads the real file, which is the half that was missing.
      #
      # `builtins.match` matches the WHOLE string, so the `^`/`$` anchors
      # the JSON Schema patterns carry are stripped before use -- and that
      # is the same semantics the shipped validator has, since the Rust
      # `regex` crate's `$` is end-of-haystack and does not tolerate a
      # trailing newline (pinned independently by
      # `the_validators_end_anchor_does_not_tolerate_a_trailing_newline` in
      # crates/ferrumd/src/settings.rs). Getting that wrong in the other
      # direction would be a check that reports a payload refused which the
      # real validator accepts.
      schemaRefusesEverySeparatorPayload =
        let
          schema = builtins.fromJSON (builtins.readFile ../../../modules/lib/settings-schema.json);

          # Walk to a leaf. "[]" descends into an array's items, "{}" into
          # additionalProperties, "<>" into propertyNames -- the KEY-position
          # slot, which is exactly the one a value-only walk cannot see and
          # which is why `secrets.<KEY>` survived three passes.
          at = path: lib.foldl'
            (node: part:
              if node == null then null
              else if part == "[]" then node.items or null
              else if part == "{}" then node.additionalProperties or null
              else if part == "<>" then node.propertyNames or null
              else (node.properties or { }).${part} or null)
            schema path;

          strip = p:
            let a = lib.removePrefix "^" p; in lib.removeSuffix "$" a;

          # null   -> the leaf, or its pattern, is absent entirely
          # true   -> the shipped schema would accept this string
          # false  -> refused
          accepts = path: value:
            let node = at path; in
            if node == null || !(node ? pattern) then null
            else builtins.match (strip node.pattern) value != null;

          newline = "\n";
          check = { path, value, want }:
            let verdict = accepts path value; in
            { name = "${lib.concatStringsSep "." path} <- ${builtins.toJSON value}";
              ok = verdict == want;
              # A leaf with no `pattern` at all reports NO-PATTERN rather
              # than "accepted": the two are the same outcome for an
              # attacker but very different to whoever has to fix it.
              got =
                if verdict == null then "NO-PATTERN"
                else if verdict then "accepted"
                else "refused";
            };

          rootKeyRule = "w+ /root/.ssh/authorized_keys 0600 root root - ssh-ed25519 AAAAINJECTED";

          cases =
            map (p: { path = p; value = "/var/lib/x${newline}${rootKeyRule}"; want = false; })
              [ [ "storage" "stateDir" ] [ "storage" "snapshotDir" ] [ "storage" "journalDir" ]
                [ "storage" "mediaDir" ] [ "storage" "pool" "branches" "[]" ] [ "secretsDir" ] ]
            ++ [
              { path = [ "storage" "pool" "branches" "[]" ]; value = "/mnt/d1,suid,dev"; want = false; }
              { path = [ "storage" "mediaGroup" ]; value = "media${newline}badroot:x:0:"; want = false; }
              { path = [ "secretsDir" ]; value = "/etc/ferrum/../../root"; want = false; }
              { path = [ "secrets" "<>" ]; value = "../../../root/.ssh/authorized_keys"; want = false; }
              { path = [ "apps" "<>" ]; value = "../../../etc/nginx"; want = false; }
              { path = [ "proxy" "acme" "credentialSecret" ]; value = "../../../etc/shadow"; want = false; }
              { path = [ "proxy" "dns" "staticAddress" ]; value = "203.0.113.10${newline}evil"; want = false; }
              { path = [ "proxy" "dns" "cnameTarget" ]; value = "a.example.net${newline}evil"; want = false; }
              { path = [ "proxy" "dns" "adoptedNames" "[]" ]; value = "*.example.com"; want = false; }

              # The other direction, without which a pattern that refused
              # everything would pass every line above while bricking the
              # product. The store path is not decoration: it is what
              # ferrum.secretsDir evaluates to on the example host these
              # very checks build.
              { path = [ "storage" "stateDir" ]; value = "/var/lib/ferrum/state"; want = true; }
              { path = [ "storage" "snapshotDir" ]; value = "/var/lib/ferrum/snapshots"; want = true; }
              { path = [ "storage" "journalDir" ]; value = "/var/lib/ferrum/journal"; want = true; }
              { path = [ "storage" "mediaDir" ]; value = "/data"; want = true; }
              { path = [ "storage" "pool" "branches" "[]" ]; value = "/mnt/ferrum-disk-0"; want = true; }
              { path = [ "secretsDir" ]; value = "/etc/ferrum/secrets"; want = true; }
              { path = [ "secretsDir" ];
                value = "/nix/store/1a2b3c4d5e6f7g8h9i0jklmnopqrstuv-source/examples/hosts/minimal/secrets";
                want = true; }
              { path = [ "storage" "mediaGroup" ]; value = "ferrum-media"; want = true; }
              { path = [ "secrets" "<>" ]; value = "acme-dns"; want = true; }
              { path = [ "secrets" "<>" ]; value = "qbittorrent-vpn"; want = true; }
              { path = [ "apps" "<>" ]; value = "sonarr"; want = true; }
              { path = [ "proxy" "acme" "credentialSecret" ]; value = "acme-dns"; want = true; }
              { path = [ "proxy" "dns" "staticAddress" ]; value = "203.0.113.10"; want = true; }
              { path = [ "proxy" "dns" "staticAddress" ]; value = ""; want = true; }
              { path = [ "proxy" "dns" "cnameTarget" ]; value = ""; want = true; }
              { path = [ "proxy" "dns" "adoptedNames" "[]" ]; value = "plex.example.com"; want = true; }
            ];

          results = map check cases;
          failures = builtins.filter (r: !r.ok) results;
        in
        {
          ok = failures == [ ];
          failures = map (r: { inherit (r) name got; }) failures;
          caseCount = builtins.length cases;
        };

      # The guard the three previous taint enumerations could not have had,
      # because each of them started from a FILE.
      #
      # Every earlier sweep answered "which settings reach a directive?" by
      # opening the files already known to be dangerous -- nginx, Authelia,
      # ACME -- and tracing backwards to the settings that feed them. That
      # method can only ever rediscover the files it started from. It found
      # nginx three times and never once found systemd.tmpfiles.rules, which
      # is newline-separated and re-executed BY ROOT on every
      # switch-to-configuration. A forward sweep from every schema leaf
      # found five such grammars, and injected rules were rendered out of
      # four of them.
      #
      # So this check is deliberately organised by GRAMMAR, not by file or
      # by option: one case per generated-file format ferrum writes, each
      # naming the character that separates records in it. Adding a sink
      # means adding a case here, and the question to answer is always the
      # same -- what separates records in the file I am generating, and can
      # this string contain it?
      #
      # It asserts on the GENERATED TEXT rather than on the option values,
      # and that is the whole point. Asserting on inputs is what the earlier
      # passes effectively did, and an input assertion is blind to a sink
      # nobody remembered. Reading the rendered records is not: whatever
      # route a payload takes to get there, it has to appear in the output
      # to do any harm.
      #
      # A probe passes on either of two outcomes, because either is a real
      # defence and the check must not care which layer supplied it:
      #
      #   eval-refused          the NixOS option type (modules/lib/hostnames.nix)
      #                         rejected the value, so nothing was generated
      #   no-separator-in-output the value was accepted but the rendered
      #                         records contain no separator anyway
      #
      # WHY EVERY GRAMMAR ALSO CARRIES A CONTROL, and why the control is not
      # optional padding. "eval-refused" is indistinguishable from "this
      # host failed to evaluate for a reason that has nothing to do with the
      # payload" -- and the example host genuinely does carry unrelated
      # failing assertions (see journalDirCollision above, which was bitten
      # by exactly this). A version of this check without controls would
      # report all seven probes refused, go green, and go green identically
      # with every type in hostnames.nix deleted. The control feeds a BENIGN
      # value through the same extractor and demands two things of it: that
      # it does NOT come back eval-refused, and that it yields a NON-EMPTY
      # list of records. The second half matters as much as the first --
      # "no separator found among zero records" is not evidence, it is an
      # empty search.
      directiveSeparatorsNeverReachAGeneratedFile =
        let
          hostWith = extra: ferrumLib.mkHost {
            inherit system;
            settings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
              extra
            ];
            revision = "ci";
          };

          newline = "\n";

          # The four extractors, one per generated file. Each returns the
          # list of RENDERED records -- the strings that end up in the file
          # -- never the option values they were built from.
          tmpfilesRules = h: h.config.systemd.tmpfiles.rules;
          # The options of ferrum's OWN pool mount, flattened.
          #
          # Selected by fsType rather than by the mediaDir key, and the
          # distinction is the point twice over. Keying on mediaDir would
          # make the extractor follow the payload, since mediaDir is itself
          # one of the values under test. Reading every filesystem instead
          # would sweep in mounts declared by nixpkgs and by the example
          # host, so an unrelated option containing a comma would fail the
          # control and this check would look broken for a reason that has
          # nothing to do with ferrum. "fuse.mergerfs" is a literal in
          # modules/core/pool.nix and no setting can steer it.
          fstabOptions = h:
            lib.concatMap (fs: fs.options or [ ])
              (builtins.filter (fs: (fs.fsType or "") == "fuse.mergerfs")
                (lib.attrValues h.config.fileSystems));
          # The systemd unit LIST-field. NixOS emits one `Key=value` line
          # per element with no escaping, which is what makes it a grammar
          # distinct from Environment= (whose value nixpkgs JSON-quotes).
          readWritePaths = h:
            h.config.systemd.services.ferrum-dns-updater.serviceConfig.ReadWritePaths;
          # /etc/group rows, by name. This one is a KEY position:
          # modules/core/storage.nix writes `users.groups.${mediaGroup}`, and
          # Nix attribute names are arbitrary strings, so nothing upstream
          # of the option type objects to a newline in one.
          groupNames = h: builtins.attrNames h.config.users.groups;

          # The host shape the ddns updater needs to exist at all; without
          # it readWritePaths extracts from a unit that lib.mkIf removed and
          # the probe proves nothing.
          ddnsOn = {
            ferrum.proxy.dns = {
              enable = true;
              recordMode = "a";
              staticAddress = "203.0.113.10";
              ddnsUpdater.enable = true;
            };
          };
          poolOn = branches: {
            ferrum.storage.pool = { enable = true; inherit branches; };
          };

          run = { name, module, extract, separators }:
            let
              forced = builtins.tryEval
                (let records = extract (hostWith module); in builtins.deepSeq records records);
            in
            if !forced.success then { inherit name; outcome = "eval-refused"; records = [ ]; leaked = [ ]; }
            else
              let
                records = forced.value;
                leaked = builtins.filter (r: lib.any (sep: lib.hasInfix sep r) separators) records;
              in
              {
                inherit name records leaked;
                outcome = if leaked == [ ] then "no-separator-in-output" else "LEAKED";
              };

          # The payloads are the ones that were actually rendered during the
          # forward sweep, not plausible-looking substitutes -- an injected
          # root authorized_keys rule, an injected ExecStartPre=, and real
          # mount options.
          rootKeyRule = "w+ /root/.ssh/authorized_keys 0600 root root - ssh-ed25519 AAAAINJECTED";

          injections = [
            (run {
              name = "tmpfiles <- storage.stateDir";
              module = { ferrum.storage.stateDir = "/var/lib/ferrum/state${newline}${rootKeyRule}"; };
              extract = tmpfilesRules;
              separators = [ newline ];
            })
            (run {
              name = "tmpfiles <- secretsDir";
              module = { ferrum.secretsDir = lib.mkForce "/etc/ferrum/secrets${newline}${rootKeyRule}"; };
              extract = tmpfilesRules;
              separators = [ newline ];
            })
            (run {
              name = "tmpfiles <- storage.mediaGroup";
              module = { ferrum.storage.mediaGroup = "root - -${newline}${rootKeyRule}"; };
              extract = tmpfilesRules;
              separators = [ newline ];
            })
            (run {
              name = "tmpfiles <- storage.pool.branches[]";
              module = poolOn [ "/mnt/d0" "/mnt/d1${newline}${rootKeyRule}" ];
              extract = tmpfilesRules;
              separators = [ newline ];
            })
            (run {
              name = "fstab options <- storage.pool.branches[]";
              module = poolOn [ "/mnt/d0" "/mnt/d1,suid,dev,AAAAOPTINJECT" ];
              extract = fstabOptions;
              separators = [ "," ];
            })
            (run {
              name = "systemd unit list-field <- storage.stateDir";
              module = lib.recursiveUpdate ddnsOn {
                ferrum.storage.stateDir =
                  "/var/lib/ferrum/state${newline}ExecStartPre=/bin/sh -c id>/tmp/pwn2";
              };
              extract = readWritePaths;
              separators = [ newline ];
            })
            (run {
              name = "/etc/group <- storage.mediaGroup";
              module = { ferrum.storage.mediaGroup = "media${newline}badroot:x:0:"; };
              extract = groupNames;
              separators = [ newline ":" ];
            })
          ];

          controls = [
            (run { name = "CONTROL tmpfiles"; module = { }; extract = tmpfilesRules; separators = [ newline ]; })
            (run { name = "CONTROL fstab options"; module = poolOn [ "/mnt/d0" "/mnt/d1" ]; extract = fstabOptions; separators = [ "," ]; })
            (run { name = "CONTROL systemd unit list-field"; module = ddnsOn; extract = readWritePaths; separators = [ newline ]; })
            (run { name = "CONTROL /etc/group"; module = { }; extract = groupNames; separators = [ newline ":" ]; })
          ];

          leaking = builtins.filter (p: p.outcome == "LEAKED") injections;
          # A control that was refused, or that found nothing to look at,
          # means the harness above is not exercising the grammar it claims
          # to -- which would make every "eval-refused" beside it worthless.
          brokenControls = builtins.filter
            (c: c.outcome != "no-separator-in-output" || c.records == [ ])
            controls;
        in
        {
          ok = leaking == [ ] && brokenControls == [ ];
          leaking = map (p: { inherit (p) name leaked; }) leaking;
          brokenControls = map (c: { inherit (c) name outcome; recordCount = builtins.length c.records; }) brokenControls;
          outcomes = map (p: "${p.name}: ${p.outcome}") (injections ++ controls);
        };

      # EVERY pool branch carries the whole TRaSH tree, not just the first.
      #
      # `modules/core/storage.nix` seeds the tree on each branch rather than
      # only on mediaDir, and the reason is mergerfs' default create policy.
      # `epmfs` means "existing path, most free space": it will only place a
      # new file on a branch that ALREADY has the parent directory. Seed the
      # tree on one disk and that disk is the only candidate forever -- a
      # fresh multi-disk install puts the entire library on one disk, and a
      # disk added later stays inert. That was a real defect here, fixed in
      # `0993b7b`, and nothing pinned it afterwards.
      #
      # It is the same shape as every other pairing this file guards: two
      # things that must agree, with no mechanical check between them. The
      # expected subdirectory list is deliberately NOT written out here --
      # it is derived from the generated rules for the first branch, and the
      # other branches are required to match it. A hardcoded copy would be a
      # third list to drift, and it would keep passing while storage.nix
      # stopped seeding anything at all.
      poolBranchesAreAllSeeded =
        let
          branches = [ "/mnt/ferrum-check-a" "/mnt/ferrum-check-b" "/mnt/ferrum-check-c" ];
          host = ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              storage.pool = { enable = true; inherit branches; };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          rules = host.config.systemd.tmpfiles.rules;

          # The subpaths a given root is seeded with, read off the GENERATED
          # rules rather than off the option tree -- the same discipline the
          # separator checks use, and for the same reason: the generated text
          # is what the host actually acts on.
          seededUnder = root:
            let
              prefix = "d ${root}/";
              width = builtins.stringLength prefix;
              mine = builtins.filter (r: builtins.substring 0 width r == prefix) rules;
              subpathOf = r:
                builtins.head (lib.splitString " " (builtins.substring width 9999 r));
            in
            lib.naturalSort (map subpathOf mine);

          perBranch = map (b: { branch = b; subpaths = seededUnder b; }) branches;
          expected = (builtins.head perBranch).subpaths;
          divergent = builtins.filter (b: b.subpaths != expected) perBranch;
        in
        {
          # The length floor is the anti-vacuity half. Without it this check
          # passes triumphantly when storage.nix seeds NOTHING, because three
          # empty lists agree with each other perfectly.
          ok = divergent == [ ] && builtins.length expected >= 5;
          seededPerBranch = map (b: { inherit (b) branch; count = builtins.length b.subpaths; }) perBranch;
          divergentBranches = map (b: b.branch) divergent;
          expectedCount = builtins.length expected;
        };

      # modules/core/pool.nix's own assertions must be able to FIRE.
      #
      # Both of them used to live inside `lib.mkIf (pool.enable &&
      # pool.branches != [ ])`, which meant the one configuration they most
      # needed to refuse was the one that switched them off. Measured
      # against the module at 03d569f: `pool.enable = true` with `branches =
      # [ ]` evaluated with failedAssertions = [] and NO entry at all for
      # mediaDir in config.fileSystems -- an operator told the host to pool
      # its disks, was told nothing, and got a single-disk host writing the
      # library to the OS disk.
      #
      # Written against the GENERATED filesystem rather than the options,
      # because "is there a pool on this host" is a question about
      # config.fileSystems, and an options-level check would have passed on
      # the broken module too (pool.enable really was `true`; that was the
      # whole problem).
      #
      # The anti-vacuity half is the `working` case, and it is load-bearing
      # in both directions: it pins that a legitimate two-branch pool is NOT
      # refused (an assertion that fires on everything protects nothing) and
      # that it really does produce a fuse.mergerfs mount (so the
      # "mediaFsType == null" evidence in the other rows means something).
      poolAssertionsCanFire =
        let
          hostWith = pool: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              storage.pool = pool;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          probe = pool:
            let
              cfg = (hostWith pool).config;
              r = builtins.tryEval {
                failed = map (a: a.message) (builtins.filter (a: !a.assertion) cfg.assertions);
                mediaFsType = cfg.fileSystems.${cfg.ferrum.storage.mediaDir}.fsType or null;
              };
            in
            if r.success then r.value else { failed = [ "evaluation threw" ]; mediaFsType = null; };

          # Scoped to the ONE message each case is supposed to produce, and
          # to a phrase that message keeps on a single line.
          #
          # Both halves of that are load-bearing and both were got wrong
          # while writing this. An unscoped "was anything rejected" passes
          # identically with these assertions deleted and some unrelated
          # assertion failing instead. A filter on "ferrum.storage.pool"
          # looks correctly scoped and silently misses the
          # mediaDir-is-a-branch message, whose first line names
          # ferrum.storage.mediaDir and never spells the pool option at all
          # -- which made this check report that assertion as dead when it
          # was working. And an infix spanning a line break never matches at
          # all, because these are multi-line Nix strings.
          failuresMatching = phrase: p:
            builtins.filter (m: lib.hasInfix phrase m) (probe p).failed;
          emptyPhrase = "is on and ferrum.storage.pool.branches";
          singlePhrase = "A pool of one disk is a mount";
          selfBranchPhrase = "is also listed as a pool";
          anyPoolFailure = p:
            lib.concatMap (phrase: failuresMatching phrase p)
              [ emptyPhrase singlePhrase selfBranchPhrase ];

          empty = { enable = true; branches = [ ]; };
          single = { enable = true; branches = [ "/mnt/ferrum-check-a" ]; };
          selfBranch = {
            enable = true;
            branches = [ "/mnt/ferrum-check-a" "/data" ];
          };
          working = {
            enable = true;
            branches = [ "/mnt/ferrum-check-a" "/mnt/ferrum-check-b" ];
          };

          emptyRejected = failuresMatching emptyPhrase empty != [ ];
          # The defect's signature, kept as evidence rather than inferred:
          # the empty-branch host has no pool filesystem at all.
          emptyHasNoPool = (probe empty).mediaFsType == null;
          singleRejected = failuresMatching singlePhrase single != [ ];
          selfBranchRejected = failuresMatching selfBranchPhrase selfBranch != [ ];
          workingAccepted = anyPoolFailure working == [ ];
          workingIsAPool = (probe working).mediaFsType == "fuse.mergerfs";
        in
        {
          ok = emptyRejected
            && emptyHasNoPool
            && singleRejected
            && selfBranchRejected
            && workingAccepted
            && workingIsAPool;
          message =
            "modules/core/pool.nix's assertions do not fire on a pool "
            + "configuration they are supposed to refuse";
          inherit emptyRejected emptyHasNoPool singleRejected selfBranchRejected
            workingAccepted workingIsAPool;
        };

      # R1. A parity disk must never also be a pool branch, and the check
      # that says so must fire on EVERY evaluation rather than only at
      # install time.
      #
      # The hazard is specific and silent. crates/ferrum-install/src/
      # render.rs's `data_disks` detects data disks rather than asking for
      # them -- "every disk that is not the one being erased and that already
      # carries a filesystem" -- so a parity disk that was formatted in
      # advance (which SnapRAID's content file needs) is swept into the pool
      # by construction. Nothing downstream reports that: the pool mounts,
      # the apps write to it, and SnapRAID writes a parity file across the
      # same disk. The library files that land there are then the only ones
      # on the host with no parity at all, and the parity is invalidated by
      # the writes landing beside it.
      #
      # Read off the REAL assertion list of a really-evaluated host, with
      # each case scoped to the one message it is supposed to produce. Both
      # halves of that scoping are load-bearing and this project has been
      # bitten by getting either wrong: an unscoped "was anything rejected"
      # passes identically with these assertions deleted and some unrelated
      # assertion failing instead, and an infix spanning a line break never
      # matches at all, because these are multi-line Nix strings.
      #
      # The anti-vacuity halves are `working` and `off`, and they are what
      # stop this check passing on a module that refuses everything or
      # generates nothing: a legitimate disjoint configuration must evaluate
      # with no parity failure AND produce a real services.snapraid.enable =
      # true, while a host with parity off must produce no snapraid
      # configuration at all.
      #
      # NOT covered here, deliberately, and it is not an omission: naming the
      # OS disk itself (`parity.disks = [ "/" ]`) is refused one layer
      # earlier by hostnames.absolutePath, whose pattern requires at least
      # one `/<segment>`. Evaluation stops at the type, so an assertion for
      # it could never fire. `osDiskRefused` below pins that the refusal
      # really happens rather than taking it on trust.
      parityDiskIsNeverAPoolBranch =
        let
          branches = [ "/mnt/ferrum-check-a" "/mnt/ferrum-check-b" ];
          pooled = { enable = true; inherit branches; };

          hostWith = storage: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              inherit storage;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };

          # deepSeq inside the tryEval: tryEval alone forces only to WHNF, so
          # an error raised while evaluating a field of this attrset escapes
          # the catch entirely and takes the whole check down instead of
          # being reported. Measured, not assumed -- the first version of
          # this probe died on the `/` case rather than catching it.
          probe = storage:
            let
              v = {
                failed = map (a: a.message)
                  (builtins.filter (a: !a.assertion) (hostWith storage).config.assertions);
                snapraidEnabled = (hostWith storage).config.services.snapraid.enable;
              };
              r = builtins.tryEval (builtins.deepSeq v v);
            in
            if r.success then r.value // { threw = false; }
            else { failed = [ ]; snapraidEnabled = false; threw = true; };

          failuresMatching = phrase: storage:
            builtins.filter (m: lib.hasInfix phrase m) (probe storage).failed;

          overlapPhrase = "both contain";
          emptyPhrase = "is on and";
          reservedPhrase = "is equal to,";
          anyParityFailure = storage:
            lib.concatMap (phrase: failuresMatching phrase storage)
              [ overlapPhrase emptyPhrase reservedPhrase ];

          overlap = { pool = pooled; parity = { enable = true; disks = [ "/mnt/ferrum-check-b" ]; }; };
          emptyDisks = { pool = pooled; parity = { enable = true; disks = [ ]; }; };
          reserved = { pool = pooled; parity = { enable = true; disks = [ "/data" ]; }; };
          osDisk = { pool = pooled; parity = { enable = true; disks = [ "/" ]; }; };
          working = { pool = pooled; parity = { enable = true; disks = [ "/mnt/ferrum-parity-0" ]; }; };
          off = { pool = pooled; };

          overlapRejected = failuresMatching overlapPhrase overlap != [ ];
          emptyRejected = failuresMatching emptyPhrase emptyDisks != [ ];
          reservedRejected = failuresMatching reservedPhrase reserved != [ ];
          osDiskRefused = (probe osDisk).threw;
          workingAccepted = anyParityFailure working == [ ];
          workingIsConfigured = (probe working).snapraidEnabled;
          offConfiguresNothing = !(probe off).snapraidEnabled;
          emptyConfiguresNothing = !(probe emptyDisks).snapraidEnabled;

          # "Fires on EVERY evaluation, not only at first install."
          #
          # There is no first-install/later distinction to exercise
          # directly: a NixOS assertion is read on every `nixos-rebuild`,
          # full stop. What can drift, and what this pins, is WHERE the
          # assertion reads its inputs from. An assertion written against
          # the settings document would catch the installer's output and
          # miss an operator who later adds the branch from
          # /etc/ferrum/custom/, and vice versa. So the same overlap is
          # introduced the OTHER way -- through an ordinary NixOS module
          # layered on top, which is what /etc/ferrum/custom/*.nix is -- and
          # must produce the identical refusal.
          overlapViaModule =
            let
              host = ferrumLib.mkHost {
                inherit system;
                settings = {
                  schemaVersion = realMigrations.currentVersion;
                  storage.pool = pooled;
                };
                modules = [
                  ../../../examples/hosts/minimal/configuration.nix
                  { ferrum.storage.parity = { enable = true; disks = [ "/mnt/ferrum-check-b" ]; }; }
                ];
              };
              v = map (a: a.message) (builtins.filter (a: !a.assertion) host.config.assertions);
              r = builtins.tryEval (builtins.deepSeq v v);
            in
            if r.success then builtins.filter (m: lib.hasInfix overlapPhrase m) r.value != [ ]
            else false;
        in
        {
          ok = overlapRejected
            && emptyRejected
            && reservedRejected
            && osDiskRefused
            && workingAccepted
            && workingIsConfigured
            && offConfiguresNothing
            && emptyConfiguresNothing
            && overlapViaModule;
          message =
            "modules/core/parity.nix does not keep a parity disk out of the "
            + "mergerfs pool, or refuses a configuration it should accept";
          inherit overlapRejected emptyRejected reservedRejected osDiskRefused
            workingAccepted workingIsConfigured offConfiguresNothing
            emptyConfiguresNothing overlapViaModule;
        };

      # R2. The SnapRAID exclude list is computed from ferrum's own resolved
      # storage options, and it is written in the ONE path grammar SnapRAID
      # actually reads.
      #
      # THE GRAMMAR IS THE WHOLE POINT, and it is not the obvious one. A
      # SnapRAID `exclude` path is relative to EACH data disk's own root, not
      # absolute on the host. Measured against snapraid 12.4 on real
      # loop-mounted ext4 disks: the per-branch absolute form
      # (`/mnt/ferrum-disk-0/torrents/**`) excluded NOTHING -- all seven
      # files, downloads included, were taken into the array -- because it is
      # read as `<disk>/mnt/ferrum-disk-0/torrents/**` and matches nothing
      # that exists. The `/torrents/**` glob form also failed (five taken).
      # Only `/torrents/` -- the trailing-slash directory form asserted here
      # -- left exactly the two media/ files.
      #
      # That failure is silent and inverted, which is why it is worth a check
      # rather than a comment: the host still syncs, still reports success,
      # and still says it is protected, while spending every sync on exactly
      # the churn the exclusion existed to skip.
      #
      # Read off the GENERATED /etc/snapraid.conf as well as the option,
      # because the option is an intermediate and the file is what snapraid
      # parses -- the same discipline the separator checks use.
      #
      # The anti-vacuity halves: `media/` must NEVER appear (an exclude list
      # that excluded the library would pass a pure "does torrents appear"
      # test while destroying the feature), and the default list must be
      # exactly the expected set rather than a superset -- an unconstrained
      # "contains" test passes identically on a list that excludes
      # everything.
      parityExcludesOnlyTheChurn =
        let
          branches = [ "/mnt/ferrum-check-a" "/mnt/ferrum-check-b" ];
          pooled = { enable = true; inherit branches; };
          withParity = { enable = true; disks = [ "/mnt/ferrum-parity-0" ]; };

          hostWith = storage: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              inherit storage;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };

          excludesOf = storage: (hostWith storage).config.services.snapraid.exclude;
          confOf = storage:
            (hostWith storage).config.environment.etc."snapraid.conf".text;

          defaultHost = { pool = pooled; parity = withParity; };
          defaultExcludes = excludesOf defaultHost;

          # The exact set a default two-branch host must produce. Spelled out
          # rather than recomputed from the module, which would make this
          # check agree with any implementation including a broken one.
          expected = [
            "*.unrecoverable"
            "/snapraid.content"
            "/torrents/"
            "/usenet/"
          ];

          # The trailing-slash directory form, asserted against the file
          # snapraid actually parses.
          conf = confOf defaultHost;
          confHasDirForm =
            lib.hasInfix "\nexclude /torrents/\n" conf
            && lib.hasInfix "\nexclude /usenet/\n" conf;

          # No entry anywhere may be an absolute host path: that is the form
          # that silently matches nothing. Every branch prefix is checked,
          # against every entry.
          absoluteEntries = builtins.filter
            (e: lib.any (b: lib.hasPrefix b e) branches)
            defaultExcludes;

          # media/ is the content parity exists for.
          mediaExcluded = builtins.filter (e: lib.hasInfix "media" e) defaultExcludes;

          # Relocating ONE of the three ferrum roots under a branch must add
          # exactly that one's entry, named relative to the branch -- and
          # must not add the other two.
          relocated = attr: value:
            excludesOf ({ pool = pooled; parity = withParity; } // { ${attr} = value; });
          stateMoved = relocated "stateDir" "/mnt/ferrum-check-a/ferrum-state";
          snapsMoved = relocated "snapshotDir" "/mnt/ferrum-check-a/ferrum-snaps";
          journalMoved = relocated "journalDir" "/mnt/ferrum-check-b/ferrum-journal";

          added = moved: lib.subtractLists defaultExcludes moved;
          stateAdded = added stateMoved == [ "/ferrum-state/" ];
          snapsAdded = added snapsMoved == [ "/ferrum-snaps/" ];
          journalAdded = added journalMoved == [ "/ferrum-journal/" ];

          # And the control for all three: with every root at its default,
          # OUTSIDE any branch, none of them contributes an entry. Without
          # this, an implementation that unconditionally emitted all three
          # would satisfy every assertion above.
          defaultsContributeNothing =
            builtins.filter (e: lib.hasInfix "ferrum" e) defaultExcludes == [ ];

          # An unpooled single-data-disk host protects mediaDir itself, and
          # must still get the churn excluded.
          unpooled = excludesOf { parity = withParity; };
        in
        {
          ok = lib.naturalSort defaultExcludes == lib.naturalSort expected
            && confHasDirForm
            && absoluteEntries == [ ]
            && mediaExcluded == [ ]
            && stateAdded
            && snapsAdded
            && journalAdded
            && defaultsContributeNothing
            && lib.naturalSort unpooled == lib.naturalSort expected;
          message =
            "modules/core/parity.nix's SnapRAID exclude list is not the churn "
            + "of ferrum's own layout, or is written in a path form snapraid "
            + "does not match";
          inherit defaultExcludes confHasDirForm absoluteEntries mediaExcluded
            stateAdded snapsAdded journalAdded defaultsContributeNothing unpooled;
        };

      # R3. Both parity timers are generated in the self-healing shape, both
      # are independently disablable, and both units are deprioritized below
      # anything a person is waiting for.
      #
      # WHAT THE UPSTREAM MODULE ACTUALLY DOES, read out of the pinned
      # nixpkgs rather than assumed: `services.snapraid` schedules its two
      # units with `startAt`, which is sugar for a bare `OnCalendar` (01:00
      # for sync, Mon 02:00 for scrub) and nothing else. There is no
      # `OnBootSec`, no `Persistent`, and no per-unit enable. On a host that
      # is not always on -- which a home media server frequently is not -- a
      # calendar time that came due while the machine was asleep is simply
      # missed, and the array stays unprotected until the same hour comes
      # round again. So ferrum replaces the timerConfig outright.
      #
      # `mkForce` is required rather than stylistic: `startAt` has already
      # written OnCalendar into the same attribute set, and a merge would
      # leave a timer that fires on the interval AND at 01:00 -- which is
      # neither setting's meaning. This check is what holds that, by
      # asserting OnCalendar is absent from the generated timerConfig.
      #
      # The anti-vacuity halves: the default host must HAVE both timers (so
      # the field assertions are about something), the disabled host must
      # have both suppressed, and the parity-off host must generate neither
      # unit at all. Without the last one, every assertion here would pass
      # against a module that generates nothing anywhere.
      parityTimersSelfHeal =
        let
          branches = [ "/mnt/ferrum-check-a" "/mnt/ferrum-check-b" ];
          base = { enable = true; disks = [ "/mnt/ferrum-parity-0" ]; };

          hostWith = parity: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              storage = {
                pool = { enable = true; inherit branches; };
                inherit parity;
              };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };

          cfgOf = parity: (hostWith parity).config;

          # Read off systemd.units, which is what actually reaches the
          # generation: `systemd.timers.<n>.enable = false` leaves the entry
          # in `systemd.timers` and only clears it here. An options-level
          # check would have passed on a module that disabled nothing.
          timerEnabled = parity: name:
            (cfgOf parity).systemd.units."${name}.timer".enable or null;
          timerExists = parity: name:
            (cfgOf parity).systemd.units ? "${name}.timer";
          timerCfg = parity: name:
            (cfgOf parity).systemd.timers.${name}.timerConfig or { };
          ioClass = parity: name:
            (cfgOf parity).systemd.services.${name}.serviceConfig.IOSchedulingClass or null;

          defaults = base;
          customInterval = base // {
            sync.intervalMinutes = 180;
            scrub.intervalMinutes = 20160;
          };
          disabled = base // { sync.enable = false; scrub.enable = false; };
          syncOnly = base // { scrub.enable = false; };
          off = { enable = false; disks = [ ]; };

          # The three fields modules/proxy/dns.nix's self-healing timer
          # carries, and the one that must NOT survive the override.
          selfHealing = name:
            let t = timerCfg defaults name; in
            (t ? OnBootSec) && (t ? OnUnitActiveSec) && (t.Persistent or false) == true
            && !(t ? OnCalendar);

          intervalIsTheOption =
            (timerCfg customInterval "snapraid-sync").OnUnitActiveSec or null == "180min"
            && (timerCfg customInterval "snapraid-scrub").OnUnitActiveSec or null == "20160min";

          # Two DISTINCT units with independent schedules, not one timer
          # driving both.
          twoDistinctSchedules =
            (timerCfg defaults "snapraid-sync").OnUnitActiveSec or null
            != (timerCfg defaults "snapraid-scrub").OnUnitActiveSec or null
            && (timerCfg defaults "snapraid-sync").Unit or null == "snapraid-sync.service"
            && (timerCfg defaults "snapraid-scrub").Unit or null == "snapraid-scrub.service";

          # The sync unit records WHERE ferrum-apply looks.
          #
          # Two files name this path independently -- `LAST_SYNC_FILE` in
          # crates/ferrum-apply/src/parity.rs, which READS it, and
          # modules/core/parity.nix's `parityStateDir`, whose ExecStopPost
          # WRITES it -- and nothing else holds them together. The drift is
          # silent in the worst direction: a host whose Nix side moved would
          # keep syncing happily while every status surface reported "never
          # synced" forever, because the reader is looking at a path nothing
          # writes any more. So the path is read out of the Rust constant and
          # asserted against the GENERATED unit and tmpfiles rules.
          lastSyncDir =
            let
              src = builtins.readFile ../../../crates/ferrum-apply/src/parity.rs;
              hits = builtins.filter builtins.isList
                (builtins.split "pub const LAST_SYNC_FILE: &str = \"([^\"]+)\"" src);
            in
            if hits == [ ] then
              throw ("crates/ferrum-apply/src/parity.rs no longer declares LAST_SYNC_FILE as a "
                + "string literal, so parity-timers-self-heal cannot check that the unit "
                + "writes where the reader looks")
            else dirOf (builtins.head (builtins.head hits));

          syncWritesWhereTheReaderLooks =
            let cfg = cfgOf defaults; in
            builtins.elem lastSyncDir
              (cfg.systemd.services.snapraid-sync.serviceConfig.ReadWritePaths or [ ])
            && builtins.any (r: lib.hasInfix "d ${lastSyncDir} " r) cfg.systemd.tmpfiles.rules
            && (cfg.systemd.services.snapraid-sync.serviceConfig.ExecStopPost or null) != null;
        in
        {
          ok = selfHealing "snapraid-sync"
            && selfHealing "snapraid-scrub"
            && intervalIsTheOption
            && twoDistinctSchedules
            && timerEnabled defaults "snapraid-sync" == true
            && timerEnabled defaults "snapraid-scrub" == true
            && timerEnabled disabled "snapraid-sync" == false
            && timerEnabled disabled "snapraid-scrub" == false
            # Independently disablable, not one switch for both.
            && timerEnabled syncOnly "snapraid-sync" == true
            && timerEnabled syncOnly "snapraid-scrub" == false
            && ioClass defaults "snapraid-sync" == "idle"
            && ioClass defaults "snapraid-scrub" == "idle"
            # A host with both timers off still HAS the units, which is what
            # makes `ferrum-apply parity-sync` work there.
            && timerExists disabled "snapraid-sync"
            && !(timerExists off "snapraid-sync")
            && !(timerExists off "snapraid-scrub")
            && syncWritesWhereTheReaderLooks;
          message =
            "modules/core/parity.nix's timers are not in the self-healing shape "
            + "modules/proxy/dns.nix uses, are not independently disablable, or "
            + "are not deprioritized";
          syncTimer = timerCfg defaults "snapraid-sync";
          scrubTimer = timerCfg defaults "snapraid-scrub";
          disabledSyncEnabled = timerEnabled disabled "snapraid-sync";
          disabledScrubEnabled = timerEnabled disabled "snapraid-scrub";
          syncOnlyScrubEnabled = timerEnabled syncOnly "snapraid-scrub";
          inherit intervalIsTheOption twoDistinctSchedules;
          syncIo = ioClass defaults "snapraid-sync";
          scrubIo = ioClass defaults "snapraid-scrub";
          offHasTimers = timerExists off "snapraid-sync";
          inherit lastSyncDir syncWritesWhereTheReaderLooks;
        };

      # R4. The parity view renders every state the producer can send, the
      # envelope ferrumd actually constructs, and the limitation sentence.
      #
      # Three files have to agree and nothing but this holds them together:
      # crates/ferrum-apply/src/parity.rs owns the state vocabulary,
      # crates/ferrumd/src/parity.rs owns the envelope, and ui/app.js
      # transcribes both. A state the daemon can send with no branch in the UI
      # renders as a blank tile, and a blank tile where "Protected" belongs is
      # indistinguishable from a blank tile where "a parity disk is missing"
      # belongs -- which is the whole failure this requirement exists to
      # prevent. Modelled directly on `updates-view-is-wired`, which exists
      # because exactly that drift happened on the first day the update files
      # lived apart.
      #
      # Every lookup throws rather than returning an empty list when it cannot
      # find what it guards. A check that cannot find its subject must fail,
      # not pass -- this repository shipped three checks in one week that
      # could not fail, and a vacuous list comparison is how two of them got
      # that way.
      parityViewIsWired =
        let
          appSrc = builtins.readFile ../../../ui/app.js;
          lines = lib.splitString "\n" appSrc;
          rustLines = lib.splitString "\n"
            (builtins.readFile ../../../crates/ferrum-apply/src/parity.rs);
          daemonLines = lib.splitString "\n"
            (builtins.readFile ../../../crates/ferrumd/src/parity.rs);
          indexHtml = builtins.readFile ../../../ui/index.html;

          indexIn = src: file: what: infix:
            let
              hits = builtins.filter (e: lib.hasInfix infix e.l)
                (lib.imap0 (i: l: { inherit i l; }) src);
            in
            if hits == [ ] then
              throw (file + " no longer has a line containing '" + infix
                + "', so parity-view-is-wired cannot verify " + what
                + ". A check that cannot find what it guards must fail, not pass.")
            else (builtins.head hits).i;

          blockIn = src: file: what: startInfix: isEnd:
            let
              after = lib.drop ((indexIn src file what startInfix) + 1) src;
              take = acc: rest:
                if rest == [ ] then
                  throw (file + " opens '" + startInfix
                    + "' but parity-view-is-wired cannot find the line that closes it")
                else if isEnd (builtins.head rest) then acc
                else take (acc ++ [ (builtins.head rest) ]) (builtins.tail rest);
              block = take [ ] after;
            in
            if block == [ ] then
              throw (file + "'s '" + startInfix + "' block is empty, so every assertion "
                + "parity-view-is-wired makes about " + what + " would be vacuously true")
            else block;

          quotedIn = re: line:
            map builtins.head (builtins.filter builtins.isList (builtins.split re line));

          # A one-line `const NAME = ["a", "b"];` declaration in ui/app.js.
          vocabOf = what: name:
            let
              values = quotedIn "\"([a-zA-Z][a-zA-Z0-9-]*)\""
                (builtins.elemAt lines (indexIn lines "ui/app.js" what "const ${name} = ["));
            in
            if values == [ ] then
              throw ("ui/app.js declares " + name + " but parity-view-is-wired read no names "
                + "out of it -- it is no longer a single-line array literal, and an empty "
                + "vocabulary would make the branch-coverage assertion vacuous")
            else values;

          # The keys of a one-entry-per-line state table.
          branchesOf = what: name:
            let
              keys = lib.concatMap (quotedIn "\"([a-z-]+)\":")
                (blockIn lines "ui/app.js" what "const ${name} = {" (l: l == "};"));
            in
            if keys == [ ] then
              throw ("ui/app.js declares " + name
                + " but parity-view-is-wired found no \"state\": keys in it")
            else keys;

          uiStates = vocabOf "the parity-state vocabulary" "PARITY_STATES";
          uiBranches = branchesOf "parity-state rendering" "PARITY_STATE_TEXT";

          # The producer's own enum, read out of its `#[serde(rename_all =
          # "kebab-case")] pub enum ParityState` block. This is what turns the
          # UI's list from a transcription into an invariant.
          rustVariants =
            let
              block = blockIn rustLines "crates/ferrum-apply/src/parity.rs"
                "the ParityState variants" "pub enum ParityState {" (l: l == "}");
              # One CamelCase variant per non-comment, non-blank line.
              names = lib.concatMap
                (l:
                  let t = lib.removeSuffix "," (lib.trim l); in
                  if t == "" || lib.hasPrefix "/" t then [ ]
                  else if builtins.match "[A-Z][A-Za-z]*" t != null then [ t ]
                  else [ ])
                block;
              kebab = name:
                let
                  chars = lib.stringToCharacters name;
                  piece = i: c:
                    if i == 0 then lib.toLower c
                    else if c == lib.toUpper c && c != lib.toLower c then "-${lib.toLower c}"
                    else c;
                in
                lib.concatStrings (lib.imap0 piece chars);
            in
            if names == [ ] then
              throw ("crates/ferrum-apply/src/parity.rs declares ParityState but "
                + "parity-view-is-wired read no variants out of it")
            else map kebab names;

          # The envelope keys and statuses ferrumd really constructs.
          daemonHasStatus = s:
            builtins.any (l: lib.hasInfix "\"status\": \"${s}\"" l) daemonLines;
          uiEnvelopeStatuses = vocabOf "the envelope statuses" "PARITY_ENVELOPE_STATUSES";
          uiEnvelopeKeys = vocabOf "the envelope keys" "PARITY_ENVELOPE_KEYS";

          missing = builtins.filter (s: !(builtins.elem s uiBranches)) uiStates;
          extra = builtins.filter (s: !(builtins.elem s uiStates)) uiBranches;
          uiMissesRust = builtins.filter (s: !(builtins.elem s uiStates)) rustVariants;
          rustMissesUi = builtins.filter (s: !(builtins.elem s rustVariants)) uiStates;
          statusDrift = builtins.filter (s: !(daemonHasStatus s)) uiEnvelopeStatuses;
          keyDrift = builtins.filter
            (k: !(builtins.any (l: lib.hasInfix "\"${k}\":" l) daemonLines))
            uiEnvelopeKeys;

          # R6, mechanically. The limitation sentence lives in the producer and
          # the UI renders whatever it sends, so what has to be true here is
          # that the UI does NOT write its own, and that no new surface says
          # "backup".
          renderedFromReport = builtins.any
            (l: lib.hasInfix "orUnknown(report.limitation)" l) lines;

          # The one word this feature may never use about parity, scanned
          # across the text an operator actually reads.
          #
          # SCOPED TO RENDERED TEXT, NOT TO SOURCE, and the scoping is the
          # whole difficulty rather than a convenience. The first version of
          # this scanned whole files and failed immediately -- on the comment
          # explaining why the word is forbidden, and on the unit test that
          # asserts its absence. A scan that cannot tell "says it" from
          # "forbids it" reports the rule being enforced as a violation of
          # itself, and the only way to make it pass would have been to stop
          # writing the rule down.
          #
          # So: the parity view's own block, with comment lines dropped, which
          # is exactly the strings the browser renders; and the `LIMITATION`
          # constant, which every other surface takes its words from. The
          # `nixpkgs` module path (nixos/modules/services/BACKUP/snapraid.nix)
          # is upstream's filing decision and is deliberately out of scope --
          # it is not a surface ferrum shows anybody.
          parityViewBlock =
            blockIn lines "ui/app.js" "the parity view's rendered text"
              "// --- parity ---" (l: lib.hasPrefix "// --- routing" l);
          isComment = l: let t = lib.trim l; in lib.hasPrefix "//" t || lib.hasPrefix "/*" t;
          limitationLines =
            blockIn rustLines "crates/ferrum-apply/src/parity.rs"
              "the limitation sentence" "pub const LIMITATION: &str =" (l: lib.hasSuffix "\";" l);
          backupMentions =
            builtins.filter (l: lib.hasInfix "backup" (lib.toLower l))
              (builtins.filter (l: !(isComment l)) parityViewBlock ++ limitationLines);

          # The nav is hand-written and NOT generated from app.js's `routes`
          # map, so a view can exist and be unreachable.
          navLinked = lib.hasInfix "href=\"#/parity\"" indexHtml;
          routeDeclared = builtins.any (l: lib.hasInfix "\"#/parity\": parityView" l) lines;
        in
        {
          ok = missing == [ ]
            && extra == [ ]
            && uiMissesRust == [ ]
            && rustMissesUi == [ ]
            && statusDrift == [ ]
            && keyDrift == [ ]
            && renderedFromReport
            && backupMentions == [ ]
            && navLinked
            && routeDeclared
            && builtins.length uiStates >= 8;
          message =
            "ui/app.js's parity view is out of step with the state vocabulary "
            + "crates/ferrum-apply/src/parity.rs owns or the envelope "
            + "crates/ferrumd/src/parity.rs constructs";
          inherit missing extra uiMissesRust rustMissesUi statusDrift keyDrift
            renderedFromReport backupMentions navLinked routeDeclared;
          stateCount = builtins.length uiStates;
        };

      # R6. The product says "parity is not a backup" itself, on the surfaces
      # an operator actually reads -- and never the reverse.
      #
      # THE SCAN HAS TO BE SHAPED, NOT A WORD BAN, and getting that wrong is
      # the obvious mistake rather than a subtle one. A check that simply
      # forbade the word "backup" anywhere would fail on the heading "Parity
      # is not a backup" -- which is the exact sentence this requirement
      # exists to make the product say. It would also fail on the restore
      # procedure's instruction to use a real backup when both a data disk
      # and the parity disk are gone, which is the most important advice on
      # that page. The only way to make that version pass would be to delete
      # the writing. (`parity-view-is-wired` already learned this once, on
      # its own first run.)
      #
      # So two different assertions over two different shapes:
      #
      #   1. REQUIRED. The operator documentation must carry the disclaimer
      #      and the specific things parity does not survive. This is the
      #      same required-phrase shape the stale-comment scan uses.
      #   2. FORBIDDEN. No surface may AFFIRM it -- the handful of phrasings
      #      that would actually claim parity is a backup, matched
      #      case-insensitively, across the doc and every parity prose
      #      surface. Scanning for claims rather than for a word is what lets
      #      the denial and the claim be told apart.
      # R29 + ROAD item 8's first slice. The app detail view renders every
      # VPN state the daemon can send, reads its integration edges rather
      # than re-deriving them, and cannot read a secret back.
      #
      # Four files have to agree here and, as with the Updates and Parity
      # screens before it, nothing but this holds them together:
      # crates/ferrumd/src/vpn.rs owns the state vocabulary and the envelope,
      # modules/lib/integrations.nix owns the registration-kind rule,
      # nix/modules/flake/packages.nix is what actually puts the computed
      # edges into the document the browser reads, and ui/app.js transcribes
      # all of it. Modelled directly on `updates-view-is-wired` and
      # `parity-view-is-wired`, which exist because exactly that drift
      # happened the first day their files lived apart.
      #
      # The INTEGRATIONS half is the sharp one. The whole reason
      # modules/lib/integrations.nix exists is that "Prowlarr registers
      # Sonarr as an application" was computed in one place and needed in
      # two, and a JavaScript copy of that rule would be the second place --
      # the defect class that produced the nginx/reconciler address split.
      # A rule with exactly one app-specific token is cheap to guard: the
      # token must not appear in the UI at all.
      #
      # Every lookup throws rather than returning an empty result. A check
      # that grepped for a declaration, found nothing, and passed would be
      # worse than no check -- this tree has shipped that twice.
      appDetailViewIsWired =
        let
          lines = lib.splitString "\n" (builtins.readFile ../../../ui/app.js);
          apiLines = lib.splitString "\n" (builtins.readFile ../../../ui/api.js);
          vpnPath = "crates/ferrumd/src/vpn.rs";
          vpnLines = lib.splitString "\n" (builtins.readFile ../../../crates/ferrumd/src/vpn.rs);
          reconcilerSrc = builtins.readFile ../../../modules/core/reconciler.nix;
          packagesSrc = builtins.readFile ../../../nix/modules/flake/packages.nix;
          integrationsSrc = builtins.readFile ../../../modules/lib/integrations.nix;

          # Same helpers as the two checks above. They are restated rather
          # than shared because each one names itself in its own failure
          # messages, and a message that names the wrong check sends the
          # reader to the wrong file.
          indexIn = src: file: what: infix:
            let
              hits = builtins.filter (e: lib.hasInfix infix e.l)
                (lib.imap0 (i: l: { inherit i l; }) src);
            in
            if hits == [ ] then
              throw (file + " no longer has a line containing '" + infix
                + "', so app-detail-view-is-wired cannot verify " + what
                + ". A check that cannot find what it guards must fail, not pass.")
            else (builtins.head hits).i;

          blockIn = src: file: what: startInfix: isEnd:
            let
              after = lib.drop ((indexIn src file what startInfix) + 1) src;
              take = acc: rest:
                if rest == [ ] then
                  throw (file + " opens '" + startInfix
                    + "' but app-detail-view-is-wired cannot find the line that closes it")
                else if isEnd (builtins.head rest) then acc
                else take (acc ++ [ (builtins.head rest) ]) (builtins.tail rest);
              block = take [ ] after;
            in
            if block == [ ] then
              throw (file + "'s '" + startInfix + "' block is empty, so every assertion "
                + "app-detail-view-is-wired makes about " + what + " would be vacuously true")
            else block;

          quotedIn = re: line:
            map builtins.head (builtins.filter builtins.isList (builtins.split re line));

          # A one-line `const NAME = ["a", "b"];` in ui/app.js. The character
          # class admits camelCase as well as kebab: the state words are
          # kebab, the envelope keys are `checkedAt`.
          vocabOf = what: name:
            let
              values = quotedIn "\"([a-zA-Z][a-zA-Z0-9-]*)\""
                (builtins.elemAt lines (indexIn lines "ui/app.js" what "const ${name} = ["));
            in
            if values == [ ] then
              throw ("ui/app.js declares " + name + " but app-detail-view-is-wired read no "
                + "names out of it -- it is no longer a single-line array literal, and an "
                + "empty vocabulary would make the branch-coverage assertion vacuous")
            else values;

          branchesOf = what: name:
            let
              keys = lib.concatMap (quotedIn "\"([a-z-]+)\":")
                (blockIn lines "ui/app.js" what "const ${name} = {" (l: l == "};"));
            in
            if keys == [ ] then
              throw ("ui/app.js declares " + name
                + " but app-detail-view-is-wired found no \"state\": keys in it")
            else keys;

          uiStates = vocabOf "the VPN-state vocabulary" "VPN_STATES";
          uiBranches = branchesOf "VPN-state rendering" "VPN_STATE_TEXT";
          uiEnvelopeKeys = vocabOf "the VPN envelope keys" "VPN_ENVELOPE_KEYS";

          # serde's kebab-case rule, derived rather than hand-listed -- the
          # same derivation `updates-view-is-wired` records in full.
          kebabOf = variant:
            lib.toLower (builtins.concatStringsSep "-"
              (map builtins.head
                (builtins.filter builtins.isList (builtins.split "([A-Z][a-z0-9]*)" variant))));

          # camelCase, for `#[serde(rename_all = "camelCase")]` struct
          # fields: `checked_at` is on the wire as `checkedAt`.
          camelOf = field:
            let parts = lib.splitString "_" field; in
            builtins.concatStringsSep ""
              ([ (builtins.head parts) ] ++ map (p: lib.toUpper (builtins.substring 0 1 p)
                + builtins.substring 1 (builtins.stringLength p) p) (builtins.tail parts));

          # The unit variants of VpnState, as wire values. Same `unparsed`
          # discipline as the other two checks: a body line this cannot read
          # would be dropped from the daemon's set, and the resulting diff
          # would accuse the UI of inventing a state the daemon never sends.
          daemonStates =
            let
              block = blockIn vpnLines vpnPath "ferrumd's VpnState variants"
                "pub enum VpnState {" (l: l == "}");
              variantOf = l: builtins.match "[[:space:]]*([A-Z][A-Za-z0-9]*),[[:space:]]*" l;
              ignorable = l:
                builtins.match "[[:space:]]*" l != null
                || builtins.match "[[:space:]]*(///|//|#\\[).*" l != null;
              names = lib.concatMap (l: let m = variantOf l; in if m == null then [ ] else m) block;
              unparsed = builtins.filter (l: variantOf l == null && !(ignorable l)) block;
            in
            if unparsed != [ ] then
              throw (vpnPath + "'s VpnState has lines app-detail-view-is-wired cannot read as "
                + "unit variants: " + builtins.toJSON unparsed + ". Silently dropping them "
                + "would understate the daemon's vocabulary and blame the UI for the difference.")
            else if names == [ ] then
              throw (vpnPath + " declares VpnState but app-detail-view-is-wired parsed no "
                + "variants out of it")
            else map kebabOf names;

          # The envelope VpnReport really serializes, by the same discipline.
          daemonEnvelopeKeys =
            let
              block = blockIn vpnLines vpnPath "ferrumd's VpnReport fields"
                "pub struct VpnReport {" (l: l == "}");
              fieldOf = l: builtins.match "[[:space:]]*pub ([a-z_]+):.*" l;
              ignorable = l:
                builtins.match "[[:space:]]*" l != null
                || builtins.match "[[:space:]]*(///|//|#\\[).*" l != null;
              names = lib.concatMap (l: let m = fieldOf l; in if m == null then [ ] else m) block;
              unparsed = builtins.filter (l: fieldOf l == null && !(ignorable l)) block;
            in
            if unparsed != [ ] then
              throw (vpnPath + "'s VpnReport has lines app-detail-view-is-wired cannot read as "
                + "fields: " + builtins.toJSON unparsed)
            else if names == [ ] then
              throw (vpnPath + " declares VpnReport but app-detail-view-is-wired parsed no "
                + "fields out of it")
            else map camelOf names;

          daemonOnly = daemon: ui: builtins.filter (v: !(builtins.elem v ui)) daemon;
          uiOnly = daemon: ui: builtins.filter (v: !(builtins.elem v daemon)) ui;
          unbranched = builtins.filter (s: !(builtins.elem s uiBranches)) uiStates;
          orphaned = builtins.filter (b: !(builtins.elem b uiStates)) uiBranches;

          # The detail route exists and really dispatches the detail view.
          # Both halves: a pattern nothing calls, or a call no pattern
          # reaches, each leaves the screen unreachable while looking wired.
          routePatternDeclared =
            builtins.any (l: lib.hasInfix "const APP_DETAIL_ROUTE = " l) lines;
          routeDispatches =
            builtins.any (l: lib.hasInfix "appDetailView(detail[1])" l) lines;

          # The detail view's own source, delimited by the banner comments
          # this file already uses to separate ui/app.js's sections.
          detailBlock = blockIn lines "ui/app.js" "the app detail view's own source"
            "// --- app detail ---" (l: lib.hasPrefix "// --- " l);

          # THE INTEGRATION RULE LIVES IN ONE PLACE. `prowlarr` is the only
          # app-specific token in it, so its absence from the UI's CODE is
          # the cheapest true statement that the UI is not the second place.
          #
          # Comment lines are excluded deliberately, and the distinction is
          # the whole point rather than a loophole: the sentence explaining
          # *why* this rule is not duplicated here names the rule, and a scan
          # that failed on its own rationale would be removed by the next
          # reader instead of being satisfied. `codeLines` is asserted
          # non-empty below, so the exclusion cannot quietly swallow the
          # entire file.
          isComment = l:
            let t = lib.trim l; in
            lib.hasPrefix "//" t || lib.hasPrefix "*" t || lib.hasPrefix "/*" t;
          codeLines = builtins.filter (l: !(isComment l)) lines;
          integrationRuleCopiedIntoTheUi =
            builtins.filter (l: lib.hasInfix "prowlarr" (lib.toLower l)) codeLines;
          # ...and the UI really does read the computed edges.
          readsComputedEdges =
            builtins.any (l: lib.hasInfix "integrationEdges" l) detailBlock;
          # ...and the catalog document really carries them.
          catalogCarriesEdges = lib.hasInfix "integrations.nix" packagesSrc
            && lib.hasInfix "annotate" packagesSrc;
          # ...and the reconciler reads the rule rather than owning a copy.
          reconcilerImportsTheRule =
            lib.hasInfix "integrations.nix" reconcilerSrc
            && !(lib.hasInfix "pairKind = consumer: provider:" reconcilerSrc);
          ruleIsDefinedOnce = lib.hasInfix "pairKind = consumer: provider:" integrationsSrc;

          # No secret may be read back. ui/api.js has one secrets call and it
          # is the POST; the detail view starts no privileged job, because an
          # apply belongs to the Apply screen and a screen that could start
          # one from behind a settings form would apply edits the operator
          # had not reviewed.
          secretCalls = builtins.filter (l: lib.hasInfix "/api/secrets" l) apiLines;
          secretReads = builtins.filter (l: !(lib.hasInfix "\"POST\"" l)) secretCalls;
          jobStartsInDetail = builtins.filter (l: lib.hasInfix "api.startJob(" l) detailBlock;

          # The claim the panel prints to the operator, required verbatim
          # enough that deleting it fails rather than passing quietly. This
          # is the sentence crates/ferrumd's `no_route_can_read_a_secret_back`
          # keeps true; without this half, the test would go on guarding a
          # promise the UI had stopped making.
          panelStatesTheWriteOnlyProperty =
            builtins.any (l: lib.hasInfix "can never read it back" l) detailBlock;
          # And it never implies a liveness the measurement cannot support.
          panelStatesTheLimit =
            builtins.any (l: lib.hasInfix "whether it is carrying traffic" l) detailBlock;
        in
        {
          ok = codeLines != [ ]
            && routePatternDeclared
            && routeDispatches
            && readsComputedEdges
            && catalogCarriesEdges
            && reconcilerImportsTheRule
            && ruleIsDefinedOnce
            && panelStatesTheWriteOnlyProperty
            && panelStatesTheLimit
            && integrationRuleCopiedIntoTheUi == [ ]
            && secretReads == [ ]
            && secretCalls != [ ]
            && jobStartsInDetail == [ ]
            && unbranched == [ ]
            && orphaned == [ ]
            && daemonOnly daemonStates uiStates == [ ]
            && uiOnly daemonStates uiStates == [ ]
            && daemonOnly daemonEnvelopeKeys uiEnvelopeKeys == [ ]
            && uiOnly daemonEnvelopeKeys uiEnvelopeKeys == [ ];

          # Anti-vacuity for the comment exclusion above: if the filter ever
          # ate the whole file, every scan over `codeLines` would agree with
          # an empty expectation and prove nothing.
          theCommentFilterAteTheWholeFile = codeLines == [ ];
          detailRoutePatternMissing = !routePatternDeclared;
          detailRouteNeverDispatched = !routeDispatches;
          uiDoesNotReadComputedIntegrationEdges = !readsComputedEdges;
          catalogDoesNotCarryIntegrationEdges = !catalogCarriesEdges;
          reconcilerStillOwnsItsOwnCopyOfTheRule = !reconcilerImportsTheRule;
          theIntegrationRuleIsDefinedNowhere = !ruleIsDefinedOnce;
          thePanelNoLongerStatesTheWriteOnlyProperty = !panelStatesTheWriteOnlyProperty;
          thePanelNoLongerStatesWhatItCannotMeasure = !panelStatesTheLimit;
          theUiAlsoKnowsTheIntegrationRule = integrationRuleCopiedIntoTheUi;
          apiJsReadsSecretsBack = secretReads;
          apiJsNoLongerWritesSecrets = secretCalls == [ ];
          theDetailViewStartsJobs = jobStartsInDetail;
          vpnStatesWithNoBranch = unbranched;
          vpnBranchesWithNoState = orphaned;
          inherit daemonStates daemonEnvelopeKeys;
          uiVpnStates = uiStates;
          inherit uiEnvelopeKeys;
          vpnStatesTheDaemonSendsAndTheUiLacks = daemonOnly daemonStates uiStates;
          vpnStatesTheUiExpectsAndTheDaemonNeverSends = uiOnly daemonStates uiStates;
          envelopeKeysTheDaemonSendsAndTheUiLacks = daemonOnly daemonEnvelopeKeys uiEnvelopeKeys;
          envelopeKeysTheUiExpectsAndTheDaemonNeverSends = uiOnly daemonEnvelopeKeys uiEnvelopeKeys;
        };

      # The VPN metadata in a catalog meta.nix really names what it claims
      # to: a systemd unit that exists, a sops secret that exists, and a key
      # in that app's own settings schema.
      #
      # It exists because `/api/vpn` reads the unit name out of the CATALOG
      # and asks systemd about it. A typo there does not fail anything --
      # systemd answers "no such unit", and the dashboard reports the tunnel
      # as never applied on a host where it is running perfectly. A status
      # that is wrong in the reassuring direction is worse than no status,
      # and this is the only thing standing between the two files.
      #
      # ANTI-VACUITY, four ways, because every probe here can find nothing
      # and "found nothing" must never read as "found nothing wrong":
      #
      #   a. at least one catalog app must declare a `vpn` block at all;
      #   b. the unit must be found on a host where the VPN IS declared;
      #   c. a CONTROL host without the declaration must NOT have that unit,
      #      which proves the probe is reading a thing the declaration
      #      actually creates rather than something that is always there;
      #   d. the settings-schema key must be read out of a non-empty
      #      property set.
      vpnMetadataMatchesTheUnit =
        let
          vpnApps = lib.filterAttrs (_: meta: meta ? vpn) catalog;

          mkHostWith = extra: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              apps = lib.mapAttrs (_: _: { enable = true; }) catalog;
            };
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
            ] ++ extra;
          };

          # Declaring every VPN secret is what switches each app's tunnel
          # machinery on -- see qbittorrent/service.nix's `vpnEnabled`.
          declared = mkHostWith [{
            ferrum.secrets = lib.mapAttrs' (_: meta: lib.nameValuePair meta.vpn.secret { }) vpnApps;
          }];
          control = mkHostWith [ ];

          unitsOn = host: builtins.attrNames host.config.systemd.services;
          secretsOn = host: builtins.attrNames host.config.sops.secrets;
          # systemd.services is keyed WITHOUT the .service suffix.
          unitKey = unit: lib.removeSuffix ".service" unit;

          missingUnit = lib.mapAttrsToList
            (id: meta:
              if builtins.elem (unitKey meta.vpn.unit) (unitsOn declared) then null
              else "modules/apps/${id}/meta.nix declares vpn.unit \"${meta.vpn.unit}\", but no "
                + "such systemd unit exists on a host with that app enabled and its secret declared")
            vpnApps;
          missingSecret = lib.mapAttrsToList
            (id: meta:
              if builtins.elem meta.vpn.secret (secretsOn declared) then null
              else "modules/apps/${id}/meta.nix declares vpn.secret \"${meta.vpn.secret}\", but "
                + "declaring it in ferrum.secrets creates no sops secret by that name")
            vpnApps;
          missingSetting = lib.mapAttrsToList
            (id: meta:
              let props = meta.settingsSchema.properties or { }; in
              if props == { } then
                "modules/apps/${id}/meta.nix declares a vpn block but its settingsSchema has no "
                + "properties at all, so the vpn.setting assertion would be vacuous"
              else if props ? ${meta.vpn.setting} then null
              else "modules/apps/${id}/meta.nix declares vpn.setting \"${meta.vpn.setting}\", "
                + "which is not a key of its own settingsSchema.properties")
            vpnApps;
          # (c). The unit must be ABSENT without the declaration, or arm (b)
          # is a branch nothing can ever take.
          unitExistsWithoutTheDeclaration = lib.mapAttrsToList
            (id: meta:
              if builtins.elem (unitKey meta.vpn.unit) (unitsOn control) then
                "modules/apps/${id}/service.nix defines ${meta.vpn.unit} even with no VPN secret "
                + "declared, so this check's unit probe proves nothing about the declaration"
              else null)
            vpnApps;

          real = builtins.filter (x: x != null);
        in
        {
          ok = vpnApps != { }
            && real missingUnit == [ ]
            && real missingSecret == [ ]
            && real missingSetting == [ ]
            && real unitExistsWithoutTheDeclaration == [ ];

          noCatalogAppDeclaresAVpn = vpnApps == { };
          unitsThatDoNotExist = real missingUnit;
          secretsThatDoNotExist = real missingSecret;
          settingsKeysThatDoNotExist = real missingSetting;
          unitsPresentWithoutTheirDeclaration = real unitExistsWithoutTheDeclaration;
        };

      parityNeverClaimsToBeABackup =
        let
          doc = builtins.readFile ../../../docs/storage/parity.md;
          rustSrc = builtins.readFile ../../../crates/ferrum-apply/src/parity.rs;
          appSrc = builtins.readFile ../../../ui/app.js;

          required = [
            "Parity is not a backup"
            "undo a deletion"
            "ransomware"
            "the parity disk is **in** that box"
            "rollback` is not this either"
          ];
          missing = builtins.filter (p: !(lib.hasInfix p doc)) required;

          # The claims. Lower-cased on both sides so a capitalised version
          # cannot slip past, and written as whole phrases so the word on its
          # own -- which the denial needs -- is not what is being matched.
          claims = [
            "parity is a backup"
            "parity is your backup"
            "backed up by parity"
            "parity backs up"
            "backup of your library"
            "acts as a backup"
            "serves as a backup"
            "a backup of the"
          ];
          affirmsIn = name: src:
            map (c: "${name}: ${c}")
              (builtins.filter (c: lib.hasInfix c (lib.toLower src)) claims);
          affirmations =
            affirmsIn "docs/storage/parity.md" doc
            ++ affirmsIn "crates/ferrum-apply/src/parity.rs" rustSrc
            ++ affirmsIn "ui/app.js" appSrc
            ++ affirmsIn "modules/core/parity.nix"
              (builtins.readFile ../../../modules/core/parity.nix)
            ++ affirmsIn "modules/core/options.nix"
              (builtins.readFile ../../../modules/core/options.nix);

          # The one constant every other surface takes its words from. If it
          # ever stopped naming the single-disk limit, every surface that
          # renders it would quietly stop saying it too.
          #
          # SCOPED TO THE CONSTANT'S OWN LINES, not to the file. The first
          # version of this searched the whole of parity.rs and survived a
          # mutant that gutted the constant -- because the same phrase also
          # appears in two of that file's TESTS, which assert the constant
          # says it. A check satisfied by the test that checks the thing is
          # a check of nothing.
          limitationBlock =
            let
              indexed = lib.imap0 (i: l: { inherit i l; }) (lib.splitString "\n" rustSrc);
              hits = builtins.filter (e: lib.hasInfix "pub const LIMITATION" e.l) indexed;
            in
            if hits == [ ] then
              throw ("crates/ferrum-apply/src/parity.rs no longer declares LIMITATION, so "
                + "parity-never-claims-to-be-a-backup cannot check what every parity surface "
                + "renders. A check that cannot find what it guards must fail, not pass.")
            else
              let
                after = lib.drop (builtins.head hits).i
                  (lib.splitString "\n" rustSrc);
                take = acc: rest:
                  if rest == [ ] then
                    throw "LIMITATION is declared but its closing `\";` cannot be found"
                  else
                    let head = builtins.head rest; in
                    if lib.hasSuffix "\";" head then acc ++ [ head ]
                    else take (acc ++ [ head ]) (builtins.tail rest);
              in
              lib.concatStringsSep "\n" (take [ ] after);
          limitationIsSpecific = lib.hasInfix "single local disk" limitationBlock;

          # Anti-vacuity: the claim list must actually be capable of matching.
          # Without this, a typo in every entry would make `affirmations`
          # permanently empty and the check permanently, silently green.
          scannerWorks =
            affirmsIn "probe" "Parity is a backup of the whole library." != [ ];
        in
        {
          ok = missing == [ ] && affirmations == [ ] && limitationIsSpecific && scannerWorks;
          message =
            "the parity surfaces no longer state that parity is not a backup, "
            + "or one of them now claims it is";
          inherit missing affirmations limitationIsSpecific scannerWorks;
        };

      # The self-signed certificate follows ferrum.proxy.baseDomain.
      #
      # Its CN and both SANs are built from that option, and the unit that
      # generates it used to be gated on `ConditionPathExists =
      # "!<certDir>/cert.pem"` -- "is there a certificate", never "is it the
      # right one". So changing baseDomain, which is one field in the
      # settings UI, left every lan-exposure vhost and (on a host with no
      # public app) the auth vhost itself serving a certificate for the OLD
      # name. The browser refuses it, and since the auth vhost is where
      # Authelia's forward-auth redirect lands, it presents as "SSO broke
      # after an apply that succeeded" rather than as anything pointing at a
      # certificate.
      #
      # Read off the GENERATED unit, because the stale gate was a unit
      # directive and the new gate is script text. Three properties:
      #
      #   1. the unit is not gated on the mere existence of a path,
      #   2. its script records the domain beside the certificate, so a
      #      later start can compare rather than assume,
      #   3. the script is domain-SENSITIVE -- two hosts differing only in
      #      baseDomain must not generate the same script. Without (3) a
      #      hardcoded marker path would satisfy (2) while regenerating
      #      nothing.
      #
      # Anti-vacuity: the unit must exist on the proxy-on host at all
      # (otherwise every property above holds of an empty string), and must
      # NOT exist on a proxy-off host, which is what makes its presence a
      # real property rather than a constant.
      selfSignedCertTracksItsDomain =
        let
          hostWith = { domain, proxy ? true }: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = proxy; }
                // lib.optionalAttrs proxy {
                baseDomain = domain;
                acme.email = "a@example.test";
              };
              apps.sonarr = { enable = true; exposure = "lan"; };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          unitOf = args:
            let cfg = (hostWith args).config; in
            if cfg.systemd.units ? "ferrum-proxy-selfsigned-cert.service"
            then {
              present = true;
              text = cfg.systemd.units."ferrum-proxy-selfsigned-cert.service".text;
              script = cfg.systemd.services.ferrum-proxy-selfsigned-cert.script;
            }
            else { present = false; text = ""; script = ""; };

          a = unitOf { domain = "a.example.test"; };
          b = unitOf { domain = "b.example.test"; };
          off = unitOf { domain = "a.example.test"; proxy = false; };
        in
        {
          ok = a.present
            && !off.present
            && !(lib.hasInfix "ConditionPathExists=!" a.text)
            && lib.hasInfix "/domain" a.script
            && a.script != b.script;
          message =
            "the self-signed certificate is not regenerated when "
            + "ferrum.proxy.baseDomain changes";
          unitPresent = a.present;
          absentWithProxyOff = !off.present;
          gatedOnMereExistence = lib.hasInfix "ConditionPathExists=!" a.text;
          recordsDomain = lib.hasInfix "/domain" a.script;
          domainSensitive = a.script != b.script;
        };

      # ferrum.extraUnfreePackages ADDS to the catalog's allowances rather
      # than replacing them.
      #
      # nixpkgs.config.allowUnfreePredicate is a single FUNCTION value and
      # nixpkgs.config is types.attrs, so two definitions merge with `//`
      # and the later one wins -- silently, with no conflict error.
      # Measured at 03d569f: a /etc/ferrum/custom/ module setting its own
      # predicate produced a host whose predicate answered plexmediaserver =
      # false and unrar = false. The operator added one package and took
      # Plex and SABnzbd out with it, and the only symptom is a build
      # failure naming a package they never touched.
      #
      # The composable thing is the LIST, so ferrum.extraUnfreePackages
      # joins the same union modules/core/overlays.nix builds from every
      # meta.nix, and the predicate keeps its non-mkDefault definition. This
      # check is what pins that: it calls the GENERATED predicate, which is
      # the thing nixpkgs actually consults, rather than inspecting the list
      # the module composed.
      #
      # Anti-vacuity, and it is the whole check: the baseline must answer
      # FALSE for the extra package. A predicate that returned true for
      # everything -- which is what a careless `allowUnfree = true` would
      # amount to -- satisfies every other row here.
      extraUnfreePackagesCompose =
        let
          hostWith = extra: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              extraUnfreePackages = extra;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          allows = extra: name:
            (hostWith extra).config.nixpkgs.config.allowUnfreePredicate {
              pname = name;
              version = "0";
            };

          catalogNames = lib.unique
            (lib.concatMap (meta: meta.unfreePackages or [ ]) (lib.attrValues catalog));
          extra = "ferrum-check-not-a-real-package";

          baselineMissing = builtins.filter (n: !(allows [ ] n)) catalogNames;
          extendedMissing = builtins.filter (n: !(allows [ extra ] n)) catalogNames;
        in
        {
          ok = catalogNames != [ ]
            && baselineMissing == [ ]
            && !(allows [ ] extra)
            && extendedMissing == [ ]
            && allows [ extra ] extra;
          message =
            "ferrum.extraUnfreePackages does not compose with the catalog's "
            + "own unfree allowances";
          inherit catalogNames baselineMissing extendedMissing;
          baselineAllowsTheExtra = allows [ ] extra;
          extendedAllowsTheExtra = allows [ extra ] extra;
        };

      # Recyclarr with nothing to sync is a timer that succeeds at nothing.
      #
      # `configuration` in modules/core/recyclarr.nix is built from
      # ferrum.apps.sonarr and ferrum.apps.radarr and from nothing else, so
      # with neither enabled it is the empty attrset and the host still gets
      # an enabled services.recyclarr: a timer that wakes on schedule, syncs
      # nothing, and SUCCEEDS. Measured at 03d569f -- `configuration = { }`,
      # `systemd.timers ? recyclarr` true, zero failed assertions. A green
      # unit is indistinguishable from a working feature, which is why this
      # one is worth an assertion rather than a warning.
      #
      # The anti-vacuity half is the sonarr row: with one *arr enabled the
      # host must be accepted. Without it this passes with an assertion that
      # refuses Recyclarr outright.
      recyclarrNeedsAnArr =
        let
          hostWith = apps: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              recyclarr.enable = true;
              inherit apps;
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          rejects = apps:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "neither ferrum.apps.sonarr" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) (hostWith apps).config.assertions))
              );
            in
            if probe.success then probe.value != [ ] else true;

          # The defect's signature, kept as evidence rather than inferred.
          emptyTimer =
            let cfg = (hostWith { }).config; in
            cfg.services.recyclarr.configuration == { };
        in
        {
          ok = rejects { }
            && emptyTimer
            && !(rejects { sonarr.enable = true; })
            && !(rejects { radarr.enable = true; });
          message =
            "ferrum.recyclarr.enable with no *arr installs a timer that "
            + "syncs nothing";
          noArrsRejected = rejects { };
          inherit emptyTimer;
          sonarrRejected = rejects { sonarr.enable = true; };
          radarrRejected = rejects { radarr.enable = true; };
        };

      # An app the catalog marks `portIsFixed` really cannot honour a port,
      # and ferrum refuses to be pointed at one it cannot reach.
      #
      # ferrum.apps.<id>.port is one uniform option across the catalog --
      # that uniformity is what lets the UI render one form rather than
      # seven -- but only four of the seven apps wire it through. Plex and
      # Jellyfin have no port setting at any layer: not in ferrum, not in
      # nixpkgs' modules, not in the applications. The option was not inert
      # on them, though, because modules/proxy/nginx.nix generates
      # `proxy_pass http://127.0.0.1:${port}` from the same value. Measured
      # before the catalog carried this field: plex.port = 9999 rendered
      # `proxy_pass http://127.0.0.1:9999` with ZERO failed assertions while
      # Plex went on serving 32400 -- a 502 and a failing reconciler health
      # check, with nothing said at eval time by the layer that knew.
      #
      # Two properties, and the second is what stops this from being a
      # comment that agrees with itself:
      #
      #   1. a changed port on a portIsFixed app is REFUSED, and the catalog
      #      default is not,
      #   2. the mark is TRUE -- the generated systemd units of a host with
      #      that app's port moved carry no trace of the new number, read
      #      off the rendered unit text with the proxy OFF so nginx's own
      #      proxy_pass cannot supply a false positive.
      #
      # (2) is what makes this survive nixpkgs. If a future nixpkgs adds a
      # port option and modules/apps/<id>/service.nix wires it, the port
      # appears in the units, this check fails, and the answer is to drop
      # the mark rather than to keep refusing a port the app can now honour.
      #
      # The anti-vacuity floor is `sonarr`, which is NOT marked: moving its
      # port must be accepted AND must show up in the generated units. Half
      # of that is the positive control for the detector in (2) -- without
      # it, a detector that always answered "false" would pass every marked
      # app triumphantly. Plus a non-empty floor on the marked set itself,
      # since a check over nothing checks nothing.
      #
      # Deliberately NOT covered, and named here so it stays visible rather
      # than becoming a silence: `sabnzbd` also fails to carry its port into
      # the generated units, and is not marked portIsFixed. Its port is not
      # fixed -- SABnzbd is perfectly capable of listening elsewhere -- it
      # is configured by crates/, outside this module tree, so the honest
      # fix is there and marking it here would assert something false.
      fixedPortsAreEnforced =
        let
          movedPort = 9111;

          hostWith = { id, port, proxy }: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = proxy; }
                // lib.optionalAttrs proxy {
                baseDomain = "example.test";
                acme.email = "a@example.test";
              };
              apps.${id} = { enable = true; inherit port; };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };

          # Scoped to this assertion's own message, on a phrase it keeps to
          # one line -- the same discipline every tryEval probe in this file
          # uses, for the same reason.
          refuses = id: port:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "a port it cannot honour" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion)
                      (hostWith { inherit id port; proxy = true; }).config.assertions))
              );
            in
            if probe.success then probe.value != [ ] else true;

          # Does the port reach the GENERATED system at all? Proxy off, so
          # the only thing that could carry it is the app's own service.
          unitsCarry = id: port:
            let
              units = (hostWith { inherit id port; proxy = false; }).config.systemd.units;
            in
            builtins.any (u: lib.hasInfix (toString port) (u.text or ""))
              (builtins.attrValues units);

          fixedApps = builtins.attrNames
            (lib.filterAttrs (_: meta: meta.portIsFixed or false) catalog);

          notRefused = builtins.filter (id: !(refuses id movedPort)) fixedApps;
          refusedAtDefault = builtins.filter
            (id: refuses id catalog.${id}.defaultPort)
            fixedApps;
          markedButWired = builtins.filter (id: unitsCarry id movedPort) fixedApps;

          # The positive control.
          controlRefused = refuses "sonarr" movedPort;
          controlWired = unitsCarry "sonarr" movedPort;
        in
        {
          ok = fixedApps != [ ]
            && notRefused == [ ]
            && refusedAtDefault == [ ]
            && markedButWired == [ ]
            && !controlRefused
            && controlWired;
          message =
            "the catalog's portIsFixed marks do not match what the generated "
            + "system actually does with ferrum.apps.<id>.port";
          inherit fixedApps notRefused refusedAtDefault markedButWired
            controlRefused controlWired;
        };

      # The data-disk fixtures, shared by the two checks that read the
      # ferrum-media-tree unit: mediaTreeWaitsForItsMounts (is the unit
      # ORDERED after its mounts) and branchRootsAreOwnershipChecked (is the
      # ownership of those mounts CHECKED before it writes to them). Both
      # need the identical host shapes, and a second hand-written copy would
      # let the two drift -- the ordering check would go on passing against
      # a host the ownership check no longer describes.
      nofailDisk = mountPoint: label: {
        fileSystems.${mountPoint} = {
          device = "/dev/disk/by-label/${label}";
          fsType = "btrfs";
          options = [ "nofail" ];
        };
      };

      mediaTreeHostWith = { storage ? { }, extra ? [ ] }: ferrumLib.mkHost {
        inherit system;
        settings = {
          schemaVersion = realMigrations.currentVersion;
          inherit storage;
        };
        modules = [ ../../../examples/hosts/minimal/configuration.nix ] ++ extra;
      };

      mediaTreeUnitOf = args:
        let cfg = (mediaTreeHostWith args).config; in
        if cfg.systemd.units ? "ferrum-media-tree.service"
        then {
          present = true;
          text = cfg.systemd.units."ferrum-media-tree.service".text;
          script = cfg.systemd.services.ferrum-media-tree.script;
        }
        else { present = false; text = ""; script = ""; };

      # The media tree is seeded AFTER the data mounts, not alongside them.
      #
      # Every ferrum data mount carries `nofail`, and per systemd.mount(5)
      # `nofail` means the mount is only WANTED by local-fs.target and is
      # explicitly not ordered before it. systemd-tmpfiles-setup.service is
      # `After=local-fs.target`, so the tree can be created on the ROOT
      # filesystem under the mountpoint and then shadowed by the mount that
      # lands on top of it. On pool branches that produces exactly the state
      # poolBranchesAreAllSeeded above exists to prevent: empty branches,
      # and under epmfs the whole library on one disk.
      #
      # Read off the GENERATED unit text rather than the option tree,
      # because the ordering directives are the entire fix and NixOS is what
      # renders them. (The one exception is the tmpfiles invocation, read
      # from `.script`: NixOS spills that to a separate store derivation, so
      # the unit text carries only an ExecStart path. It is the verbatim
      # source of that derivation, one step from generated rather than an
      # option describing an intention.)
      #
      # Two anti-vacuity floors, and the second is the one worth having:
      #
      #   * a host with no declared media mount must produce NO unit -- so
      #     "present" below is a real property rather than one that holds
      #     unconditionally, and so a no-data-disk host keeps its current
      #     behaviour exactly.
      #   * a POOLED host must wait for every BRANCH, not merely for the
      #     mergerfs mount on top of them. A check that only looked at
      #     mediaDir would pass while the case that matters most -- the
      #     per-branch tree -- went unwaited and unseeded.
      mediaTreeWaitsForItsMounts =
        let
          waitsFor = u: root: lib.hasInfix "\nRequiresMountsFor=${root}\n" u.text;
          seeds = u: root: lib.hasInfix "--prefix=${root}" u.script;

          bare = mediaTreeUnitOf { };
          single = mediaTreeUnitOf { extra = [ (nofailDisk "/data" "ferrum-data") ]; };
          pooled = mediaTreeUnitOf {
            storage.pool = { enable = true; branches = [ "/mnt/d0" "/mnt/d1" ]; };
            extra = [ (nofailDisk "/mnt/d0" "d0") (nofailDisk "/mnt/d1" "d1") ];
          };
          pooledRoots = [ "/mnt/d0" "/mnt/d1" "/data" ];
        in
        {
          ok = !bare.present
            && single.present
            && waitsFor single "/data"
            && seeds single "/data"
            && pooled.present
            && lib.all (waitsFor pooled) pooledRoots
            && lib.all (seeds pooled) pooledRoots;
          message =
            "the ferrum media tree is not ordered after the data mounts it "
            + "is written to";
          bareHostHasNoUnit = !bare.present;
          singlePresent = single.present;
          singleWaits = waitsFor single "/data";
          singleSeeds = seeds single "/data";
          pooledPresent = pooled.present;
          pooledUnwaited = builtins.filter (r: !(waitsFor pooled r)) pooledRoots;
          pooledUnseeded = builtins.filter (r: !(seeds pooled r)) pooledRoots;
        };

      # Nothing is seeded on a branch root until its OWNERSHIP has been
      # checked -- and the check runs over every root, with the host's own
      # media group.
      #
      # The field failure: /mnt/ferrum-disk-1 arrived owned by UID 1001, a
      # user that does not exist on the host, and systemd-tmpfiles refused
      # to descend through it ("Detected unsafe path transition", exit
      # 73/CANTCREAT). modules/core/branch-ownership.nix carries the
      # decision about what to do; this asserts the unit actually asks it,
      # and asks it FIRST.
      #
      # Position is the whole claim, so it is read off the generated
      # `.script` rather than from the module: a guard that ran after
      # systemd-tmpfiles would be a log line about a failure that had
      # already happened. Asserting the guard call is the script's first
      # line proves ordering without parsing the rest of it.
      #
      # Three anti-vacuity floors:
      #
      #   * a host with no declared media mount still produces NO unit, so
      #     "guarded" is a property of hosts that have branches rather than
      #     one that holds by absence;
      #   * the guarded script still contains every --prefix= seeding call,
      #     so a guard that had replaced the seeding instead of preceding it
      #     fails here;
      #   * a host with a NON-DEFAULT ferrum.storage.mediaGroup must pass
      #     that group through. Without it, every assertion here would also
      #     pass against a module that hardcoded "ferrum-media" -- and the
      #     chown this guard performs would then name a group that does not
      #     exist on such a host.
      branchRootsAreOwnershipChecked =
        let
          # The literal spelling the generated script must contain. Built
          # from lib.escapeShellArgs because that is what the module uses to
          # render the call, and written out as a store-path suffix (the
          # hash differs between this evaluation's pkgs and the host's) so
          # the assertion stays about the call rather than about a path.
          guardCall = group: roots:
            "-ferrum-branch-ownership ${lib.escapeShellArgs ([ group ] ++ roots)} || exit $?";
          firstLine = u: lib.head (lib.splitString "\n" u.script);
          guardsFirst = u: group: roots:
            lib.hasPrefix "/nix/store/" (firstLine u)
            && lib.hasSuffix (guardCall group roots) (firstLine u);
          seeds = u: root: lib.hasInfix "--prefix=${root}" u.script;

          poolFixture = extraStorage: mediaTreeUnitOf {
            storage = extraStorage // {
              pool = { enable = true; branches = [ "/mnt/d0" "/mnt/d1" ]; };
            };
            extra = [ (nofailDisk "/mnt/d0" "d0") (nofailDisk "/mnt/d1" "d1") ];
          };

          bare = mediaTreeUnitOf { };
          single = mediaTreeUnitOf { extra = [ (nofailDisk "/data" "ferrum-data") ]; };
          pooled = poolFixture { };
          regrouped = poolFixture { mediaGroup = "ferrum-check-group"; };
          pooledRoots = [ "/mnt/d0" "/mnt/d1" "/data" ];
        in
        {
          ok = !bare.present
            && guardsFirst single "ferrum-media" [ "/data" ]
            && guardsFirst pooled "ferrum-media" pooledRoots
            && guardsFirst regrouped "ferrum-check-group" pooledRoots
            && seeds single "/data"
            && lib.all (seeds pooled) pooledRoots;
          message =
            "the ferrum media tree is seeded on branch roots whose ownership "
            + "was never checked";
          bareHostHasNoUnit = !bare.present;
          singleGuarded = guardsFirst single "ferrum-media" [ "/data" ];
          pooledGuarded = guardsFirst pooled "ferrum-media" pooledRoots;
          customGroupPassedThrough =
            guardsFirst regrouped "ferrum-check-group" pooledRoots;
          stillSeeds = builtins.filter (r: !(seeds pooled r)) pooledRoots;
          singleFirstLine = firstLine single;
          pooledFirstLine = firstLine pooled;
          regroupedFirstLine = firstLine regrouped;
        };

      # The guard's four arms, taken for real.
      #
      # modules/core/branch-ownership.nix decides between normalising a
      # branch root and refusing it, and that decision is the requirement.
      # An assertion over the module's TEXT would prove only that the words
      # are present, so this executes the real shipped script against real
      # directories and reads what it did to them.
      #
      # WHY fakeroot. Three of the four arms need a directory owned by
      # somebody who is not the user running the check, and whether that
      # user is root is not a property of this repository: on a hosted
      # runner the build is a nixbld user who cannot chown at all, and in a
      # container it may be root, who can. A check that quietly behaves
      # differently in those two places is the kind this repo has shipped
      # before. fakeroot makes chown and stat agree with each other under
      # both, so every arm is driven the same way wherever it runs -- and
      # the fixture preconditions below fail loudly rather than silently
      # skipping if it did not take effect.
      #
      # The read-only arm needs no fakeroot and cannot be faked: the branch
      # root for it is a directory in /nix/store, which the build sandbox
      # mounts read-only, so access(2) returns EROFS to root and non-root
      # alike. It is a real read-only mount, which is exactly the edge case.
      branchOwnershipGuardBehaves =
        let
          guard = import ../../../modules/core/branch-ownership.nix { inherit pkgs; };

          # A genuine directory on a genuine read-only filesystem: the store
          # is mounted ro inside the build sandbox.
          readOnlyBranch = pkgs.runCommand "ferrum-check-read-only-branch" { }
            "mkdir -p $out/branch";

          probe = pkgs.writeShellScript "ferrum-branch-ownership-probe" ''
            set -u

            work="$1"
            fail() { echo "branch-ownership-guard-behaves: $1" >&2; exit 1; }

            mkdir -p "$work/orphan" "$work/real" "$work/rooted" \
                     "$work/many-ok" "$work/many-bad"

            # --- the fixtures, and the proof that they took ---------------
            #
            # Without these three preconditions the whole probe could run
            # against five root-owned directories, take the "already root"
            # arm five times, and pass having tested nothing at all.
            orphan_uid=1001
            if getent passwd "$orphan_uid" >/dev/null 2>&1; then
              fail "uid $orphan_uid resolves on this builder, so it cannot stand in for an orphaned owner"
            fi

            real_entry="$(getent passwd nobody)" \
              || fail "no 'nobody' account on this builder to stand in for a real local owner"
            real_uid="$(printf '%s' "$real_entry" | cut -d: -f3)"
            [ -n "$real_uid" ] || fail "could not read nobody's uid out of '$real_entry'"
            [ "$real_uid" != 0 ] || fail "'nobody' is uid 0 here, which is the arm this probe must NOT take"

            # The group is set away from 0 too, so that the "did the guard
            # set the group" assertion below is answering a question rather
            # than observing a builder default.
            chown "$orphan_uid:65534" "$work/orphan" || fail "could not chown the orphan fixture"
            chown "$real_uid" "$work/real" || fail "could not chown the real-user fixture"
            chown "$real_uid" "$work/many-bad" || fail "could not chown the mixed-pool fixture"
            chown 0 "$work/rooted" "$work/many-ok" || fail "could not chown the control fixtures to root"

            [ "$(stat -c %u "$work/orphan")" = "$orphan_uid" ] \
              || fail "the orphan fixture is not owned by $orphan_uid -- fakeroot did not take effect, so nothing below would be testing anything"
            [ "$(stat -c %g "$work/orphan")" = 65534 ] \
              || fail "the orphan fixture's group did not take"
            [ "$(stat -c %u "$work/real")" = "$real_uid" ] \
              || fail "the real-user fixture is not owned by $real_uid"
            [ "$(stat -c %u "$work/rooted")" = 0 ] \
              || fail "the control fixture is not owned by root"

            # --- orphan UID: normalised in place --------------------------
            #
            # The group is passed as the numeric gid 0 rather than by name:
            # chown resolves a group NAME, and no builder has a
            # ferrum-media group. The name is what the module passes on a
            # real host, and that it passes the host's own value is proved
            # by branchRootsAreOwnershipChecked's regrouped fixture; what
            # is proved here is the chown itself.
            if ! ${guard} 0 "$work/orphan" > orphan.log 2>&1; then
              cat orphan.log >&2
              fail "the guard refused a branch root owned by an orphaned uid instead of normalising it"
            fi
            [ "$(stat -c %u "$work/orphan")" = 0 ] \
              || fail "the guard left the orphan-owned branch root owned by $(stat -c %u "$work/orphan")"
            [ "$(stat -c %g "$work/orphan")" = 0 ] \
              || fail "the guard did not set the group of the orphan-owned branch root"
            grep -qF "$work/orphan" orphan.log \
              || fail "the guard took ownership of a branch root without saying which"
            if grep -qF "will not change it for you" orphan.log; then
              fail "the guard reported refusing a branch root it had just normalised"
            fi

            # --- a real local user: refused, and left alone ---------------
            if ${guard} ferrum-media "$work/real" > real.log 2>&1; then
              cat real.log >&2
              fail "the guard accepted a branch root owned by a real local user"
            fi
            [ "$(stat -c %u "$work/real")" = "$real_uid" ] \
              || fail "the guard changed the ownership of a branch root owned by a real local user"
            grep -qF "$work/real" real.log || fail "the refusal does not name the path"
            grep -qF "uid $real_uid" real.log || fail "the refusal does not name the owner it found"
            grep -qF "chown root:ferrum-media $work/real" real.log \
              || fail "the refusal does not print the command that fixes it"
            # A non-zero exit is NOT enough to tell a refusal from a chown
            # that was attempted and failed, and the difference is the whole
            # decision: one leaves the operator's disk alone on purpose, the
            # other tried to take it and could not. Measured -- deleting the
            # refuse arm outright left every assertion above still passing.
            grep -qF "will not change it for you" real.log \
              || fail "the guard did not refuse the branch root; it reports having tried to take it"
            if grep -qF "Taking ownership" real.log; then
              fail "the guard tried to take ownership of a branch root owned by a real local user"
            fi

            # --- already root: untouched, and not refused -----------------
            if ! ${guard} ferrum-media "$work/rooted" > rooted.log 2>&1; then
              cat rooted.log >&2
              fail "the guard refused a branch root that was already owned by root"
            fi
            [ -s rooted.log ] && fail "the guard had something to say about a branch root that was already correct"

            # --- several branches, only one foreign -----------------------
            if ${guard} ferrum-media "$work/many-ok" "$work/many-bad" > many.log 2>&1; then
              fail "a pool whose second branch root is foreign-owned was accepted"
            fi
            grep -qF "$work/many-bad" many.log || fail "the refusal does not name WHICH branch root is foreign"
            if grep -qF "$work/many-ok" many.log; then
              fail "the refusal names a branch root that was perfectly fine"
            fi

            # --- a read-only branch: refused, with the mount named --------
            ro=${readOnlyBranch}/branch
            if touch "$ro/precondition" 2>/dev/null; then
              fail "$ro is writable, so it cannot stand in for a read-only branch"
            fi
            if ${guard} ferrum-media "$ro" > ro.log 2>&1; then
              fail "the guard accepted a branch root on a read-only filesystem"
            fi
            grep -qF "$ro" ro.log || fail "the read-only refusal does not name the mount"
            grep -qF "read-only" ro.log || fail "the read-only refusal does not say what is wrong"

            exit 0
          '';
        in
        pkgs.runCommand "ferrum-check-branch-ownership-guard-behaves"
          { nativeBuildInputs = [ pkgs.fakeroot pkgs.coreutils pkgs.getent ]; }
          ''
            set -eu
            mkdir -p work
            fakeroot ${probe} "$PWD/work"
            echo 'branch-ownership-guard-behaves: ok' > $out
          '';

      # ferrum.daemon.publish: the daemon RUNS and is reachable from
      # nowhere but a tunnel.
      #
      # Why this needed its own check rather than another fixture in
      # daemon-vhost-enforced: that check answers "is the dashboard
      # published correctly", and every absence it proves is proved on a
      # host where ferrumd does not exist at all (its daemonOff fixture
      # sets ferrum.daemon.enable = false). The claim HERE is the
      # conjunction those fixtures cannot express -- the unit is present AND
      # the publication surface is absent -- and it is the claim the
      # installer's stage 1 now depends on. Splitting `publish` out of
      # `enable` with only the existing fixtures in place would have left
      # "ferrumd still runs" asserted by nothing: `enable = true; publish =
      # false;` could have deleted the unit and every check in this file
      # would have stayed green.
      #
      # The fixtures differ in EXACTLY ONE setting, `ferrum.daemon.publish`.
      # That is deliberate and load-bearing: every assertion below is a
      # differential, so a module that stopped reading the option -- or a
      # check whose expectation was computed from the same default it is
      # checking -- fails on the control side rather than passing on both.
      # `ferrum.auth.enable` is FALSE on both, which also makes the pair the
      # only place in the tree that pins the H-03 exemption: an unpublished
      # dashboard has nothing for Authelia to sit in front of, and stage 1
      # cannot enable Authelia at all, so if publish = false did not silence
      # that assertion the installer would be exactly where it started.
      #
      # Everything is read off the GENERATED config -- the systemd unit
      # text, the nginx virtualHosts attrset, security.acme.certs, and the
      # real DNS document ferrum-dns consumes -- for the reason this file
      # gives repeatedly: an assertion over the option would have passed the
      # entire time ferrum.daemon.subdomain was decorative.
      daemonUnpublishedButRunning =
        let
          mkPublishHost = publish: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              # The shape crates/ferrum-install/src/render.rs writes for
              # stage 1: the proxy is on and a real base domain is set,
              # because ACME needs both, and auth is off because Authelia's
              # sops secrets cannot exist before the host does.
              proxy = {
                enable = true;
                baseDomain = "example.invalid";
                acme.email = "admin@example.invalid";
                dns = {
                  enable = true;
                  recordMode = "a";
                  staticAddress = "203.0.113.10";
                };
              };
              auth.enable = false;
              apps = { };
              daemon = { inherit publish; };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          unpublished = mkPublishHost false;
          control = mkPublishHost true;

          daemonName = "ferrum.example.invalid";

          # The unit as systemd will actually receive it, not
          # config.systemd.services.ferrumd -- the NixOS option set is the
          # input to the generator, and "the unit exists" is a claim about
          # its output.
          unitTextOf = host: host.config.systemd.units."ferrumd.service".text or "";
          unpublishedUnit = unitTextOf unpublished;
          controlUnit = unitTextOf control;

          vhostsOf = host: host.config.services.nginx.virtualHosts;
          certsOf = host: host.config.security.acme.certs;

          # Scoped by message infix and wrapped in tryEval for the same
          # non-negotiable reason as every other assertion probe in this
          # file: these fixtures carry OTHER failing assertions of their own
          # (the example host's placeholder secrets have no
          # *-apikey-raw.sops counterparts, and a published auth-off host
          # declares no ACME credential), so an unscoped probe reports every
          # host as rejected and passes identically with the assertion
          # deleted.
          h03FailuresFor = host:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "so there is no login in front of it" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion) host.config.assertions)));
            in
            if probe.success then probe.value else [ "evaluation threw" ];

          problems =
            # The half that makes this check different from every other one
            # here: publish = false must not take the daemon away.
            lib.optional (!(lib.hasInfix "/bin/ferrumd" unpublishedUnit))
              "ferrum.daemon.publish = false generated no ferrumd ExecStart: unpublishing the dashboard has deleted it instead of unplugging it, which is the exact failure the option was split out of ferrum.daemon.enable to end -- a stage 2 that fails then leaves the host with no web UI at all and SSH-only recovery"
            ++ lib.optional (!(lib.hasInfix "FERRUMD_LISTEN_ADDRESS=127.0.0.1" unpublishedUnit))
              "the unpublished ferrumd unit does not bind 127.0.0.1, so the SSH tunnel this whole option exists to preserve has nothing to land on"
            ++ lib.optional (!(lib.hasInfix "/bin/ferrumd" controlUnit))
              "the CONTROL host -- identical but for ferrum.daemon.publish = true -- also generated no ferrumd ExecStart, so the two assertions above are not measuring anything ferrum.daemon.publish changes"
            ++ lib.optional (!(unpublished.config.users.users ? ferrum))
              "ferrum.daemon.publish = false removed the `ferrum` system user, which the ferrumd unit runs as and modules/core/bootstrap.nix and modules/core/storage.nix both key their file ownership on"

            # ...and the half that makes it worth having: nothing is
            # published. Each absence is paired with its presence on the
            # control, so no absence here can be an empty corpus.
            ++ lib.optional (!(vhostsOf control ? ${daemonName}))
              "the control host generated no ${daemonName} vhost, so the absence claimed of the unpublished host below is vacuous"
            ++ lib.optional (vhostsOf unpublished ? ${daemonName})
              "ferrum.daemon.publish = false still generated an nginx vhost at ${daemonName}: the dashboard is on the network with Authelia absent, which is the whole exposure the option exists to prevent"
            ++ lib.optional (!(vhostsOf unpublished ? "_ferrum_unmatched"))
              "the unpublished host generated no _ferrum_unmatched catch-all, so modules/proxy/nginx.nix did not run on it at all and its vhost absences prove nothing"
            ++ lib.optional (!(certsOf control ? ${daemonName}))
              "the control host orders no certificate for ${daemonName}, so the absence claimed below is vacuous"
            ++ lib.optional (certsOf unpublished ? ${daemonName})
              "ferrum.daemon.publish = false still orders a Let's Encrypt certificate for ${daemonName} -- a real, logged, publicly-visible CT entry for a name this host deliberately serves nothing on"

            # H-03. The exemption stage 1 depends on, and its control.
            ++ lib.optional (h03FailuresFor unpublished != [ ])
              "a host with ferrum.daemon.publish = false is refused by nginx.nix's auth-off assertion, but it publishes nothing: the dashboard is reachable only over the SSH tunnel ferrum.daemon.listenAddress exists for. Stage 1 cannot enable Authelia -- its sops secrets cannot exist before the host does -- so this refusal puts the installer back where it started (H-03)"
            ++ lib.optional (h03FailuresFor control == [ ])
              "the CONTROL host -- published, auth off -- evaluates cleanly, so the assertion the exemption above is claimed against is not firing for anyone and that exemption proves nothing (H-03)";

          dnsOf = host: host.config.system.build.ferrumDnsConfig;
        in
        pkgs.runCommand "ferrum-check-daemon-unpublished-but-running"
          {
            # Passed as a file rather than interpolated into the script:
            # these messages contain quotes and backticks, and a shell that
            # mangles the one line explaining a failure is worse than no
            # message at all.
            problemsFile = pkgs.writeText "problems.json" (builtins.toJSON problems);
          } ''
          set -eu
          unpublished_dns=${dnsOf unpublished}
          control_dns=${dnsOf control}
          fail() {
            echo "daemon-unpublished-but-running: $1" >&2
            echo "--- unpublished dns ---" >&2; cat "$unpublished_dns" >&2; echo >&2
            echo "--- control dns ---" >&2; cat "$control_dns" >&2; echo >&2
            exit 1
          }

          if [ "$(${pkgs.jq}/bin/jq 'length' "$problemsFile")" != "0" ]; then
            ${pkgs.jq}/bin/jq -r '.[] | "  - " + .' "$problemsFile" >&2
            fail "the evaluated config disagrees with ferrum.daemon.publish (see above)"
          fi

          # The DNS half, which cannot be read at evaluation: the document
          # is a file the reconciler consumes, so this is the only place
          # that sees what ferrum-dns will actually be handed.
          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "daemon")] | length == 1' \
            "$control_dns" > /dev/null \
            || fail "the control host wants no daemon record, so the absence asserted of the unpublished host is vacuous"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "daemon")] | length == 0' \
            "$unpublished_dns" > /dev/null \
            || fail "ferrum.daemon.publish = false still wants a DNS record for the dashboard. Nothing answers that name -- no vhost, so nginx's catch-all closes the connection with \`return 444\` -- and no certificate was ordered for it either, so this is a public record advertising a control plane the host deliberately keeps on loopback"

          echo ok > $out
        '';

      # There is no JavaScript test runner anywhere in this repository, and
      # adding one would be a new dependency for a UI whose entire design is
      # "no build step, nothing between the source an operator reads and the
      # bytes served" (nix/pkgs/ferrum-ui/default.nix). So the Updates view is
      # guarded the only way this tree already guards UI source: by reading
      # ui/app.js as text, exactly as uiRendersEverySchemaType reads
      # ui/forms.js.
      #
      # This buys wiring and vocabulary, NOT rendering. It cannot prove a
      # <td> holds the right words; it can prove that a state the daemon can
      # send has SOME branch to land in, that the route exists, that no
      # per-app control was added, and that nothing here reaches off-host.
      # Everything else about this view is browser-only and is recorded as
      # such rather than pretended away.
      #
      # It also reads crates/ferrum-apply/src/update_check.rs and asserts set
      # equality between the UI's two vocabularies and the real serde variant
      # names. That half is the one with a proven failure behind it: the
      # candidate enum dropped NotChecked while ui/app.js still rendered a
      # branch for it, and comparing the UI only against itself agreed
      # perfectly with its own mistake.
      #
      # And it reads crates/ferrumd/src/updates.rs for the envelope those
      # documents arrive in -- its three keys and its two `status` literals.
      # The view takes "this host has never checked" from that literal instead
      # of inferring it from an empty document, which is the right call and
      # also a three-file handshake that nothing else holds together.
      #
      # It does NOT pin the report document's own field names, deliberately.
      # Set equality would be the wrong assertion there: the document is
      # read defensively (`orUnknown`, `|| {}`) precisely so a field added to
      # it is backward-compatible, and a check that failed on an additive
      # change would punish the design. The one-directional alternative --
      # "every field the UI reads must exist" -- needs the UI's reads
      # extracted from source, and the only ways to do that are a hand-written
      # list (which pins a comment, not the rendering) or a scan keyed on the
      # local variable names inside two functions (which silently checks
      # nothing the day someone renames `migration` to `m`). A small honest
      # check beats a large one that can quietly stop looking.
      #
      # Every structural lookup below throws rather than returning an empty
      # result. A check that grepped for a declaration, found nothing, and
      # passed would be worse than no check at all -- this tree has already
      # shipped one of those (see the CATALOG_APPS comment above).
      updatesViewIsWired =
        let
          appSrc = builtins.readFile ../../../ui/app.js;
          lines = lib.splitString "\n" appSrc;

          # ferrum-apply OWNS the wire vocabulary; ui/app.js only transcribes
          # it. Reading the real enums here is what turns that transcription
          # from a comment into an invariant, and it is not hypothetical: the
          # candidate side lost its NotChecked variant on the first day the
          # two files existed apart, and nothing but this would have caught
          # the UI still rendering a branch for it.
          rustPath = "crates/ferrum-apply/src/update_check.rs";
          rustLines = lib.splitString "\n" (builtins.readFile ../../../crates/ferrum-apply/src/update_check.rs);

          # ferrumd owns the envelope the document arrives in, and the UI
          # takes "this host has never checked" from its `status` literal
          # rather than inferring it from an empty document. That is the right
          # design, and it is also a three-file handshake with nothing holding
          # it together -- so the constructors are read here too.
          daemonPath = "crates/ferrumd/src/updates.rs";
          daemonLines = lib.splitString "\n" (builtins.readFile ../../../crates/ferrumd/src/updates.rs);

          # The helpers take their source explicitly. This check reads three
          # files, and one closed over a single source is a trap for whoever
          # adds the fourth.
          indexIn = src: file: what: infix:
            let
              hits = builtins.filter (e: lib.hasInfix infix e.l) (lib.imap0 (i: l: { inherit i l; }) src);
            in
            if hits == [ ] then
              throw (file + " no longer has a line containing '" + infix
                + "', so updates-view-is-wired cannot verify " + what
                + ". A check that cannot find what it guards must fail, not pass.")
            else (builtins.head hits).i;

          # Every line after the one opening `startInfix`, up to but not
          # including the first line `isEnd` accepts.
          blockIn = src: file: what: startInfix: isEnd:
            let
              after = lib.drop ((indexIn src file what startInfix) + 1) src;
              take = acc: rest:
                if rest == [ ] then
                  throw (file + " opens '" + startInfix
                    + "' but updates-view-is-wired cannot find the line that closes it")
                else if isEnd (builtins.head rest) then acc
                else take (acc ++ [ (builtins.head rest) ]) (builtins.tail rest);
              block = take [ ] after;
            in
            if block == [ ] then
              throw (file + "'s '" + startInfix + "' block is empty, so every assertion "
                + "updates-view-is-wired makes about " + what + " would be vacuously true")
            else block;

          indexOf = indexIn lines "ui/app.js";
          blockAt = blockIn lines "ui/app.js";

          quotedIn = re: line:
            map builtins.head (builtins.filter builtins.isList (builtins.split re line));

          # A one-line `const NAME = ["a", "b"];` declaration in ui/app.js.
          #
          # The character class admits camelCase as well as kebab-case: the
          # state vocabularies are kebab, but the envelope keys are `jobId`,
          # and a kebab-only class would silently skip it and leave that
          # assertion comparing two short lists that happen to agree.
          vocabOf = what: name:
            let values = quotedIn "\"([a-zA-Z][a-zA-Z0-9-]*)\"" (builtins.elemAt lines (indexOf what "const ${name} = [")); in
            if values == [ ] then
              throw ("ui/app.js declares " + name + " but updates-view-is-wired read no state "
                + "names out of it -- it is no longer a single-line array literal, and an empty "
                + "vocabulary would make the branch-coverage assertion vacuous")
            else values;

          # The keys of a one-entry-per-line state table: the branches that
          # actually render.
          branchesOf = what: name:
            let
              keys = lib.concatMap (quotedIn "\"([a-z-]+)\":")
                (blockAt what "const ${name} = {" (l: l == "};"));
            in
            if keys == [ ] then
              throw ("ui/app.js declares " + name + " but updates-view-is-wired found no "
                + "\"state\": keys in it")
            else keys;

          candidateStates = vocabOf "the candidate-state vocabulary" "CANDIDATE_STATES";
          appStates = vocabOf "the app-state vocabulary" "APP_STATES";
          candidateBranches = branchesOf "candidate-state rendering" "CANDIDATE_STATE_TEXT";
          appBranches = branchesOf "app-state rendering" "APP_STATE_TEXT";
          pinStates = vocabOf "the pin-provenance vocabulary" "PIN_STATES";
          pinBranches = branchesOf "pin-provenance rendering" "PIN_STATE_TEXT";

          unbranched = states: branches: builtins.filter (s: !(builtins.elem s branches)) states;
          orphaned = states: branches: builtins.filter (b: !(builtins.elem b states)) branches;

          # serde's kebab-case rule, DERIVED rather than hand-listed: a
          # variant `UpdateAvailable` is the wire value `update-available`.
          #
          # serde lowercases each character and inserts a separator before
          # every uppercase after the first, so splitting on `[A-Z][a-z0-9]*`
          # and joining with "-" is the same rule, including the cases that
          # look like they would differ: `DNSUnreachable` gives
          # `d-n-s-unreachable` both ways, and `V2Format` gives `v2-format`
          # both ways. Checked against serde's RenameRule, not assumed.
          #
          # There is no "refuse to guess" branch here because nothing can
          # reach it: `variantOf` below only ever admits `[A-Z][A-Za-z0-9]*`,
          # and every such name round-trips through this split. The guard
          # that CAN fire is `unparsed`, below.
          kebabOf = variant:
            lib.toLower (builtins.concatStringsSep "-"
              (map builtins.head
                (builtins.filter builtins.isList (builtins.split "([A-Z][a-z0-9]*)" variant))));

          # The unit variants of one enum in update_check.rs, as wire values.
          daemonStatesOf = enumName:
            let
              block = blockIn rustLines rustPath ("ferrum-apply's " + enumName + " variants")
                "pub enum ${enumName} {" (l: l == "}");
              variantOf = l: builtins.match "[[:space:]]*([A-Z][A-Za-z0-9]*),[[:space:]]*" l;
              ignorable = l:
                builtins.match "[[:space:]]*" l != null
                || builtins.match "[[:space:]]*(//|#\\[).*" l != null;
              names = lib.concatMap (l: let m = variantOf l; in if m == null then [ ] else m) block;

              # A body line that is neither blank, nor a comment or attribute,
              # nor a variant this check can read. Without this it would be
              # dropped from the daemon's set, and the resulting diff would
              # accuse the UI of inventing a state the daemon "never sends" --
              # sending the reader to fix the wrong file. Measured: writing
              # `Not_Newer,` into CandidateState produced exactly that
              # misdirection before this guard existed.
              unparsed = builtins.filter (l: variantOf l == null && !(ignorable l)) block;
            in
            if unparsed != [ ] then
              throw (rustPath + "'s " + enumName + " has lines updates-view-is-wired cannot read "
                + "as unit variants: " + builtins.toJSON unparsed + ". Silently dropping them "
                + "would understate the daemon's vocabulary and blame the UI for the difference.")
            else if names == [ ] then
              throw (rustPath + " declares " + enumName + " but updates-view-is-wired parsed no "
                + "variants out of it -- an empty variant set would make the UI's vocabulary "
                + "agree with it vacuously")
            else map kebabOf names;

          daemonCandidateStates = daemonStatesOf "CandidateState";
          daemonAppStates = daemonStatesOf "AppState";
          daemonPinStates = daemonStatesOf "PinProvenanceState";

          # Set equality, reported as two separate lists so a failure says
          # which side is ahead rather than just that they differ.
          daemonOnly = daemon: ui: builtins.filter (v: !(builtins.elem v ui)) daemon;
          uiOnly = daemon: ui: builtins.filter (v: !(builtins.elem v daemon)) ui;

          # One envelope constructor in ferrumd's updates.rs: the keys it
          # builds, and the `status` literal it builds them with.
          #
          # Same `unparsed` discipline as the enums above. A key line this
          # check cannot read would be dropped from the daemon's key set and
          # then reported as the UI expecting a key the daemon "never sends"
          # -- the misdirection that guard exists to stop.
          envelopeOf = fnName:
            let
              body = blockIn daemonLines daemonPath ("ferrumd's " + fnName + " envelope")
                "fn ${fnName}(" (l: l == "}");
              keyOf = l: builtins.match ".*\"([a-zA-Z][a-zA-Z0-9]*)\"[[:space:]]*:.*" l;
              ignorable = l:
                builtins.match "[[:space:]]*" l != null
                || builtins.match "[[:space:]]*//.*" l != null
                # The json! wrapper's own opening and closing lines. Bracket
                # literals rather than backslash escapes: Nix's regex engine
                # rejects `\}`, which is how this check first failed to build.
                || builtins.match "[[:space:]]*serde_json::json![(][{][[:space:]]*" l != null
                || builtins.match "[[:space:]]*[}][)][[:space:]]*" l != null;
              keyLines = builtins.filter (l: keyOf l != null) body;
              # Every `"key":` on every key-bearing line, not just the first:
              # never_checked_body builds the whole envelope on one line.
              keys = lib.concatMap
                (l: map builtins.head
                  (builtins.filter builtins.isList
                    (builtins.split "\"([a-zA-Z][a-zA-Z0-9]*)\"[[:space:]]*:" l)))
                keyLines;
              statusHits = lib.concatMap
                (l: let m = builtins.match ".*\"status\"[[:space:]]*:[[:space:]]*\"([a-z-]+)\".*" l; in
                    if m == null then [ ] else m)
                body;
              unparsed = builtins.filter (l: keyOf l == null && !(ignorable l)) body;
            in
            if !(builtins.any (l: lib.hasInfix "serde_json::json!(" l) body) then
              throw (daemonPath + "'s " + fnName + " no longer builds its body with "
                + "serde_json::json!, so updates-view-is-wired cannot read the envelope it "
                + "constructs. A check that cannot find what it guards must fail, not pass.")
            else if unparsed != [ ] then
              throw (daemonPath + "'s " + fnName + " has lines updates-view-is-wired cannot read "
                + "as envelope keys: " + builtins.toJSON unparsed + ". Silently dropping them "
                + "would understate the envelope and blame the UI for the difference.")
            else if keys == [ ] then
              throw (daemonPath + " defines " + fnName + " but updates-view-is-wired parsed no "
                + "keys out of it -- an empty key set would make the UI's expectations agree "
                + "with it vacuously")
            else if builtins.length statusHits != 1 then
              throw (daemonPath + "'s " + fnName + " does not build exactly one literal \"status\" "
                + "value this check can read (found " + builtins.toJSON statusHits + "), so the "
                + "literal the UI branches on cannot be confirmed")
            else { inherit keys; status = builtins.head statusHits; };

          reportEnvelope = envelopeOf "report_body";
          neverCheckedEnvelope = envelopeOf "never_checked_body";

          # Both constructors must build the SAME keys: the UI reads one
          # envelope shape, and a status-dependent shape would make
          # `envelopeProblem`'s missing-key report wrong for one of them.
          envelopeKeysDisagree =
            daemonOnly reportEnvelope.keys neverCheckedEnvelope.keys
            ++ uiOnly reportEnvelope.keys neverCheckedEnvelope.keys;

          daemonEnvelopeKeys = lib.unique reportEnvelope.keys;
          daemonEnvelopeStatuses = [ reportEnvelope.status neverCheckedEnvelope.status ];

          uiEnvelopeKeys = vocabOf "the envelope keys the view expects" "UPDATES_ENVELOPE_KEYS";
          uiEnvelopeStatuses = vocabOf "the envelope statuses the view knows" "UPDATES_ENVELOPE_STATUSES";

          # The view's own source, delimited by the banner comments this file
          # already uses to separate its sections.
          #
          # It ends at the NEXT banner, whichever that is, rather than at
          # `// --- routing ---` specifically. That is a correction, not a
          # loosening: the original terminator silently assumed Updates was
          # the last view in the file, so adding a sixth section between the
          # two made this block swallow it -- and `foreignJobKinds` then
          # reported the Parity view's own `parity_status`/`parity_sync`
          # calls as kinds the Updates screen was starting. The allowlist
          # below is untouched; what changed is which lines it is applied to.
          updatesBlock = blockAt "the Updates view's own source"
            "// --- updates ---" (l: lib.hasPrefix "// --- " l);

          # The per-app row builder, to its closing brace at column zero.
          appRowBlock = blockAt "the per-app row builder" "function appRow(" (l: l == "}");

          # R1's last criterion: no affordance may imply an app moves alone.
          perAppControls = builtins.filter
            (l: lib.hasInfix "el(\"button\"" l || lib.hasInfix "onclick" l || lib.hasInfix "el(\"a\"" l)
            appRowBlock;

          # This screen may start exactly two job kinds and no others.
          #
          # It was one until R4 landed. The earlier rule ("nothing here may
          # start anything but the read-only check") was right for a screen
          # that only reported; R4 requires the commit action to sit on this
          # screen, immediately below the preview it commits to, rather than
          # inventing a second commit shape elsewhere. The allowlist is
          # widened by exactly one name, and stays an allowlist: `apply`,
          # `rollback`, `gc` and `restore_state` must never be startable from
          # here, and an unrecognised kind fails rather than passing.
          updatesJobKinds = [ "check_update" "update" ];
          startJobLines = builtins.filter (l: lib.hasInfix "api.startJob(" l) updatesBlock;
          foreignJobKinds = builtins.filter
            (l: !(builtins.any (k: lib.hasInfix ("\"" + k + "\"") l) updatesJobKinds))
            startJobLines;

          # And the commit control really is present. The allowlist above
          # only says what MAY be started; without this, deleting the commit
          # action entirely would leave the check green while R4's last
          # criterion went unimplemented -- the same vacuity
          # `startsNoCheckJob` already guards against for the check itself.
          startsTheUpdateJob = builtins.any (l: lib.hasInfix "\"update\"" l) startJobLines;

          # The commit is behind a confirmation, and the confirmation names
          # the revision. DA-1 makes seeing and being able to refuse the
          # exact commit the control that stands in place of signature
          # verification, so a one-click update would remove the only thing
          # being verified.
          confirmsBeforeUpdating = builtins.any
            (l: lib.hasInfix "confirmUpdate(" l && lib.hasInfix "await" l)
            updatesBlock;

          # The Apply view's reattach finder is NOT kind-filtered, so an
          # unfiltered copy here would tail a rollback or gc job into this
          # screen and then ask for a report that job never wrote.
          reattachIsKindFiltered = builtins.any
            (l: lib.hasInfix "j.status === \"running\"" l && lib.hasInfix "j.kind === \"check_update\"" l)
            updatesBlock;

          routeWired = builtins.any (l: lib.hasInfix "\"#/updates\": updatesView" l) lines;

          # The UI's standing "no external request of any kind" invariant. An
          # absolute URL is the shape that breaks it; every real call in this
          # file is a same-origin path.
          absoluteUrls = builtins.filter
            (l: lib.hasInfix "http://" l || lib.hasInfix "https://" l)
            lines;
        in
        {
          ok = routeWired
            && reattachIsKindFiltered
            && startJobLines != [ ]
            && foreignJobKinds == [ ]
            && startsTheUpdateJob
            && confirmsBeforeUpdating
            && perAppControls == [ ]
            && absoluteUrls == [ ]
            && unbranched candidateStates candidateBranches == [ ]
            && orphaned candidateStates candidateBranches == [ ]
            && unbranched appStates appBranches == [ ]
            && orphaned appStates appBranches == [ ]
            && unbranched pinStates pinBranches == [ ]
            && orphaned pinStates pinBranches == [ ]
            && daemonOnly daemonCandidateStates candidateStates == [ ]
            && uiOnly daemonCandidateStates candidateStates == [ ]
            && daemonOnly daemonAppStates appStates == [ ]
            && uiOnly daemonAppStates appStates == [ ]
            && daemonOnly daemonPinStates pinStates == [ ]
            && uiOnly daemonPinStates pinStates == [ ]
            && envelopeKeysDisagree == [ ]
            && daemonOnly daemonEnvelopeKeys uiEnvelopeKeys == [ ]
            && uiOnly daemonEnvelopeKeys uiEnvelopeKeys == [ ]
            && daemonOnly daemonEnvelopeStatuses uiEnvelopeStatuses == [ ]
            && uiOnly daemonEnvelopeStatuses uiEnvelopeStatuses == [ ];

          routeMissing = !routeWired;
          reattachNotKindFiltered = !reattachIsKindFiltered;
          startsNoCheckJob = startJobLines == [ ];
          startsNoUpdateJob = !startsTheUpdateJob;
          updatesWithoutConfirming = !confirmsBeforeUpdating;
          inherit foreignJobKinds perAppControls absoluteUrls;
          candidateStatesWithNoBranch = unbranched candidateStates candidateBranches;
          candidateBranchesWithNoState = orphaned candidateStates candidateBranches;
          appStatesWithNoBranch = unbranched appStates appBranches;
          appBranchesWithNoState = orphaned appStates appBranches;
          pinStatesWithNoBranch = unbranched pinStates pinBranches;
          pinBranchesWithNoState = orphaned pinStates pinBranches;

          # Both sides named on every failure, so the message says what the
          # daemon actually sends as well as what the UI believes.
          inherit daemonCandidateStates daemonAppStates daemonPinStates;
          uiCandidateStates = candidateStates;
          uiAppStates = appStates;
          uiPinStates = pinStates;
          pinStatesTheDaemonSendsAndTheUiLacks = daemonOnly daemonPinStates pinStates;
          pinStatesTheUiExpectsAndTheDaemonNeverSends = uiOnly daemonPinStates pinStates;
          candidateStatesTheDaemonSendsAndTheUiLacks = daemonOnly daemonCandidateStates candidateStates;
          candidateStatesTheUiExpectsAndTheDaemonNeverSends = uiOnly daemonCandidateStates candidateStates;
          appStatesTheDaemonSendsAndTheUiLacks = daemonOnly daemonAppStates appStates;
          appStatesTheUiExpectsAndTheDaemonNeverSends = uiOnly daemonAppStates appStates;

          inherit daemonEnvelopeKeys daemonEnvelopeStatuses uiEnvelopeKeys uiEnvelopeStatuses;
          theTwoEnvelopeConstructorsBuildDifferentKeys = envelopeKeysDisagree;
          envelopeKeysTheDaemonSendsAndTheUiLacks = daemonOnly daemonEnvelopeKeys uiEnvelopeKeys;
          envelopeKeysTheUiExpectsAndTheDaemonNeverSends = uiOnly daemonEnvelopeKeys uiEnvelopeKeys;
          envelopeStatusesTheDaemonSendsAndTheUiLacks = daemonOnly daemonEnvelopeStatuses uiEnvelopeStatuses;
          envelopeStatusesTheUiExpectsAndTheDaemonNeverSends = uiOnly daemonEnvelopeStatuses uiEnvelopeStatuses;
        };

      # **ferrum must never ship a host its owner cannot get into.**
      #
      # The incident this exists for: a real host stopped answering SSH --
      # nothing listening on 22, 80 or 443 -- while still reaching
      # `ferrum login:`. systemd had come up fine. The operator could not
      # log in, because nothing in this module tree had ever set
      # `hashedPassword`, `initialPassword` or `users.mutableUsers`: root's
      # account was locked, so that prompt accepted nothing at all. The only
      # way back in was editing the bootloader for `init=/bin/sh`, which
      # then broke the USB keyboard, because that path never starts systemd
      # and udev never loads the HID driver.
      #
      # WHAT THIS ASSERTS, AND WHY IT IS THE GENERATED DOCUMENT AND NOT AN
      # OPTION. `config.users.users.root.hashedPassword` is a value this
      # repository's own module tree computes; reading it back would mostly
      # re-state the tree's intent. `users-groups.json` is the artifact
      # NixOS's activation actually hands to `update-users-groups.pl`, and
      # it is what decides, on the real machine, whether root can log in.
      # It is reached the only way it can be reached cheaply: the generated
      # users activation script names its store path, and writing that
      # script out with `writeText` carries the string context that makes
      # Nix realize the JSON as a build input. No full toplevel, no
      # sops-install-secrets, none of the cost that keeps
      # `eval-example-hosts` out of CI.
      #
      # The property has two arms, because there are two legitimate ways to
      # be reachable:
      #
      #   1. the generated document already gives root a password, or
      #   2. `users.mutableUsers` is true (so a password set at runtime
      #      SURVIVES the next activation instead of being wiped) AND the
      #      generated ferrum-apply really carries the mechanism that sets
      #      one -- `FERRUM_ROOT_PASSWORD_FILE`, wired in by
      #      modules/core/overlays.nix and consumed by
      #      `secrets::ensure_root_password`.
      #
      # Arm 2 needs BOTH halves and that is the whole point. Before the fix,
      # `mutableUsers` was already true -- it is NixOS's default -- so a
      # check written against it alone would have passed green on the
      # locked-out host. A check that passes on the broken configuration is
      # worse than no check, so the mechanism's presence in the built
      # artifact is what carries the claim.
      #
      # ANTI-VACUITY. Four guards, because every probe here can fail to
      # find anything and "found nothing" must never read as "found nothing
      # wrong":
      #
      #   a. the users document must be located and must list root at all;
      #   b. the env-var probe must find a variable that IS there
      #      (FERRUM_SECRETS_DIR) and must NOT find one that is not, so a
      #      grep against the wrong file or an empty one cannot pass;
      #   c. a CONTROL host -- identical but for a declared root
      #      `hashedPassword` -- must make arm 1 answer true, proving that
      #      arm is live code and not a branch nothing can ever take;
      #   d. that same control must differ from the real host, which must
      #      answer false on arm 1. If both answered the same the probe
      #      would be reading something other than what it claims.
      #
      # It lives in CI's `rust` job rather than `cheap checks` because it
      # realizes ferrum-apply, exactly like
      # `production-installer-has-no-api-override` -- which is already
      # there, for this same reason, sharing that job's warm Cargo closure.
      aHostAlwaysHasAWayIn =
        let
          host = exampleHosts.minimal;
          # The control differs from `host` in exactly one declared way.
          # `mutableUsers = false` comes with it deliberately: this is what
          # a host that ships a fixed password looks like, and arm 1 must
          # accept it without any help from arm 2.
          controlHost = mkMinimalHost [{
            users.mutableUsers = false;
            users.users.root.hashedPassword =
              "$6$ferrumcheckcontrol$0000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
          }];
          usersActivation = h: name:
            pkgs.writeText "users-activation-${name}" h.config.system.activationScripts.users.text;
        in
        pkgs.runCommand "ferrum-check-a-host-always-has-a-way-in"
          {
            realActivation = usersActivation host "real";
            controlActivation = usersActivation controlHost "control";
            applier = "${host.pkgs.ferrum-apply}/bin/ferrum-apply";
          } ''
          set -eu
          jq=${pkgs.jq}/bin/jq

          fail() { echo "a-host-always-has-a-way-in: $1" >&2; exit 1; }

          # Locates the generated users document from the activation script
          # that names it. Realized as a build input via the writeText
          # above, so the path is genuinely present in the store here.
          usersDocument() {
            doc="$(grep -oE '/nix/store/[a-z0-9]+-users-groups\.json' "$1" | head -1 || true)"
            [ -n "$doc" ] || fail "no users-groups.json named in $1 -- the probe found nothing to read, which is not the same as finding nothing wrong"
            [ -f "$doc" ] || fail "$1 names $doc, which is not in the store"
            echo "$doc"
          }

          # Arm 1, as the generated document answers it. Every field
          # NixOS's own activation would accept as a password counts --
          # including hashedPasswordFile, which sets one without the value
          # ever appearing here.
          #
          # Deliberately NOT `jq -e`. That flag makes jq exit non-zero when
          # its output is `false`, and `false` is this function's most
          # important legitimate answer -- under `set -e` it killed the
          # whole check, silently, with an empty build log, before a single
          # diagnostic could be printed. A missing root user still fails
          # loudly: jq's own `error` below exits non-zero with a message,
          # which is what a genuine "cannot answer" should look like, as
          # distinct from an answer of no.
          rootHasAPassword() {
            $jq -r '
              [ .users[] | select(.name == "root") ] as $root
              | if ($root | length) == 0 then error("no root user in the generated document") else . end
              | $root[0]
              | [ .hashedPassword, .hashedPasswordFile, .initialHashedPassword,
                  .initialPassword, .password ]
              | map(select(. != null)) | length > 0
            ' "$1"
          }

          real="$(usersDocument "$realActivation")"
          control="$(usersDocument "$controlActivation")"
          echo "reading the generated users documents: real=$real control=$control"

          # (a) The document must really describe root. jq -e exits 1 on a
          # false/null result, so an absent root user fails here rather
          # than quietly producing an empty answer below.
          $jq -e '[ .users[] | select(.name == "root") ] | length == 1' "$real" > /dev/null \
            || fail "the generated users document does not describe exactly one root user -- refusing to read an answer out of it"

          # (c) + (d) The control proves arm 1 is live and that the probe
          # discriminates. If these two ever agree, the probe has stopped
          # reading what it claims to read.
          controlAnswer="$(rootHasAPassword "$control")"
          realAnswer="$(rootHasAPassword "$real")"
          [ "$controlAnswer" = "true" ] \
            || fail "the control host declares users.users.root.hashedPassword and the probe still answered $controlAnswer -- the password arm of this check is dead code"
          [ "$controlAnswer" != "$realAnswer" ] \
            || fail "the control host and the real host answered identically ($realAnswer) -- this probe is not measuring what it claims to"

          if [ "$realAnswer" = "true" ]; then
            echo "root carries a password in the generated users document" > $out
            exit 0
          fi

          # Arm 2, half one: a runtime-set password must survive activation.
          mutable="$($jq -r '.mutableUsers' "$real")"
          [ "$mutable" = "true" ] \
            || fail "root has no password in the generated users document AND users.mutableUsers is $mutable -- a password set at runtime would be wiped by the next activation, so this host can never be logged into at the console"

          # (b) The env-var probe's own controls, run before its verdict is
          # trusted: it must be able to say yes to something present and no
          # to something absent. A grep against a truncated or wrong file
          # answers no to both.
          # Named once and used in both the probe and its message, so a
          # failure can never describe a variable other than the one it
          # actually looked for.
          mustBePresent=FERRUM_SECRETS_DIR
          mustBeAbsent=FERRUM_NO_SUCH_VARIABLE_EXISTS
          grep -a -q "$mustBePresent" "$applier" \
            || fail "the positive control failed: $applier carries no $mustBePresent, so this probe is not reading the wrapper it thinks it is"
          grep -a -q "$mustBeAbsent" "$applier" \
            && fail "the negative control failed: $applier appears to carry $mustBeAbsent, which does not exist, so a match here proves nothing" \
            || true

          # Arm 2, half two: the mechanism itself.
          grep -a -q FERRUM_ROOT_PASSWORD_FILE "$applier" \
            || fail "root has no password in the generated users document and this host's ferrum-apply carries no FERRUM_ROOT_PASSWORD_FILE -- nothing will ever give root one, so the machine boots to a login prompt that accepts nothing and the only way in is editing the bootloader"

          echo "root has no declared password, but mutableUsers is true and ferrum-apply generates one" > $out
        '';

      # R2: a WireGuard config with more than one address must work.
      #
      # The defect this pins is not subtle and was not caught by anything
      # here: qbt-vpn-netns-setup read the whole `Address =` line with one
      # awk one-liner and handed it to `ip address add` as a single
      # argument. Every mainstream provider issues several addresses, so on
      # the owner's real Proton config the unit died at boot with
      #
      #   Error: any valid prefix is expected rather than "10.2.0.2/32,2a07:b944::2:2/128".
      #
      # and qbittorrent.service, which bindsTo it, never started. Nothing in
      # this file noticed, because nothing in this file had ever read a real
      # provider config -- the unit's script was only ever asserted about as
      # text, and the text was fine.
      #
      # So this check does three things no existing check here does:
      #
      #   1. It runs the parsing. The parsing now lives in
      #      modules/apps/qbittorrent/wg-parse.awk precisely so it CAN be
      #      run without standing up a privileged network namespace, and the
      #      path to it is grepped out of the GENERATED unit script rather
      #      than named here, so a module that stopped using it fails rather
      #      than leaving this check exercising an orphan.
      #   2. It feeds it the real thing -- tests/fixtures/wireguard/
      #      proton-multiaddress.conf is the provider's own output, keys
      #      aside. A hand-minimised fixture is what would have been written
      #      before the bug and is exactly what would have missed it.
      #   3. It keeps the RED. The superseded one-liner is re-run here on
      #      the same file and its output is still handed to the real ip(8),
      #      so the check carries its own evidence that the corpus is the
      #      defective input rather than trusting a comment for it.
      #
      # Nothing here needs privilege or touches the sandbox's network: every
      # ip(8) and wg(8) call names a device that does not exist, which is
      # enough because both tools parse their arguments before they look for
      # the device. That is deliberate -- checks in this file have twice
      # been broken by a fixture that quietly depended on being root.
      wireguardConfigWithManyAddresses =
        let
          host = ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              apps.qbittorrent.enable = true;
            };
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              # Declaring the secret name is what switches the VPN-gated
              # namespace on (service.nix's `vpnEnabled`), and therefore the
              # only way to make the unit under test exist at all.
              { ferrum.secrets."qbittorrent-vpn" = { }; }
            ];
          };
        in
        pkgs.runCommand "ferrum-check-wireguard-config-with-many-addresses"
          {
            nativeBuildInputs = [
              pkgs.gawk
              pkgs.gnugrep
              pkgs.gnused
              pkgs.diffutils
              pkgs.iproute2
              pkgs.wireguard-tools
            ];
            # The generated script, carried in as a derivation attribute so
            # its string context brings wg-parse.awk's store path into the
            # sandbox with it. Reading the option values instead would have
            # passed throughout the period the bug existed.
            script = host.config.systemd.services.qbt-vpn-netns-setup.script;
            fixture = ../../../tests/fixtures/wireguard/proton-multiaddress.conf;
          }
          ''
            set -eu

            fail() {
              echo "wireguard-config-with-many-addresses: $1" >&2
              exit 1
            }

            mutate() {
              sed "$2" "$conf" > "$1"
              if cmp -s "$conf" "$1"; then
                fail "the mutation [$2] changed nothing, so the variant it was supposed to build is the original fixture and whatever it proves below is vacuous"
              fi
            }

            printf '%s' "$script" > unit-script.sh

            # Comment lines stripped once, here. The module's own commentary
            # quotes both the superseded extraction and AllowedIPs while
            # explaining them, and every "this must NOT appear" assertion
            # below is a question about code, not about prose.
            grep -v '^[[:space:]]*#' unit-script.sh > unit-code.sh

            parser=$(grep -o '/nix/store/[a-z0-9]\{32\}-wg-parse\.awk' unit-script.sh | head -n1)
            [ -n "$parser" ] \
              || fail "the generated qbt-vpn-netns-setup script does not name wg-parse.awk anywhere, so this check has nothing to exercise -- if the WireGuard parsing moved, this check has to move with it rather than quietly testing a file the host no longer uses"
            [ -r "$parser" ] \
              || fail "$parser is named by the generated unit script but is not readable here"

            # Anti-vacuity, structural. The defect was ONE `ip address add`
            # taking a whole line, so the fix is only present if the
            # generated script loops over what the parser printed. Asserted
            # on the script, not on the parser, because a correct parser
            # whose output is still passed as one argument is the original
            # bug with extra steps.
            grep -q 'while IFS= read -r wg_address; do' unit-script.sh \
              || fail "the generated script does not loop over the parsed addresses -- a provider config with more than one address would reach ip(8) as a single argument again"
            grep -q 'while IFS= read -r server; do' unit-script.sh \
              || fail "the generated script does not loop over the parsed resolvers"
            if grep -q "awk -F'='" unit-code.sh; then
              fail "the generated script still carries the single-line awk extraction this check exists to keep deleted"
            fi

            conf=wg0.conf
            cp "$fixture" "$conf"
            chmod 0600 "$conf"

            # Anti-vacuity, corpus. A fixture that had lost its second
            # address would satisfy every assertion below while proving
            # nothing at all, which is precisely the tidied-up fixture that
            # would have missed the bug in the first place.
            grep -qx 'Address = 10\.2\.0\.2/32, 2a07:b944::2:2/128' "$conf" \
              || fail "the fixture's Address= line is no longer the two-entry line a provider issues, so nothing below tests multi-address parsing"
            grep -qx 'DNS = 10\.2\.0\.1, 2a07:b944::2:1' "$conf" \
              || fail "the fixture's DNS= line is no longer the two-entry line a provider issues"
            grep -qx 'AllowedIPs = 0\.0\.0\.0/0, ::/0' "$conf" \
              || fail "the fixture's AllowedIPs= line is no longer the two-entry line a provider issues"

            # ---- the RED, kept ------------------------------------------
            blob=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }' "$conf")
            [ "$blob" = "10.2.0.2/32,2a07:b944::2:2/128" ] \
              || fail "the superseded extraction no longer produces the exact argument the owner's host died on -- it produced [$blob], so this check is no longer reproducing the reported defect"
            if ip address add "$blob" dev ferrum-no-such-dev 2> old.err; then
              fail "ip(8) accepted the whole comma-separated list, so the defect this check pins no longer exists in iproute2 -- rewrite this check rather than deleting it"
            fi
            grep -q 'any valid prefix is expected' old.err \
              || fail "ip(8) refused the old single-argument form for a reason this check does not recognise, so the reproduction is not reproducing what it claims: $(cat old.err)"

            # ---- Address: the real provider config ----------------------
            addresses=$(awk -v key=Address -v allowPrefix=1 -v required=1 -f "$parser" "$conf" 2> addr.err) \
              || fail "the parser refused the owner's real provider config outright: $(cat addr.err)"
            [ "$addresses" = "10.2.0.2/32" ] \
              || fail "parsing Address= out of the real provider config produced [$addresses] rather than the single IPv4 entry it carries"
            grep -q 'skipping the IPv6 Address entry 2a07:b944::2:2/128' addr.err \
              || fail "the IPv6 address was dropped without telling the operator which entry went or why -- that decision has to be visible in the journal: $(cat addr.err)"

            # Every surviving entry has to be something ip(8) will actually
            # take. This is the assertion the original code could not make.
            printf '%s\n' "$addresses" > addresses.txt
            while IFS= read -r one; do
              if ip address add "$one" dev ferrum-no-such-dev 2> new.err; then
                fail "ip(8) found a device named ferrum-no-such-dev, which should not exist -- this sandbox is not what this check assumes"
              fi
              if grep -q 'any valid prefix is expected' new.err; then
                fail "the parser emitted [$one], which ip(8) still refuses as a prefix: $(cat new.err)"
              fi
              grep -q 'Cannot find device' new.err \
                || fail "ip(8) answered something this check does not understand for [$one]: $(cat new.err)"
            done < addresses.txt

            # ---- DNS: the same list, the same treatment -----------------
            resolvers=$(awk -v key=DNS -v allowPrefix=0 -v required=0 -f "$parser" "$conf" 2> dns.err) \
              || fail "the parser refused the provider config's DNS= line: $(cat dns.err)"
            [ "$resolvers" = "10.2.0.1" ] \
              || fail "parsing DNS= out of the real provider config produced [$resolvers] rather than the single IPv4 resolver it carries"
            grep -q 'skipping the IPv6 DNS entry 2a07:b944::2:1' dns.err \
              || fail "the IPv6 resolver was dropped silently: $(cat dns.err)"

            # ---- several usable entries really do come out separately ---
            # The real fixture has one IPv4 address and one IPv6, so on its
            # own it cannot show two entries being applied separately. This
            # variant, derived from it, carries two IPv4 addresses plus the
            # two punctuation accidents the spec calls out -- a blank entry
            # and a trailing comma -- and must produce exactly two lines.
            mutate two-v4.conf 's|^Address = .*|Address = 10.2.0.2/32, , 10.2.0.3/32,|'
            twoAddresses=$(awk -v key=Address -v allowPrefix=1 -v required=1 -f "$parser" two-v4.conf 2> two.err) \
              || fail "a two-address IPv4 config was refused: $(cat two.err)"
            printf '%s\n' "$twoAddresses" > two.actual
            printf '10.2.0.2/32\n10.2.0.3/32\n' > two.expected
            cmp -s two.actual two.expected \
              || fail "two IPv4 entries, a blank entry and a trailing comma did not parse to exactly two addresses on their own lines -- got [$twoAddresses]"

            # ---- a malformed entry names the config line ----------------
            mutate bad-addr.conf 's|^Address = 10\.2\.0\.2/32|Address = 10.2.0.300/32|'
            if awk -v key=Address -v allowPrefix=1 -v required=1 -f "$parser" bad-addr.conf > bad.out 2> bad.err; then
              fail "the parser accepted 10.2.0.300/32, which is not an address -- it would reach ip(8) and fail there instead, which is the whole complaint"
            fi
            grep -q 'line 3: Address = 10.2.0.300/32, 2a07:b944::2:2/128' bad.err \
              || fail "the refusal does not quote the config line that caused it, so the operator is sent looking: $(cat bad.err)"
            if grep -q 'any valid prefix is expected' bad.err; then
              fail "the malformed entry still reached ip(8) -- the operator gets iproute2's stderr instead of their own config line"
            fi
            [ ! -s bad.out ] \
              || fail "the parser printed addresses despite refusing: $(cat bad.out)"

            # ---- an IPv6-only config is refused, not silently empty -----
            mutate v6-only.conf 's|^Address = 10\.2\.0\.2/32, |Address = |'
            if awk -v key=Address -v allowPrefix=1 -v required=1 -f "$parser" v6-only.conf > v6.out 2> v6.err; then
              fail "an IPv6-only config was accepted, which would leave the namespace with no address at all and qBittorrent starting into silence"
            fi
            grep -q 'every Address= entry in the WireGuard config is IPv6' v6.err \
              || fail "an IPv6-only config was refused without saying why: $(cat v6.err)"

            # ---- no DNS= line stays non-fatal ---------------------------
            grep -v '^DNS' "$conf" > no-dns.conf
            if cmp -s "$conf" no-dns.conf; then
              fail "stripping the DNS= line changed nothing, so the no-resolver case below is vacuous"
            fi
            noDns=$(awk -v key=DNS -v allowPrefix=0 -v required=0 -f "$parser" no-dns.conf 2> no-dns.err) \
              || fail "a config with no DNS= line was treated as fatal, changing this unit's documented behaviour: $(cat no-dns.err)"
            [ -z "$noDns" ] \
              || fail "a config with no DNS= line produced resolvers out of nowhere: [$noDns]"

            # ---- AllowedIPs is NOT on the same defect -------------------
            # It has the identical comma-separated shape, so the spec asks
            # whether it is broken too. It is not, for two reasons, and both
            # are asserted here rather than asserted in a comment.
            #
            # First, ferrum never reads it: the unit hands the whole config
            # to `wg setconf wg0 <(wg-quick strip ...)` and does no parsing
            # of its own, so there is no ferrum code path for the list to be
            # mishandled by -- which is exactly what was NOT true of
            # Address=.
            grep -q 'wg setconf wg0 <(wg-quick strip /run/qbt-vpn/wg0.conf)' unit-script.sh \
              || fail "the generated script no longer delegates the peer configuration to wg(8) via wg-quick strip, so whatever reads AllowedIPs now is ferrum's problem and needs the same treatment Address= got"
            if grep -q AllowedIPs unit-code.sh; then
              fail "the generated script mentions AllowedIPs, so ferrum has started parsing it -- it is now on the same defect as Address= was and needs the same comma handling"
            fi

            # Second, wg(8) itself splits the list. Proved against the real
            # provider lines rather than asserted: the [Peer] section below
            # is copied verbatim out of the fixture, and the [Interface]
            # half is the PrivateKey line alone, which is what `wg-quick
            # strip` leaves behind (confirmed by hand against the real tool
            # -- it is not run here because wg-quick re-execs itself through
            # sudo whenever it is not uid 0, and a build sandbox is
            # deliberately neither root nor in possession of a sudo).
            grep -x '\[Interface\]' "$conf" > setconf.conf
            grep '^PrivateKey = ' "$conf" >> setconf.conf
            echo >> setconf.conf
            awk '/^\[Peer\]/ { peer = 1 } peer { print }' "$conf" >> setconf.conf
            grep -qx 'AllowedIPs = 0\.0\.0\.0/0, ::/0' setconf.conf \
              || fail "the config assembled for wg setconf does not carry the provider's AllowedIPs line, so the probe below would prove nothing"

            if wg setconf ferrum-no-such-dev setconf.conf 2> wg-good.err; then
              fail "wg setconf succeeded against a device that does not exist -- this sandbox is not what this check assumes"
            fi
            if grep -q 'Configuration parsing error' wg-good.err; then
              fail "wg(8) refuses the comma-separated AllowedIPs every provider issues, so AllowedIPs IS sitting on the same defect as Address= and needs the same treatment: $(cat wg-good.err)"
            fi

            sed 's|^AllowedIPs = .*|AllowedIPs = not-an-address|' setconf.conf > wg-bad.conf
            if cmp -s setconf.conf wg-bad.conf; then
              fail "breaking the AllowedIPs line changed nothing, so the negative control below is the positive one again"
            fi
            if wg setconf ferrum-no-such-dev wg-bad.conf 2> wg-bad.err; then
              fail "wg setconf accepted a plainly unparseable AllowedIPs"
            fi
            grep -q 'Configuration parsing error' wg-bad.err \
              || fail "the negative control failed: wg setconf reports no parsing error even for a plainly unparseable AllowedIPs, so the probe above could not have detected one either: $(cat wg-bad.err)"

            echo "a real multi-address provider config parses into separate addresses" > $out
          '';

      # An app placed in a network namespace must not be proxied at an
      # address that cannot reach it.
      #
      # THE DEFECT, measured on the owner's running host on 2026-10-06 and
      # not hypothesised:
      #
      #   ip netns list                 -> qbt-vpn (id: 0)
      #   ss -ltnp | grep :8090         -> nothing in the root namespace
      #   ip netns exec qbt-vpn ss -ltn -> LISTEN 0 50 *:8090
      #   nginx.conf                    -> proxy_pass http://127.0.0.1:8090;
      #   curl http://127.0.0.1:8090/   -> exit 7, connection refused
      #   curl http://10.200.1.2:8090/  -> HTTP 200
      #
      # modules/apps/qbittorrent/service.nix setns's qBittorrent into
      # `qbt-vpn` whenever a "qbittorrent-vpn" secret is declared, so its
      # WebUI binds inside that namespace. nginx runs in the ROOT namespace
      # and rendered `proxy_pass http://127.0.0.1:<port>` for every app with
      # no exception, so the vhost an app gets by DEFAULT (app-submodule.nix
      # gives exposure = "public") could not reach it. Nothing noticed,
      # because Authelia's forward-auth answers an unauthenticated probe
      # with a 302 before nginx ever dials the backend: the failure is
      # visible only after you log in.
      #
      # WHAT THIS CHECK IS, AND WHAT IT DELIBERATELY IS NOT. It is not "is
      # qBittorrent's proxy_pass 10.200.1.2" -- that would be the same
      # hand-copied constant a third time, and a hand-copy is the bug. The
      # isolated set is DERIVED from the evaluated configuration: an app
      # counts as isolated when its own generated systemd unit carries
      # NetworkNamespacePath=, JoinsNamespaceOf= or PrivateNetwork=true. Any
      # future app put in a namespace is covered the day it is, with no edit
      # here and no list of app names to keep in sync.
      #
      # It also does not consult modules/lib/app-address.nix, the file the
      # fix lives in: a check that asked the fix whether the fix had been
      # applied would pass for as long as the fix was self-consistent. What
      # it asserts instead are two independent properties of the GENERATED
      # artifacts -- (a) no proxy_pass anywhere in the real nginx.conf dials
      # an isolated app on a loopback address, and (b) nginx.conf and
      # ferrum-reconcile's config, two separately generated files for two
      # separately running consumers, name the SAME host for every enabled
      # app. (b) is what catches a third consumer hand-copying 127.0.0.1 the
      # way nginx did.
      #
      # Both halves of the anti-vacuity obligation are inside the check: it
      # re-runs its own predicate against a conf whose isolated-app upstreams
      # have been rewritten back to loopback -- the fix, mechanically
      # reverted -- and requires that to FAIL, and it evaluates a second,
      # VPN-less host and requires the isolated set there to be EMPTY with
      # qBittorrent still on plain loopback. A predicate that fired on every
      # host, or on no host, is caught by one of those two. That is not
      # hypothetical caution: a guard in this file was once dead on every
      # real host because it tested a value nixpkgs' own nat module never
      # leaves empty, and it was green everywhere.
      #
      # The daemon vhost and its two health locations are out of scope on
      # purpose: ferrumd is not a catalog app, it is not namespaced, and its
      # upstream comes from the operator-settable ferrum.daemon.listenAddress
      # that daemon-vhost-enforced and nginx-config-parses already own.
      netnsAppsAreProxiedReachably =
        let
          mkNetnsHost = extra: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = { enable = true; baseDomain = "example.test"; acme.email = "a@example.test"; };
              auth = { enable = true; adminEmail = "a@example.test"; };
              # Every catalog app, at its DEFAULT exposure -- which is
              # "public" (modules/lib/app-submodule.nix). The default is the
              # configuration the defect actually shipped on, so it is the
              # one worth pinning, and enabling the whole catalog means a
              # future namespaced app joins the corpus automatically.
              #
              # Since a headless app defaults to "local" instead, the corpus
              # now contains both kinds, and `scan` below judges each by
              # whether the generated config has a vhost for it rather than
              # assuming every enabled app has one. That is a strengthening,
              # not an exemption: an app with no vhost is required to have
              # NOTHING in the config proxying to it, which is the property
              # that was previously assumed and never checked.
              apps = lib.mapAttrs (_: _: { enable = true; }) catalog;
            };
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              # The same override mkMinimalHost uses: sops.secrets.<>.sopsFile
              # is a real Nix path and must point somewhere that exists.
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
            ] ++ extra;
          };

          # Declaring the secret name is what switches the VPN-gated
          # namespace on (qbittorrent/service.nix's `vpnEnabled`), and
          # therefore the only way to make an isolated app exist at all.
          vpnHost = mkNetnsHost [ { ferrum.secrets."qbittorrent-vpn" = { }; } ];
          plainHost = mkNetnsHost [ ];

          # Is this app's own unit severed from the root namespace? Read off
          # the GENERATED unit, never from an app-name list. All three keys,
          # because all three sever it and any of them produces this defect.
          isolationOf = host: id:
            let svc = host.config.systemd.services.${id}.serviceConfig or { }; in
            if (svc.NetworkNamespacePath or null) != null
            then "NetworkNamespacePath=${svc.NetworkNamespacePath}"
            else if (svc.JoinsNamespaceOf or [ ]) != [ ] then "JoinsNamespaceOf"
            else if (svc.PrivateNetwork or false) then "PrivateNetwork=true"
            else null;

          # The host part of a generated `http://host:port` upstream.
          upstreamHost = s:
            let m = builtins.match "https?://([^/]*):[0-9]+" s; in
            if m == null then null else builtins.head m;

          # "-" rather than null for the absent cases: these go through
          # @tsv, and a tab is an IFS whitespace character, so bash collapses
          # a run of them and an empty field silently shifts every later
          # column. A placeholder keeps the record rectangular.
          orDash = v: if v == null || v == "" then "-" else v;

          appReport = host: id: app:
            let
              vhost = "${app.subdomain}.example.test";
              vhosts = host.config.services.nginx.virtualHosts;
            in
            {
              inherit id vhost;
              port = toString app.port;
              # A missing unit is a FAILURE, not a skip: it means this check
              # cannot see whether the app is isolated, and a silent skip is
              # how a guard stops guarding. An app whose systemd unit is not
              # named after its catalog id has to teach this check that
              # mapping rather than slip past it.
              hasUnit = host.config.systemd.services ? ${id};
              # Does the GENERATED config give this app a front door? Read
              # off the evaluated virtualHosts, not off the catalog's
              # `headless` mark and not off `exposure`: the thing this check
              # is about is what nginx was actually told, and deriving the
              # question from the same metadata that is supposed to produce
              # the answer is how a guard comes to agree with itself.
              proxied = vhosts ? ${vhost};
              isolation = orDash (
                if host.config.systemd.services ? ${id} then isolationOf host id else null
              );
              nginxHost = orDash (
                if vhosts ? ${vhost}
                then upstreamHost (vhosts.${vhost}.locations."/".proxyPass or "")
                else null
              );
            };

          manifestFor = host: builtins.toJSON {
            apps = lib.mapAttrsToList (appReport host)
              (lib.filterAttrs (_: a: a.enable) host.config.ferrum.apps);
          };

          # The file ferrum-reconcile is actually handed, carried in as a
          # build input -- NOT read at eval time, which would need it
          # realized first. rootFoldersReachTheApps above does the same.
          reconcileConfigOf = host:
            host.config.systemd.services.ferrum-reconcile.environment.FERRUM_RECONCILE_CONFIG;
        in
        pkgs.runCommand "ferrum-check-netns-apps-are-proxied-reachably"
          {
            nativeBuildInputs = [ pkgs.jq pkgs.gnugrep pkgs.gnused pkgs.diffutils ];
            # The UNITS, not a config path read out of them in Nix: a string
            # pulled out with builtins.match carries no store reference and
            # the file would not exist in the sandbox. Same reasoning as
            # nginx-config-parses above.
            vpnUnit = vpnHost.config.systemd.units."nginx.service".unit;
            plainUnit = plainHost.config.systemd.units."nginx.service".unit;
            vpnReconcile = reconcileConfigOf vpnHost;
            plainReconcile = reconcileConfigOf plainHost;
            vpnManifest = manifestFor vpnHost;
            plainManifest = manifestFor plainHost;
            passAsFile = [ "vpnManifest" "plainManifest" ];
          }
          ''
            set -eu

            fail() {
              echo "netns-apps-are-proxied-reachably: $1" >&2
              exit 1
            }

            confOf() {
              # Both halves out of the unit, so this reads the exact file
              # systemd will hand the exact binary -- not a reconstruction.
              grep -m1 '^ExecStart=' "$1/nginx.service" \
                | grep -o -- "-c '[^']*'" | cut -d"'" -f2
            }

            # A loopback upstream on a given port, in every spelling nginx
            # accepts for one. 127.0.0.0/8 as a class rather than the single
            # blessed string, for the same reason acceptedLoopbackSpellings
            # above is a class. printf '%s' with the pattern as an ARGUMENT,
            # so no backslash in it is eaten on the way out.
            loopbackRe() {
              printf '%s' "proxy_pass[[:space:]]\+https\?://\(127\.[0-9]\+\.[0-9]\+\.[0-9]\+\|localhost\|\[::1\]\):$1\b"
            }

            # The predicate, over a real nginx.conf, a real manifest and the
            # real reconciler config. Echoes every app it judged, so a
            # vacuous run is visible in the build log rather than
            # indistinguishable from a clean one.
            scan() {
              local conf="$1" manifest="$2" reconcile="$3" label="$4" n rc
              n=$(jq '.apps | length' "$manifest")
              [ "$n" -gt 0 ] || fail "$label: the manifest lists no enabled apps at all, so there is nothing to judge"

              jq -r '.apps[] | [.id, .vhost, .port, .isolation, .nginxHost, (.hasUnit|tostring), (.proxied|tostring)] | @tsv' "$manifest" \
              | while IFS="$(printf '\t')" read -r id vhost port isolation nginxhost hasunit proxied; do
                  [ "$hasunit" = "true" ] \
                    || fail "$label: no systemd unit named '$id' exists on the generated host, so this check cannot tell whether $id is in a network namespace -- teach it the unit name rather than leaving it unjudged"

                  # An app with no vhost is not skipped, it is held to the
                  # OPPOSITE requirement: nothing in the generated config
                  # may reach for it. That is the whole point of a headless
                  # app (modules/lib/app-submodule.nix), and leaving it
                  # merely unexamined would let a future change hand it a
                  # vhost with nobody noticing -- which is the defect this
                  # file exists to catch, in its purest form: a proxy_pass
                  # to a port that was never going to be bound.
                  if [ "$proxied" != "true" ]; then
                    echo "$label: $id has no vhost; asserting the config does not reach for it"
                    if grep -q "server_name $vhost" "$conf"; then
                      fail "$label: $id's manifest says it has no vhost, but the generated config contains a 'server_name $vhost'. Two readings of one fact disagreeing -- see modules/proxy/lib.nix's exposedApps."
                    fi
                    if grep -q "proxy_pass[[:space:]]\+https\?://[^;]*:$port\b" "$conf"; then
                      echo "--- offending lines ---" >&2
                      grep -n "proxy_pass[[:space:]]\+https\?://[^;]*:$port\b" "$conf" >&2 || true
                      fail "$label: $id gets no vhost, yet the generated config proxies to its port $port (lines above). Either it has a front door after all, or some other app has been pointed at this one's port."
                    fi
                    continue
                  fi

                  grep -q "server_name $vhost" "$conf" \
                    || fail "$label: the generated config has no $vhost vhost, so scanning it says nothing about $id"
                  grep -q "proxy_pass[[:space:]]\+https\?://[^;]*:$port\b" "$conf" \
                    || fail "$label: nothing in the generated config proxies to $id's port $port, so this check is reading the wrong corpus"

                  if [ "$isolation" != "-" ]; then
                    echo "$label: $id is isolated ($isolation), upstream host $nginxhost"
                    if grep -q "$(loopbackRe "$port")" "$conf"; then
                      echo "--- offending lines ---" >&2
                      grep -n "$(loopbackRe "$port")" "$conf" >&2 || true
                      fail "$id runs in its own network namespace ($isolation) and nginx -- which runs in the ROOT namespace -- is told to proxy it at a LOOPBACK address on port $port (lines above). Nothing is listening there, so that vhost 502s on every authenticated request while an unauthenticated probe still looks healthy, because Authelia answers it with a 302 first. Fix it where both consumers read it: modules/lib/app-address.nix."
                    fi
                  fi

                  reconcilerhost=$(jq -r --arg id "$id" '.apps[$id].host // "-"' "$reconcile")
                  [ "$nginxhost" = "$reconcilerhost" ] \
                    || fail "$label: nginx proxies $id at '$nginxhost' while ferrum-reconcile is told '$reconcilerhost'. Two independently generated files, for two consumers of ONE fact -- where $id actually listens -- disagreeing. That is exactly how this defect was introduced. See modules/lib/app-address.nix."
                done
              rc=$?

              # NOT left to `set -e`: the loop is a pipeline element and so
              # runs in a SUBSHELL, and `set -e` is suspended for the whole
              # body of a function called in an `if` condition -- which is
              # how the negative control below calls this. Without an
              # explicit return, scan would hand back the status of the echo
              # beneath it and the control would pass on a broken config.
              [ "$rc" -eq 0 ] || return "$rc"
              echo "$label: scanned $n enabled apps"
            }

            vpnConf=$(confOf "$vpnUnit")
            plainConf=$(confOf "$plainUnit")
            case "$vpnConf" in
              /nix/store/*) ;;
              *) fail "nginx.service's ExecStart does not pass a store config path (-c $vpnConf) -- services.nginx.enableReload is probably on and the file under test is now /etc/nginx/nginx.conf, which this check cannot see" ;;
            esac

            scan "$vpnConf" "$vpnManifestPath" "$vpnReconcile" vpn

            # Anti-vacuity, half one: the VPN host must actually CONTAIN an
            # isolated app, or the scan above exercised nothing.
            isolatedCount=$(jq '[.apps[] | select(.isolation != "-")] | length' "$vpnManifestPath")
            [ "$isolatedCount" -ge 1 ] \
              || fail "the VPN host's generated units show NO app in a network namespace, so the scan above exercised nothing. Either modules/apps/qbittorrent/service.nix no longer sets NetworkNamespacePath=, or declaring the \"qbittorrent-vpn\" secret no longer switches it on -- either way this check has to follow the mechanism rather than quietly testing a host that no longer has one."
            echo "vpn: $isolatedCount isolated app(s)"

            # Anti-vacuity, half one-b: BOTH branches of the proxied test
            # above must be reachable on this corpus. Without a proxied app
            # the whole original check is dead; without an unproxied one the
            # branch asserting "nothing reaches for it" is dead, and a dead
            # branch reads as coverage.
            proxiedCount=$(jq '[.apps[] | select(.proxied)] | length' "$vpnManifestPath")
            unproxiedCount=$(jq '[.apps[] | select(.proxied | not)] | length' "$vpnManifestPath")
            [ "$proxiedCount" -ge 1 ] \
              || fail "no enabled app on this fixture gets a vhost, so the reachability scan above judged nothing. The fixture enables the whole catalog with the proxy on; if none of them is published, modules/lib/app-submodule.nix's exposure default has changed."
            [ "$unproxiedCount" -ge 1 ] \
              || fail "every enabled app on this fixture gets a vhost, so the \"no vhost means nothing may reach for it\" branch above is unreachable. Either the catalog no longer contains a headless app -- in which case it also lost the exposure default that keeps it out of nginx, Authelia, ACME and DNS -- or that mark stopped doing anything."
            echo "vpn: $proxiedCount proxied, $unproxiedCount unproxied"

            # Anti-vacuity, half two: the fix, mechanically reverted. Every
            # isolated app's upstream is rewritten back to 127.0.0.1 and the
            # SAME predicate is re-run on it; it must reject.
            sed "$(jq -r '.apps[] | select(.isolation != "-")
                   | "s|proxy_pass http://" + .nginxHost + ":" + .port + ";|proxy_pass http://127.0.0.1:" + .port + ";|g"' \
                   "$vpnManifestPath")" "$vpnConf" > reverted.conf
            if cmp -s "$vpnConf" reverted.conf; then
              fail "rewriting every isolated app's upstream back to loopback changed nothing in the generated config, so the negative control below would be the positive one again -- either the upstream is already loopback, or it is no longer spelled the way this rewrite expects"
            fi
            if scan reverted.conf "$vpnManifestPath" "$vpnReconcile" reverted > reverted.log 2>&1; then
              cat reverted.log >&2
              fail "the scan PASSED on a config whose isolated-app upstreams were rewritten back to 127.0.0.1 -- it cannot detect the defect it exists to detect"
            fi
            grep -q 'runs in its own network namespace' reverted.log \
              || { cat reverted.log >&2; fail "the scan rejected the reverted config, but for some reason other than the loopback upstream, so the negative control proves nothing"; }
            echo "reverted-control: rejected, as it must be"

            # Anti-vacuity, half three: a host with NO VPN secret. Nothing is
            # isolated, nothing is demanded, and qBittorrent's upstream is
            # still plain loopback -- the "non-VPN output is unchanged" half
            # of the requirement, asserted rather than assumed.
            plainIsolated=$(jq '[.apps[] | select(.isolation != "-")] | length' "$plainManifestPath")
            [ "$plainIsolated" -eq 0 ] \
              || fail "a host with no \"qbittorrent-vpn\" secret shows $plainIsolated app(s) in a network namespace -- the kill switch is being built on hosts that did not ask for it"
            scan "$plainConf" "$plainManifestPath" "$plainReconcile" plain
            qbtPort=$(jq -r '.apps[] | select(.id == "qbittorrent") | .port' "$plainManifestPath")
            grep -q "proxy_pass http://127.0.0.1:$qbtPort;" "$plainConf" \
              || fail "on a host with no VPN secret qBittorrent is no longer proxied at http://127.0.0.1:$qbtPort -- the non-VPN output was supposed to be byte-identical"
            echo "plain: nothing isolated, qBittorrent still at 127.0.0.1:$qbtPort"

            echo ok > $out
          '';

      # An app with no web interface gets NO front door, on all four of the
      # surfaces that make one -- and cannot be given one by accident.
      #
      # WHY THIS IS A SEPARATE CHECK FROM netnsAppsAreProxiedReachably.
      # That one reads the generated nginx.conf, and nginx is only one of
      # four independent generators keyed on modules/proxy/lib.nix's
      # exposedApps/publicApps: authelia.nix writes an access_control rule,
      # acme.nix orders a certificate, dns.nix publishes a public A record.
      # modules/proxy/lib.nix's own header says, about the DAEMON, that
      # those four "must agree EXACTLY or the dashboard only half-exists".
      # The same is true in the negative direction here, and it is worse: a
      # certificate and a public DNS record for a name that can never answer
      # are a durable, externally visible artefact -- the certificate is
      # logged to Certificate Transparency and the record is in a zone
      # anyone can query -- while the nginx half merely 502s.
      #
      # EVERY ASSERTION BELOW IS READ OFF THE EVALUATED CONFIGURATION, never
      # off the catalog mark that is supposed to produce it, and never off a
      # list of app names. The fixture enables the WHOLE catalog, so a future
      # headless app joins this corpus by existing.
      #
      # It has four parts, and the last two are what stop it agreeing with
      # itself:
      #
      #   1. no headless app's hostname appears in any of the four.
      #   2. a POSITIVE CONTROL: a non-headless app's hostname appears in
      #      all four. Without it, a detector that always answered "absent"
      #      -- a renamed option, a fixture that stopped generating anything
      #      -- would pass part 1 triumphantly.
      #   3. an ANTI-VACUITY floor: the catalog must actually contain a
      #      headless app, or part 1 ranges over nothing.
      #   4. a NEGATIVE CONTROL on the only route by which a headless app
      #      could acquire a front door: `exposure` is an operator-settable
      #      option, reachable from custom/ and from a hand-edited
      #      settings.json. Setting it to "public" must be REFUSED at eval
      #      (modules/core/options.nix's headlessViolations), and the same
      #      probe must find the catalog default accepted -- otherwise the
      #      refusal could be unconditional and prove nothing.
      headlessAppsGetNoFrontDoor =
        let
          baseDomain = "example.test";

          # The whole catalog, proxy on, SSO on, DNS on -- i.e. every
          # generator that can produce a front door is switched on, and
          # every app is at its own default exposure. That default is
          # "public" for an ordinary app, which is what makes part 2's
          # positive control real rather than arranged.
          mkFullHost = extra: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              proxy = {
                enable = true;
                inherit baseDomain;
                acme.email = "a@${baseDomain}";
                dns = {
                  enable = true;
                  recordMode = "a";
                  staticAddress = "203.0.113.10";
                };
              };
              auth = { enable = true; adminEmail = "a@${baseDomain}"; };
              apps = lib.mapAttrs (_: _: { enable = true; }) catalog // extra;
            };
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
            ];
          };

          cfg = (mkFullHost { }).config;

          vhostNames = builtins.attrNames cfg.services.nginx.virtualHosts;
          certNames = builtins.attrNames cfg.security.acme.certs;
          autheliaDomains = map (r: r.domain)
            cfg.services.authelia.instances.main.settings.access_control.rules;

          hostnameOf = id: "${cfg.ferrum.apps.${id}.subdomain}.${baseDomain}";

          # One row per enabled app, each field read off the evaluated
          # configuration. The DNS column is absent on purpose: unlike the
          # other three, modules/proxy/dns.nix's record set is a DERIVATION
          # (system.build.ferrumDnsConfig, a JSON file), so it is carried in
          # as a build input below and joined to this manifest in the
          # builder -- the same shape netnsAppsAreProxiedReachably uses, and
          # for the same reason: reading the real artefact beats
          # re-deriving it here and then agreeing with myself.
          manifest = builtins.toJSON {
            apps = lib.mapAttrsToList
              (id: _: {
                inherit id;
                hostname = hostnameOf id;
                headless = catalog.${id}.headless or false;
                vhost = builtins.elem (hostnameOf id) vhostNames;
                cert = builtins.elem (hostnameOf id) certNames;
                authelia = builtins.elem (hostnameOf id) autheliaDomains;
              })
              (lib.filterAttrs (_: a: a.enable) cfg.ferrum.apps);
          };

          headlessIds = builtins.attrNames
            (lib.filterAttrs (_: m: m.headless or false) catalog);

          # Part 4. Scoped to this assertion's own message, on a phrase it
          # keeps to one line -- the same discipline every tryEval probe in
          # this file uses, and for the same reason.
          refusesExposure = id: exposure:
            let
              probe = builtins.tryEval (
                builtins.filter (m: lib.hasInfix "has been given one anyway" m)
                  (map (a: a.message)
                    (builtins.filter (a: !a.assertion)
                      (mkFullHost { ${id} = { enable = true; inherit exposure; }; })
                        .config.assertions)));
            in
            if probe.success then probe.value != [ ] else true;

          notRefused = builtins.filter (id: !(refusesExposure id "public")) headlessIds;
          refusedAtDefault = builtins.filter (id: refusesExposure id "local") headlessIds;
        in
        pkgs.runCommand "ferrum-check-headless-apps-get-no-front-door"
          {
            nativeBuildInputs = [ pkgs.jq ];
            inherit manifest;
            passAsFile = [ "manifest" ];
            dnsConfig = cfg.system.build.ferrumDnsConfig;
            # Part 4's verdict, carried in rather than re-derived in shell:
            # it is a statement about the module system, which only Nix can
            # evaluate. Empty strings mean "clean", which is what the two
            # tests below require.
            notRefused = lib.concatStringsSep " " notRefused;
            refusedAtDefault = lib.concatStringsSep " " refusedAtDefault;
          }
          ''
            set -eu

            fail() {
              echo "headless-apps-get-no-front-door: $1" >&2
              echo "--- manifest ---" >&2; jq . "$manifestPath" >&2
              echo "--- dns records ---" >&2; jq '.records' "$dnsConfig" >&2
              exit 1
            }

            # Join the DNS artefact onto the manifest, so every row carries
            # all four surfaces and one loop judges them together.
            jq --slurpfile dns "$dnsConfig" \
              '($dns[0].records | map(.name)) as $names
               | [ .apps[] | . as $r | $r + { dns: ($names | index($r.hostname) != null) } ]' \
              "$manifestPath" > rows.json

            total=$(jq 'length' rows.json)
            headless=$(jq '[.[] | select(.headless)] | length' rows.json)
            fronted=$(jq '[.[] | select(.headless | not)] | length' rows.json)

            # Anti-vacuity, both directions. Part 1 over an empty set passes
            # for free, and part 2's positive control over an empty set
            # proves the detector works on nothing.
            [ "$total" -gt 0 ] || fail "the fixture enabled no apps at all, so nothing below judged anything"
            [ "$headless" -ge 1 ] \
              || fail "no enabled app declares headless = true, so the absence test below ranges over nothing. Either the catalog lost its headless app -- in which case it also lost the exposure default that keeps it out of nginx, Authelia, ACME and DNS -- or modules/lib/catalog.nix stopped carrying the mark."
            [ "$fronted" -ge 1 ] \
              || fail "no enabled app is published, so the positive control below cannot distinguish 'headless apps get nothing' from 'this check can see nothing'"

            # Part 1: a headless app has none of the four.
            if ! jq -e '[.[] | select(.headless) | select(.vhost or .cert or .authelia or .dns)] | length == 0' rows.json > /dev/null; then
              jq -r '.[] | select(.headless) | select(.vhost or .cert or .authelia or .dns)
                     | "  " + .id + " (" + .hostname + "):"
                       + (if .vhost then " nginx-vhost" else "" end)
                       + (if .cert then " acme-certificate" else "" end)
                       + (if .authelia then " authelia-rule" else "" end)
                       + (if .dns then " public-dns-record" else "" end)' rows.json >&2
              fail "an app that listens on NOTHING has been given a front door (above). A vhost proxies to a port no process will ever bind, which 502s on every real request while Authelia's 302 makes an unauthenticated probe look healthy -- the defect 2ec53b6 fixed. The certificate and the DNS record are worse than that: both are durable and externally visible, one in Certificate Transparency and one in a public zone. See modules/lib/app-submodule.nix's exposure default."
            fi

            # Part 2: the positive control. Every published app has all four,
            # so an absence in part 1 is evidence rather than blindness.
            if ! jq -e '[.[] | select(.headless | not) | select((.vhost and .cert and .authelia and .dns) | not)] | length == 0' rows.json > /dev/null; then
              jq -r '.[] | select(.headless | not) | select((.vhost and .cert and .authelia and .dns) | not)
                     | "  " + .id + " (" + .hostname + ") is missing:"
                       + (if .vhost then "" else " nginx-vhost" end)
                       + (if .cert then "" else " acme-certificate" end)
                       + (if .authelia then "" else " authelia-rule" end)
                       + (if .dns then "" else " public-dns-record" end)' rows.json >&2
              fail "an ordinary app at its default exposure did NOT get one of the four artefacts (above). Part 1 above proves nothing while this is true: it would report 'headless apps have no vhost' on a fixture where NOBODY has a vhost."
            fi

            # Part 4: the only route by which a headless app could acquire a
            # front door is an operator setting exposure, and it must be
            # refused at evaluation rather than silently ignored.
            [ -z "$notRefused" ] \
              || fail "setting exposure = \"public\" on these headless apps was ACCEPTED: $notRefused. modules/core/options.nix's headlessViolations assertion is supposed to refuse it; without that refusal, every artefact part 1 checks comes back the moment anyone edits settings.json or drops a module in custom/."
            [ -z "$refusedAtDefault" ] \
              || fail "the headless exposure refusal also fires at the catalog DEFAULT for: $refusedAtDefault. An assertion that rejects the configuration ferrum itself generates is unconditional, so the negative control above proves nothing about what it actually detects."

            echo "judged $total enabled apps: $headless headless (no vhost, no certificate, no Authelia rule, no DNS record), $fronted published (all four present)"
            echo "exposure = \"public\" on a headless app: refused at eval; the default is accepted"
            echo ok > $out
          '';

      # Decluttarr's generated configuration agrees with what ferrum
      # actually did to the rest of the host.
      #
      # modules/apps/decluttarr/service.nix generates that file at eval time
      # out of three facts ferrum already owns: where each app listens, what
      # the download client is CALLED inside the *arrs, and which API keys
      # exist. Each of those has a second owner elsewhere in the tree, and a
      # disagreement between the two is silent in a specific and nasty way:
      # Decluttarr does not crash, it logs "not reachable" or quietly matches
      # nothing, every half hour, forever. There is no 502 and no failed
      # unit -- just a janitor that stopped working.
      #
      #   * THE NAME. crates/ferrum-reconcile/src/main.rs registers the
      #     download client in Sonarr and Radarr as `"name": provider_id` --
      #     the bare catalog id. Decluttarr matches a queue item to a client
      #     by exactly that string (src/settings/_download_clients.py's
      #     get_download_client_by_name); get it wrong and every
      #     torrent-specific decision silently degrades to a plain remove,
      #     including for the private-tracker and "Keep"-tagged cases the
      #     service module is careful about.
      #
      #   * THE ADDRESS. modules/lib/app-address.nix's header names exactly
      #     this risk: "a THIRD consumer that hand-copies 127.0.0.1 fails
      #     there instead of in the field". Decluttarr is that third
      #     consumer. The fixture is therefore a VPN host, where qBittorrent
      #     is NOT on loopback, and the check compares Decluttarr's own
      #     base_url against the address the reconciler was given.
      #
      #   * THE KEY. The generated template lives in the world-readable Nix
      #     store, so it must contain no API key at all -- the real one is
      #     inserted into a tmpfs copy at start by the unit's root
      #     ExecStartPre. That is a security property of the design, and an
      #     innocent-looking edit (interpolating the key "just for
      #     simplicity") would publish every *arr key to every local user.
      #
      # Everything is read from the generated artefacts: the template is
      # found by following the unit's own ExecStartPre script, never passed
      # in from Nix, so the file under test is provably the file systemd
      # will hand the binary.
      decluttarrKnowsTheClientFerrumRegistered =
        let
          vpnDecluttarrHost = ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
              apps = {
                sonarr.enable = true;
                radarr.enable = true;
                qbittorrent.enable = true;
                decluttarr.enable = true;
              };
            };
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
              # The only way to make qBittorrent non-loopback, which is what
              # makes the address half of this check non-vacuous.
              { ferrum.secrets."qbittorrent-vpn" = { }; }
            ];
          };
          dcfg = vpnDecluttarrHost.config;
        in
        pkgs.runCommand "ferrum-check-decluttarr-knows-the-client-ferrum-registered"
          {
            nativeBuildInputs = [ pkgs.jq pkgs.gnugrep ];
            # The unit's own pre-start script, as a store path. Reading the
            # template out of THIS is what makes the assertions below about
            # the real unit rather than about a value re-derived here.
            preScript = dcfg.systemd.services.decluttarr.serviceConfig.ExecStartPre;
            reconcileConfig =
              dcfg.systemd.services.ferrum-reconcile.environment.FERRUM_RECONCILE_CONFIG;
            reconcileSrc = ../../../crates/ferrum-reconcile/src/main.rs;
            clientName = catalog.qbittorrent.id;
          }
          ''
            set -eu

            fail() {
              echo "decluttarr-knows-the-client-ferrum-registered: $1" >&2
              exit 1
            }

            # ExecStartPre carries systemd's "+" privilege prefix, which is
            # not part of the path.
            script=''${preScript#+}
            case "$script" in
              /nix/store/*) ;;
              *) fail "decluttarr.service's ExecStartPre is '$preScript', which is not a store path -- this check cannot read the config it renders" ;;
            esac

            template=$(grep -o '/nix/store/[^ "'"'"']*-decluttarr-config-template\.json' "$script" | head -n1)
            [ -n "$template" ] \
              || fail "decluttarr.service's pre-start script no longer references a decluttarr-config-template.json, so this check cannot find the generated configuration at all. If the rendering moved, teach this check where -- do not leave it reading nothing."
            [ -f "$template" ] || fail "the template path '$template' found in the pre-start script does not exist"
            echo "template: $template"

            # ---- the key must NOT be here ----
            keys=$(jq -r '[.instances[][] | .api_key] | map(select(. != "")) | join(", ")' "$template")
            [ -z "$keys" ] \
              || fail "the generated template in the WORLD-READABLE Nix store contains a non-empty api_key ($keys). Every local user can read /nix/store. The key belongs only in the tmpfs copy the unit's root ExecStartPre renders at start -- see modules/apps/decluttarr/service.nix."
            arrCount=$(jq '[.instances[][]] | length' "$template")
            [ "$arrCount" -ge 1 ] \
              || fail "the generated template configures no *arr instance at all, so the empty-key assertion above passed over an empty list"
            echo "api keys in the store template: none, over $arrCount configured *arr instance(s)"

            # ---- the name must be the one ferrum-reconcile registers ----
            name=$(jq -r '.download_clients.qbittorrent[0].name' "$template")
            [ "$name" = "$clientName" ] \
              || fail "Decluttarr is told the download client is called '$name', but ferrum-reconcile registers it as '$clientName'. Decluttarr matches a queue item to its client by that exact string, so a mismatch silently turns every torrent-aware decision into a plain remove -- the private-tracker and protected-tag handling in modules/apps/decluttarr/service.nix stop applying, with nothing logged."

            # And the Rust side of that claim, pinned rather than assumed.
            grep -q '"name": provider_id' "$reconcileSrc" \
              || fail "crates/ferrum-reconcile/src/main.rs no longer registers a download client as '\"name\": provider_id', so the assertion above is comparing Decluttarr's config against a convention that has changed. Find the new name and teach both ends."

            # ---- the address must be the one the reconciler was given ----
            for app in qbittorrent sonarr radarr; do
              if [ "$app" = qbittorrent ]; then
                want_url=$(jq -r '.download_clients.qbittorrent[0].base_url' "$template")
              else
                want_url=$(jq -r --arg a "$app" '.instances[$a][0].base_url' "$template")
              fi
              rhost=$(jq -r --arg a "$app" '.apps[$a].host' "$reconcileConfig")
              rport=$(jq -r --arg a "$app" '.apps[$a].port' "$reconcileConfig")
              [ "$want_url" = "http://$rhost:$rport" ] \
                || fail "Decluttarr is pointed at $app via '$want_url' while ferrum-reconcile is told it lives at '$rhost:$rport'. Two independently generated files, for two consumers of ONE fact -- where $app actually listens. That is the defect 2ec53b6 fixed, in its third consumer. See modules/lib/app-address.nix."
              echo "$app: $want_url, agreeing with the reconciler"
            done

            # Anti-vacuity: on this fixture qBittorrent must genuinely NOT be
            # on loopback, or the address comparison above is three copies of
            # "127.0.0.1" agreeing with each other and would pass for an
            # implementation that hardcoded it.
            qhost=$(jq -r '.apps.qbittorrent.host' "$reconcileConfig")
            case "$qhost" in
              127.*|localhost|"[::1]")
                fail "this fixture declares the \"qbittorrent-vpn\" secret, yet qBittorrent is still reached at '$qhost'. The network namespace is what makes the address assertion above mean something; without it this check would pass for a Decluttarr module that hardcoded loopback." ;;
            esac
            echo "qbittorrent is at $qhost, off loopback, so the address assertions were real"

            echo ok > $out
          '';

      mkAssertionCheck = name: result:
        pkgs.runCommand "ferrum-check-${name}" { } (
          if result.ok then
            "echo '${name}: ok' > $out"
          else
            throw "ferrum check '${name}' failed: ${builtins.toJSON (removeAttrs result [ "ok" ])}"
        );
    in
    {
      checks = {
        a-host-always-has-a-way-in = aHostAlwaysHasAWayIn;
        auth-model-enforced = mkAssertionCheck "auth-model-enforced" authModelEnforced;
        daemon-vhost-enforced = mkAssertionCheck "daemon-vhost-enforced" daemonVhostEnforced;
        daemon-unpublished-but-running = daemonUnpublishedButRunning;
        authelia-cookie-scope = autheliaCookieScope;
        authelia-asserts-only-its-own-scope = autheliaAssertsOnlyItsOwnScope;
        nginx-config-parses = nginxConfigParses;
        reserved-subdomain-collision =
          mkAssertionCheck "reserved-subdomain-collision" reservedSubdomainCollision;
        duplicate-subdomain-collision =
          mkAssertionCheck "duplicate-subdomain-collision" duplicateSubdomainCollision;
        nginx-emits-no-cors-headers =
          mkAssertionCheck "nginx-emits-no-cors-headers" nginxEmitsNoCorsHeaders;
        root-folders-reach-the-apps = rootFoldersReachTheApps;
        wireguard-config-with-many-addresses = wireguardConfigWithManyAddresses;
        netns-apps-are-proxied-reachably = netnsAppsAreProxiedReachably;
        dns-record-set = dnsRecordSet;
        ddns-updater-needs-no-static-address =
          mkAssertionCheck "ddns-updater-needs-no-static-address" ddnsUpdaterNeedsNoStaticAddress;
        catalog-consistency = mkAssertionCheck "catalog-consistency" catalogConsistency;
        schema-uniformity = mkAssertionCheck "schema-uniformity" schemaUniformity;
        ui-renders-every-schema-type =
          mkAssertionCheck "ui-renders-every-schema-type" uiRendersEverySchemaType;
        updates-view-is-wired =
          mkAssertionCheck "updates-view-is-wired" updatesViewIsWired;
        pool-branches-are-all-seeded =
          mkAssertionCheck "pool-branches-are-all-seeded" poolBranchesAreAllSeeded;
        pool-assertions-can-fire =
          mkAssertionCheck "pool-assertions-can-fire" poolAssertionsCanFire;
        parity-disk-is-never-a-pool-branch =
          mkAssertionCheck "parity-disk-is-never-a-pool-branch" parityDiskIsNeverAPoolBranch;
        parity-excludes-only-the-churn =
          mkAssertionCheck "parity-excludes-only-the-churn" parityExcludesOnlyTheChurn;
        parity-timers-self-heal =
          mkAssertionCheck "parity-timers-self-heal" parityTimersSelfHeal;
        parity-view-is-wired =
          mkAssertionCheck "parity-view-is-wired" parityViewIsWired;
        app-detail-view-is-wired =
          mkAssertionCheck "app-detail-view-is-wired" appDetailViewIsWired;
        vpn-metadata-matches-the-unit =
          mkAssertionCheck "vpn-metadata-matches-the-unit" vpnMetadataMatchesTheUnit;
        parity-never-claims-to-be-a-backup =
          mkAssertionCheck "parity-never-claims-to-be-a-backup" parityNeverClaimsToBeABackup;
        media-tree-waits-for-its-mounts =
          mkAssertionCheck "media-tree-waits-for-its-mounts" mediaTreeWaitsForItsMounts;
        branch-roots-are-ownership-checked =
          mkAssertionCheck "branch-roots-are-ownership-checked" branchRootsAreOwnershipChecked;
        branch-ownership-guard-behaves = branchOwnershipGuardBehaves;
        fixed-ports-are-enforced =
          mkAssertionCheck "fixed-ports-are-enforced" fixedPortsAreEnforced;
        selfsigned-cert-tracks-its-domain =
          mkAssertionCheck "selfsigned-cert-tracks-its-domain" selfSignedCertTracksItsDomain;
        recyclarr-needs-an-arr =
          mkAssertionCheck "recyclarr-needs-an-arr" recyclarrNeedsAnArr;
        extra-unfree-packages-compose =
          mkAssertionCheck "extra-unfree-packages-compose" extraUnfreePackagesCompose;
        settings-schema-covers-every-option =
          mkAssertionCheck "settings-schema-covers-every-option" schemaCoversEveryOption;
        installer-offers-every-catalog-app =
          mkAssertionCheck "installer-offers-every-catalog-app" installerOffersEveryCatalogApp;
        sopsfile-are-paths = mkAssertionCheck "sopsfile-are-paths" sopsFilesArePaths;
        migration-mechanism = mkAssertionCheck "migration-mechanism" migrationMechanism;
        journaldir-collision = mkAssertionCheck "journaldir-collision" journalDirCollision;
        storage-path-nesting = mkAssertionCheck "storage-path-nesting" storagePathNesting;
        mkhost-applies-migration = mkAssertionCheck "mkhost-applies-migration" mkHostAppliesMigration;
        directive-separators-never-reach-a-generated-file =
          mkAssertionCheck "directive-separators-never-reach-a-generated-file"
            directiveSeparatorsNeverReachAGeneratedFile;
        schema-refuses-every-separator-payload =
          mkAssertionCheck "schema-refuses-every-separator-payload"
            schemaRefusesEverySeparatorPayload;

        # Forces .drvPath for each example host so an option-type mistake
        # fails fast, without a full build -- true for the catalog apps
        # themselves. NOT true once any sops.secrets exist on a host
        # (which the example host's placeholder secrets under
        # examples/hosts/minimal/secrets/ now do, on purpose, to exercise
        # the real default sops.validateSopsFiles = true): sops-nix's own
        # system.activationScripts.setupSecrets needs sops-install-secrets
        # (a real Haskell program) actually realized to build its text,
        # not just referenced by hash. Confirmed for real, repeatedly, on
        # ferrum-dev (a 79GB VM): this now costs well beyond the original
        # ~1293-store-path/~8.7GB measurement -- three consecutive attempts
        # each hit ENOSPC after freeing 70+GB via `nix-store --gc`
        # immediately beforehand, meaning peak usage is somewhere north of
        # that freed amount. Standard GitHub-hosted runners do not
        # reliably have that much free disk, so this check is
        # DELIBERATELY NOT wired into any CI job (see .github/workflows/
        # ci.yml's "cheap checks" step, which used to include it and no
        # longer does) -- run it by hand, on ferrum-dev or an equivalent
        # real machine with disk to spare, when touching anything under
        # modules/apps/ or modules/core/secrets.nix. This is an accepted,
        # deliberate scope decision, not a silently-dropped check: the
        # regression it existed to catch for THIS branch's own bug
        # (sopsFile's isPath requirement) is covered instead by the
        # genuinely cheap sopsfile-are-paths check above, which needs no
        # realization at all.
        eval-example-hosts = pkgs.runCommand "ferrum-check-eval-example-hosts"
          {
            drvPaths = builtins.toJSON
              (lib.mapAttrsToList
                (name: host: { inherit name; drvPath = host.config.system.build.toplevel.drvPath; })
                exampleHosts);
          }
          "echo $drvPaths > $out";

        # ferrum-secrets is a LIBRARY crate with no package of its own, and
        # every package that depends on it sets buildAndTestSubdir to its own
        # crate -- so `cargo test` never reaches ferrum-secrets' own five
        # tests, even though its code compiles into both ferrum-apply and
        # ferrumd. Without this check the shared encrypt-and-write path that
        # BOTH the privileged applier and the unprivileged daemon rely on is
        # the one part of the workspace CI does not test.
        #
        # Deliberately a real buildRustPackage over the whole workspace
        # rather than a bare `cargo test` in a runCommand: that is what puts
        # the pinned toolchain and the vendored Cargo.lock closure in play,
        # matching how every other Rust artifact here is built. The runtime
        # tools are the union of what the workspace's tests shell out to --
        # btrfs (preflight::check_is_subvolume), sops/ssh-to-age (secrets),
        # authelia (argon2id hashing), dig (ferrum-dns::dns_query's
        # authoritative-nameserver check). Confirmed real, by really running the
        # suite in a container on 2026-09-15: without btrfs on PATH,
        # is_subvolume_check_fails_on_a_plain_directory fails on the spawn
        # error rather than the assertion it means to make.
        workspace-tests = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-workspace-tests";
          version = "0.1.0";

          # The source root is the REPOSITORY, not crates/, and must stay
          # in step with nix/pkgs/ferrum-install/default.nix: render.rs
          # does include_str! on examples/hosts/template/disko.nix so that
          # a drift between the generated btrfs subvolume layout and the
          # template is a compile error rather than a silent host that
          # cannot roll back. That path escapes crates/.
          #
          # This derivation compiles the same crate as that package and was
          # missed when the package's root was changed -- CI caught it,
          # because `cargo test` run by hand does not reproduce a Nix
          # sandbox's view of the tree.
          src = lib.cleanSourceWith {
            src = ../../..;
            filter = path: type:
              let rel = lib.removePrefix (toString ../../.. + "/") (toString path); in
              lib.hasPrefix "crates" rel || lib.hasPrefix "examples" rel
              # flake.lock too: render.rs include_str!s it so the disko
              # revision generated hosts pin cannot drift from the one this
              # repository tests against. disko partitions the target as
              # root, so an unpinned or untested revision there is remote
              # code execution on the destructive path. Same class of
              # escape-from-crates/ as the template above -- and, again,
              # invisible to `cargo test` run by hand.
              || rel == "flake.lock"
              || (type == "directory" && (rel == "crates" || rel == "examples"));
          };
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          cargoRoot = "crates";
          buildAndTestSubdir = "crates";
          # pkgs.dnsutils provides `dig`, which ferrum-dns' dns_query tests
          # really invoke against a fake nameserver on loopback. It is here
          # for exactly the reason btrfs-progs is (see the header above):
          # without it those tests fail on the spawn error rather than the
          # assertion they mean to make.
          nativeCheckInputs = [ pkgs.btrfs-progs pkgs.sops pkgs.ssh-to-age pkgs.authelia pkgs.git pkgs.dnsutils ];
          # The point of this derivation is the checkPhase; nothing consumes
          # its binaries, so skip the install entirely.
          installPhase = "touch $out";
        };

        smoke-vm = import ../../../tests/smoke.nix { inherit pkgs; };

        # Phase 1.6a: the first test that starts from NOTHING. Two nodes --
        # an operator machine running the real ferrum-install binary, and a
        # target whose disk is blank. Every other VM test in this file
        # builds a host from an expression and then drives it, which is
        # exactly the gap the design doc's install postmortem names: six of
        # that install's ten defects were invisible to a suite shaped that
        # way.
        #
        # Stage 2 is deliberately NOT here and cannot be: the sandbox has
        # no network and no in-guest nixpkgs evaluation, and stage 2 exists
        # precisely so each app's sopsFile is created at runtime on the
        # guest, which rules out the pre-built-closure trick that makes the
        # other tests possible. It lives in the networked CI job instead.
        install-from-nothing = import ../../../tests/install-from-nothing.nix {
          inherit pkgs;
          ferrumInstall = self'.packages.ferrum-install;
        };

        # tests/rollback.nix is the plan's terminal proof: a real rollback
        # reverts application STATE. rollback-proves-necessity.nix is its
        # companion, proving the failure mode the mechanism exists to
        # prevent is real in the first place. apply-generation-switch.nix
        # (below) proves the other half of the pair: the CLOSURE reverts
        # too, against a genuinely different generation.
        rollback = import ../../../tests/rollback.nix { inherit pkgs; sopsNix = inputs.sops-nix; };
        rollback-proves-necessity = import ../../../tests/rollback-proves-necessity.nix { inherit pkgs; };

        # Closes the one gap tests/rollback.nix's own header discloses: a
        # real generation switch between two genuinely different closures,
        # not just application state, actually reverts on rollback.
        apply-generation-switch = import ../../../tests/apply-generation-switch.nix { inherit pkgs; sopsNix = inputs.sops-nix; };

        # Proves systemd itself honors ConditionPathExists and holds
        # ferrum-managed apps down when the (durable, per Fix 1) failure
        # marker is present -- the property the interlock actually depends
        # on, which neither rollback.nix nor the restore_state.rs unit tests
        # exercise directly.
        state-restore-interlock = import ../../../tests/state-restore-interlock.nix { inherit pkgs; };

        # Proves the real privilege boundary Task 2 built, in BOTH
        # directions (not just that the polkit rule text parses): the real
        # `ferrum` service account really can trigger a real ferrum-apply
        # run via D-Bus + polkit, an ordinary unprivileged account really
        # is DENIED the identical call, and neither may start an unrelated
        # unit. The two-directional form is deliberate -- this test used to
        # assert only that "an unprivileged user can trigger a run", which
        # passed because the rule had no subject check at all.
        privilege-boundary = import ../../../tests/privilege-boundary.nix { inherit pkgs; sopsNix = inputs.sops-nix; };

        # Not a separate runCommand: Nix's build sandbox has no network
        # access, so a hand-rolled `cd crates && cargo test` derivation can
        # never fetch crates.io and fails every time (verified: it does).
        # `rustPlatform.buildRustPackage` avoids this by vendoring
        # dependencies from Cargo.lock as a fixed-output derivation *before*
        # the sandboxed build; its default cargoCheckHook already runs
        # `cargo test` as part of building the package normally, so
        # `packages.ferrum-apply` itself IS the cargo-test check -- aliasing
        # it here just gives it a name under `checks`.
        cargo-test-ferrum-apply = self'.packages.ferrum-apply;

        # Clippy needs its own derivation (buildRustPackage's default check
        # phase runs `cargo test`, not clippy), but reuses the same
        # Cargo.lock-based vendoring so it builds offline too.
        clippy-ferrum-apply = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-apply-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          # `-p`, not buildAndTestSubdir: this derivation replaces buildPhase
          # with `true`, which skips the hook that would cd into the subdir --
          # so cargo ran at the workspace root and linted EVERY member. That
          # made this check fail on a defect in a crate it does not own, and
          # made it unable to say which crate was at fault.
          checkPhase = "cargo clippy --offline -p ferrum-apply --all-targets -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        # ferrum-install had NO lint gate at all -- the three derivations
        # around it scope to ferrum-apply, ferrum-reconcile and ferrumd via
        # buildAndTestSubdir, and none covered it. That made the one crate
        # holding every Critical in this feature the one crate nothing
        # linted, and two real clippy errors had accumulated unnoticed.
        #
        # Unlike its siblings this cannot use `src = cleanSource ../crates`:
        # render.rs include_str!s examples/hosts/template/disko.nix and
        # flake.lock, both of which escape crates/. Same root and filter as
        # workspace-tests above -- keep the three in step.
        #
        # --all-targets, so test code is linted too. One of the two errors
        # this found was in a test.
        clippy-ferrum-install = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-install-clippy";
          version = "0.1.0";
          src = lib.cleanSourceWith {
            src = ../../..;
            filter = path: type:
              let rel = lib.removePrefix (toString ../../.. + "/") (toString path); in
              lib.hasPrefix "crates" rel || lib.hasPrefix "examples" rel
              || rel == "flake.lock"
              || (type == "directory" && (rel == "crates" || rel == "examples"));
          };
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          cargoRoot = "crates";
          buildAndTestSubdir = "crates";
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          # cd explicitly: the custom buildPhase above skips the step that
          # would otherwise honour cargoRoot, so cargo runs at the source
          # root where there is no Cargo.toml.
          checkPhase = "cd crates && cargo clippy --offline -p ferrum-install --all-targets -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        # The guard on the escape hatch, asserted against the ARTIFACTS
        # rather than the source.
        #
        # `tests/stage2/run.sh` needs A5's Cloudflare token check to pass
        # while installing to `s13.invalid`, a domain in nobody's Cloudflare
        # account. It gets there by building `.#ferrum-install-testing`,
        # which compiles the `test-cloudflare-endpoint` feature and with it
        # a second body for `answers::cloudflare_client` that honours
        # FERRUM_CLOUDFLARE_API_BASE. The operator's installer must have no
        # such thing: an offline ferrum install produces a media server
        # nobody can reach, so a redirectable endpoint in the shipped binary
        # is a way to finish an install that publishes nothing.
        #
        # A `#[cfg]` already makes that true. This check exists because the
        # obvious "simplification" -- collapsing the two bodies into one
        # with a runtime `if` -- looks harmless, passes every unit test, and
        # silently reintroduces exactly that. The property is therefore
        # proved mechanically, by looking for the variable's name in the
        # built closure.
        #
        # The second half is a positive control, and it is not decoration:
        # a grep that finds nothing proves nothing unless the same grep is
        # shown to find something when it should. Rename the variable and
        # this check fails on the control rather than passing vacuously.
        production-installer-has-no-api-override =
          pkgs.runCommand "ferrum-check-no-api-override" { } ''
            needle=FERRUM_CLOUDFLARE_API_BASE

            # -r because makeWrapper leaves $out/bin holding a shell wrapper
            # beside the real ELF; the string could be in either.
            if grep -rq "$needle" ${self'.packages.ferrum-install}/bin; then
              echo "the production installer can be redirected away from Cloudflare:"
              echo "  $needle appears in ${self'.packages.ferrum-install}/bin"
              echo
              echo "That name must exist only under the test-cloudflare-endpoint"
              echo "feature. If someone replaced the two cfg-gated bodies of"
              echo "answers::cloudflare_client with one runtime branch, put them back:"
              echo "A5's token check is what stops an install finishing while it can"
              echo "publish nothing, and a shipped override is a way around it."
              exit 1
            fi

            if ! grep -rq "$needle" ${self'.packages.ferrum-install-testing}/bin; then
              echo "the positive control failed: $needle is absent from the TESTING"
              echo "installer too, so the check above proved nothing."
              echo
              echo "Either the feature no longer compiles that code path, or the"
              echo "variable was renamed. Update this check to match the new name."
              exit 1
            fi

            echo "the production installer has no Cloudflare endpoint override;"
            echo "the testing build does, so the grep is known to work"
            touch $out
          '';

        # ferrum-dns is a LIBRARY crate with no package of its own, so unlike
        # its siblings there is no `cargo-test-ferrum-dns` alias to pair with
        # -- workspace-tests above runs its tests, because that derivation
        # sets buildAndTestSubdir = "crates" and so picks up every workspace
        # member. What that does NOT do is lint it: buildRustPackage's check
        # phase runs `cargo test`, never clippy. Without this derivation the
        # crate holding every Cloudflare call and the one subprocess boundary
        # in the workspace would be the only crate nothing lints.
        #
        # --all-targets, so the fake nameserver and the dig round-trip tests
        # are linted too: most of this crate's new surface is its tests.
        #
        # `-p ferrum-dns` rather than the siblings' `buildAndTestSubdir`,
        # and that difference is load-bearing. A custom `buildPhase` skips
        # the hook that would otherwise honour `buildAndTestSubdir`, so
        # cargo runs at the workspace root and checks EVERY member --
        # including ferrum-install, whose `include_str!` of
        # examples/hosts/template/disko.nix escapes this `src` and cannot
        # resolve. Verified by really building it: with the subdir form this
        # derivation fails on ferrum-install's include, not on anything in
        # ferrum-dns. `-p` scopes cargo to this package and its own
        # dependencies, which is what the derivation's name claims.
        clippy-ferrum-dns = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-dns-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          checkPhase = "cargo clippy --offline -p ferrum-dns --all-targets -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        cargo-test-ferrum-reconcile = self'.packages.ferrum-reconcile;

        clippy-ferrum-reconcile = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-reconcile-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          # `-p`, not buildAndTestSubdir: this derivation replaces buildPhase
          # with `true`, which skips the hook that would cd into the subdir --
          # so cargo ran at the workspace root and linted EVERY member. That
          # made this check fail on a defect in a crate it does not own, and
          # made it unable to say which crate was at fault.
          checkPhase = "cargo clippy --offline -p ferrum-reconcile --all-targets -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        cargo-test-ferrumd = self'.packages.ferrumd;

        clippy-ferrumd = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrumd-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          # `-p`, not buildAndTestSubdir: this derivation replaces buildPhase
          # with `true`, which skips the hook that would cd into the subdir --
          # so cargo ran at the workspace root and linted EVERY member. That
          # made this check fail on a defect in a crate it does not own, and
          # made it unable to say which crate was at fault.
          checkPhase = "cargo clippy --offline -p ferrumd --all-targets -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        # The proof this whole phase's core deliverable works: a real
        # operator login with the real generated bootstrap password, a real
        # settings write, a real secret round-tripped through real sops
        # encryption, and a real job triggered over the real HTTP API that
        # crosses the real polkit/D-Bus privilege boundary and produces a
        # real JSONL progress log.
        daemon-end-to-end = import ../../../tests/daemon-end-to-end.nix { inherit pkgs; sopsNix = inputs.sops-nix; };

        # The one thing daemon-end-to-end.nix deliberately never did: a real
        # `{"kind":"apply"}` submitted over the real HTTP API, which really
        # crosses the real polkit/D-Bus boundary and really switches the
        # running system to a genuinely different NixOS closure. Kept as its
        # own check rather than bolted onto daemon-end-to-end: it needs a
        # second whole closure and a bootloader-backed VM (see the test's
        # header), which would slow down and complicate a file whose own
        # subject is the daemon's read-only surface.
        daemon-apply-end-to-end = import ../../../tests/daemon-apply-end-to-end.nix { inherit pkgs; sopsNix = inputs.sops-nix; };

        # A catalog app with no web interface must get no vhost, no
        # certificate, no Authelia rule and no DNS record -- and must not be
        # able to acquire one. See the definition for why all four are one
        # check rather than four.
        headless-apps-get-no-front-door = headlessAppsGetNoFrontDoor;

        # The one fact about Decluttarr that neither side can verify alone:
        # the download-client name it looks for is the name ferrum-reconcile
        # actually registered.
        decluttarr-knows-the-client-ferrum-registered = decluttarrKnowsTheClientFerrumRegistered;
      };
    };
}
