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

      exampleHosts = {
        minimal = ferrumLib.mkHost {
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
          ];
          revision = "ci";
        };
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
          missing = builtins.filter (a: !(builtins.elem a declared)) catalogApps;
          extra = builtins.filter (a: !(builtins.elem a catalogApps)) declared;

          # The installer names records, urls and reachability checks after
          # the app id; the host names its vhost after the subdomain. See
          # the header above for why letting those two diverge is a silent
          # DNS defect rather than a cosmetic one.
          renamed = builtins.filter (id: catalog.${id}.defaultSubdomain != id) catalogApps;
        in
        {
          ok = missing == [ ] && extra == [ ] && renamed == [ ];
          message =
            "crates/ferrum-install/src/answers.rs's CATALOG_APPS is out of step with "
            + "modules/lib/catalog.nix."
            + (lib.optionalString (missing != [ ])
                " In the catalog but not offered by the installer: ${lib.concatStringsSep ", " missing}.")
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
            }: ferrumLib.mkHost {
              inherit system;
              settings = {
                schemaVersion = realMigrations.currentVersion;
                proxy = { enable = proxy; inherit baseDomain; acme.email = "a@example.test"; };
                auth = { enable = true; adminEmail = "a@example.test"; };
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
          # `or { }` rather than `or null` so a missing location degrades to an
          # empty config string and produces a specific "directive missing"
          # problem, instead of throwing before any of them are reported.
          locOf = loc: (daemonV.locations.${loc} or { }).extraConfig or "";
          rootLoc = locOf "/";
          apiLoc = locOf "/api/";
          hasIn = needle: hay: lib.hasInfix needle hay;

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
            ++ lib.optional (!(hasIn "error_page 401 =302 https://auth.example.test" rootLoc))
              "the daemon vhost's / does not redirect an unauthenticated navigation to Authelia (A2)"
            ++ lib.optional (hasIn "=302" apiLoc)
              "the daemon vhost's /api/ redirects a 401 instead of returning it, so the SPA sees an opaque cross-origin redirect (D8)"
            ++ lib.optional (!(hasIn "error_page 401 = @ferrum_api_401" apiLoc))
              "the daemon vhost's /api/ does not override the 401 redirect with a plain 401 (D8)"
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
            ++ map (a: "ferrum.daemon.listenAddress = \"${a}\" evaluates cleanly, and it is a NAME rather than a literal -- nginx resolves it at config load and load-balances across every address it yields, while ferrumd's TcpListener::bind takes only the first, so roughly half the dashboard's requests hit a port nothing is listening on. An intermittent 502 with no cause in either program's log (A5)")
              wronglyAcceptedNames
            ++ map (a: "ferrum.daemon.listenAddress = \"${a}\" evaluates cleanly, and it is an ALREADY-BRACKETED IPv6 literal -- modules/proxy/nginx.nix brackets any address containing a colon unconditionally, with no \"already bracketed?\" branch, because this refusal is what guarantees one never arrives. Accepting it renders `proxy_pass http://[[::1]]:7788`, which nginx rejects as an invalid host, refusing the WHOLE config file: every vhost on the host down at nginx.service start, after an apply that reported success (A5)")
              wronglyAcceptedBracketed
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
              # file the HOST would have and this sandbox does not. None of
              # them touches a directive whose parse is under test -- the
              # proxy_pass lines reach the parser byte-for-byte as
              # modules/proxy/nginx.nix wrote them, which the mutation test
              # in this commit's message demonstrates.
              sed -e "s|ssl_certificate .*|ssl_certificate $PWD/cert.pem;|" \
                  -e "s|ssl_certificate_key .*|ssl_certificate_key $PWD/key.pem;|" \
                  -e "s|ssl_trusted_certificate .*|ssl_trusted_certificate $PWD/cert.pem;|" \
                  -e "s|^pid .*|pid $PWD/nginx.pid;|" \
                  -e "s|^http {|http {\n\taccess_log off;|" \
                  "$cfg" > test.conf

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
      # these hosts carry other failing assertions (the example host's
      # placeholder secrets have no *-apikey-raw.sops counterparts), so an
      # unscoped version would report every host as "rejected" and would pass
      # identically with the assertion deleted.
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
      #   * the daemon's own record is present (owner ruling H-01, option C).
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
        in
        pkgs.runCommand "ferrum-check-dns-record-set" { } ''
          set -eu
          with_auth=${withAuth}
          without_auth=${withoutAuth}
          dashboard_only=${dashboardOnly}
          proxy_off=${proxyOff}
          record_excluded=${recordExcluded}
          fail() {
            echo "dns record-set check: $1" >&2
            echo "--- with auth ---" >&2; cat "$with_auth" >&2
            echo "--- without auth ---" >&2; cat "$without_auth" >&2
            echo "--- dashboard only ---" >&2; cat "$dashboard_only" >&2
            echo "--- proxy off ---" >&2; cat "$proxy_off" >&2
            echo "--- record excluded ---" >&2; cat "$record_excluded" >&2
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

          # A7, the proxy-off half. The daemon record below is the
          # anti-vacuity guard and nothing more: an absence found in an empty
          # record list is not a finding, so the auth assertion is only worth
          # anything once this document is shown to contain records at all.
          # (That the daemon record is present on a host with no proxy is
          # daemonRecords' own unconditional `lib.optional
          # ferrum.daemon.dns.includeRecord` -- a known, separately-owned
          # gap, deliberately not this check's business.)
          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "daemon")' \
            "$proxy_off" > /dev/null \
            || fail "the proxy-off document has no records at all, so finding no auth record in it proves nothing"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "auth")] | length == 0' \
            "$proxy_off" > /dev/null \
            || fail "a host with ferrum.proxy.enable = false got an auth.example.invalid record -- nginx builds no vhost for it, so that publishes a name with nothing behind it (A7)"

          # ferrum.daemon.dns.includeRecord = false, the only behaviour that
          # option has. The radarr assertion first, for the same reason as
          # above: it proves this document has records at all.
          ${pkgs.jq}/bin/jq -e '.records[] | select(.source == "app:radarr")' \
            "$record_excluded" > /dev/null \
            || fail "the includeRecord = false document has no records at all, so finding no daemon record in it proves nothing"

          ${pkgs.jq}/bin/jq -e '[.records[] | select(.source == "daemon")] | length == 0' \
            "$record_excluded" > /dev/null \
            || fail "ferrum.daemon.dns.includeRecord = false still produced a daemon record -- the documented one-line way to opt out of the H-01 ruling does nothing"

          for cfg in "$with_auth" "$without_auth" "$dashboard_only" "$proxy_off" "$record_excluded"; do
            ${pkgs.jq}/bin/jq -e '(.records | length) > 0 and all(.records[]; .proxied == false)' \
              "$cfg" > /dev/null \
              || fail "a record is proxied -- orange-cloud proxying makes every request arrive from a Cloudflare edge address"
          done

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
        auth-model-enforced = mkAssertionCheck "auth-model-enforced" authModelEnforced;
        daemon-vhost-enforced = mkAssertionCheck "daemon-vhost-enforced" daemonVhostEnforced;
        nginx-config-parses = nginxConfigParses;
        reserved-subdomain-collision =
          mkAssertionCheck "reserved-subdomain-collision" reservedSubdomainCollision;
        nginx-emits-no-cors-headers =
          mkAssertionCheck "nginx-emits-no-cors-headers" nginxEmitsNoCorsHeaders;
        root-folders-reach-the-apps = rootFoldersReachTheApps;
        dns-record-set = dnsRecordSet;
        catalog-consistency = mkAssertionCheck "catalog-consistency" catalogConsistency;
        schema-uniformity = mkAssertionCheck "schema-uniformity" schemaUniformity;
        ui-renders-every-schema-type =
          mkAssertionCheck "ui-renders-every-schema-type" uiRendersEverySchemaType;
        settings-schema-covers-every-option =
          mkAssertionCheck "settings-schema-covers-every-option" schemaCoversEveryOption;
        installer-offers-every-catalog-app =
          mkAssertionCheck "installer-offers-every-catalog-app" installerOffersEveryCatalogApp;
        sopsfile-are-paths = mkAssertionCheck "sopsfile-are-paths" sopsFilesArePaths;
        migration-mechanism = mkAssertionCheck "migration-mechanism" migrationMechanism;
        journaldir-collision = mkAssertionCheck "journaldir-collision" journalDirCollision;
        mkhost-applies-migration = mkAssertionCheck "mkhost-applies-migration" mkHostAppliesMigration;

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
      };
    };
}
