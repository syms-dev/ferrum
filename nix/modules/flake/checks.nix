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
      # Same mechanism, and same one-line-literal constraint, as
      # uiRendersEverySchemaType below.
      installerOffersEveryCatalogApp =
        let
          answersSrc = builtins.readFile ../../../crates/ferrum-install/src/answers.rs;
          declLine =
            let hits = builtins.filter (l: lib.hasInfix "pub const CATALOG_APPS" l)
                         (lib.splitString "\n" answersSrc);
            in if hits == [ ] then
                 throw "crates/ferrum-install/src/answers.rs no longer declares CATALOG_APPS on a single line that this check can read"
               else builtins.head hits;
          declared =
            map builtins.head
              (builtins.filter builtins.isList
                (builtins.split "\"([a-z0-9-]+)\"" declLine));

          catalogApps = builtins.attrNames (import ../../../modules/lib/catalog.nix { inherit lib; });
          missing = builtins.filter (a: !(builtins.elem a declared)) catalogApps;
          extra = builtins.filter (a: !(builtins.elem a catalogApps)) declared;
        in
        {
          ok = missing == [ ] && extra == [ ];
          message =
            "crates/ferrum-install/src/answers.rs's CATALOG_APPS is out of step with "
            + "modules/lib/catalog.nix."
            + (lib.optionalString (missing != [ ])
                " In the catalog but not offered by the installer: ${lib.concatStringsSep ", " missing}.")
            + (lib.optionalString (extra != [ ])
                " Offered by the installer but not in the catalog: ${lib.concatStringsSep ", " extra}.");
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
      #   * auth.<baseDomain> appears exactly when ferrum.auth.enable does,
      #     mirroring acme.nix's own condition. A certificate for a name that
      #     does not resolve is the incident R1 exists to fix.
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
          mkDnsHost = { auth }: ferrumLib.mkHost {
            inherit system;
            settings = {
              schemaVersion = realMigrations.currentVersion;
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
              auth.enable = auth;
              apps = {
                # Deliberately `lan`: this is the app that must NOT appear.
                sonarr = { enable = true; exposure = "lan"; };
                radarr.enable = true;
              };
            };
            modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          };
          withAuth = (mkDnsHost { auth = true; }).config.system.build.ferrumDnsConfig;
          withoutAuth = (mkDnsHost { auth = false; }).config.system.build.ferrumDnsConfig;
        in
        pkgs.runCommand "ferrum-check-dns-record-set" { } ''
          set -eu
          with_auth=${withAuth}
          without_auth=${withoutAuth}
          fail() {
            echo "dns record-set check: $1" >&2
            echo "--- with auth ---" >&2; cat "$with_auth" >&2
            echo "--- without auth ---" >&2; cat "$without_auth" >&2
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

          for cfg in "$with_auth" "$without_auth"; do
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
