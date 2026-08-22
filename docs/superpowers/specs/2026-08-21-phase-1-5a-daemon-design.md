# Phase 1.5a — ferrumd (the daemon) Design

## Context

Every prior phase built the product ferrumd will eventually operate: the rollback engine (`ferrum-apply`), the full catalog, proxy/TLS/auth, secrets, and the reconciler. None of it has a web front end yet — an operator runs `ferrum-apply apply` by hand over SSH. `ferrum.daemon.{enable,port,listenAddress,subdomain}` already exist in `modules/core/options.nix` but nothing implements them; `crates/ferrumd` and `ui/` don't exist.

This spec covers **only the daemon** — the unprivileged web server, its privilege-boundary mechanism for triggering `ferrum-apply`, and its settings/secrets/job APIs. The actual web UI (the schema-driven SPA that calls these APIs) is Phase 1.5b, a separate spec and plan, deliberately out of scope here. A daemon with no UI is still a fully real, fully testable deliverable: every capability below is exercisable by hand with `curl`.

**Scope boundary confirmed during brainstorming:** the original design doc (`docs/design/2026-08-19-phase-1-design.md`) specifies ferrumd's own auth as local accounts, written before Authelia SSO existed (Phase 1.4b). That choice still stands and is *not* revisited by Phase 1.4b's "one identity" philosophy — ferrumd is infrastructure an operator needs to reach in order to configure `ferrum.proxy`/`ferrum.auth` in the first place, so it cannot depend on Authelia being configured at all. It is deliberately never routed through Authelia forward-auth, even after SSO exists for every catalog app.

## Global Constraints

- ferrumd runs unprivileged: user `ferrum`, `ProtectSystem=strict`, empty capability set (`security.acme`/`security.polkit`'s own established idiom for this is `systemd.services.<name>.serviceConfig` hardening — matches every other service.nix in this catalog).
- **Compromising ferrumd must only ever yield the power expressed by the settings schema, not arbitrary Nix evaluation as root.** This holds only because (a) `ferrum-apply`'s own privileged surface stays exactly its five existing subcommands, never grown to accept arbitrary Nix/shell input from ferrumd, and (b) `checks.schema-uniformity` (already shipped) continues to mechanically enforce that `settings` stays JSON-scalar-only.
- No default password, ever, for the first ferrumd account — same "no fixed value anywhere in this codebase for anyone to find" property Authelia's own bootstrap (Phase 1.4b) already established. Reuse that exact pattern, not a new one.
- Secret values are never written into `settings.json`, and ferrumd never holds a private age key — it can write any secret but cannot read one back, matching the existing `ferrum-apply` secret-generation code's own zero-privilege model (`crates/ferrum-apply/src/secrets.rs`'s `host_age_recipient`/`encrypt_and_write`, which need only the public key).
- `ferrum-apply`'s existing `ApplyResult` enum (`Succeeded`/`Degraded(String)`/`Failed(String)`, `crates/ferrum-apply/src/apply.rs:7-10`) and its exit-code convention (0/3/1, `crates/ferrum-apply/src/main.rs`'s `handle_apply_result`) are the source of truth for job outcome — ferrumd classifies jobs by re-using these, not inventing a parallel status vocabulary.
- `/var/lib/ferrum` (ferrumd's own database, job history) stays on `@root`, never `@state` — already an asserted invariant in `modules/core/storage.nix`. This spec adds no new violation risk, just consumes the existing guarantee.

---

## Design

### Components

- **`crates/ferrumd`** (new binary crate) — the unprivileged web server. Owns: HTTP/SSE endpoints (axum, matching the original design doc's Tech Stack decision), session auth, the SQLite job/session database, writing `settings.json`/`secrets/*.sops` directly (both permitted without privilege — see Settings/Secrets below), and requesting privileged work from `ferrum-apply` over D-Bus.
- **`crates/ferrum-secrets`** (new library crate, extracted) — `host_age_recipient`/`random_hex_key`/`random_secret_value`/`base64_encode`/`encrypt_and_write`, currently private functions inside `ferrum-apply`'s own `secrets.rs`. Both `ferrum-apply` (generating auto-created secrets) and `ferrumd` (writing operator-provided secrets from the API) need the identical zero-privilege encrypt operation — extracting it once avoids two independently-maintained copies of the same sops invocation, the same class of drift this project has already deliberately avoided elsewhere (`nix/overlays/default.nix`'s own "single source of truth... so there is exactly one definition" comment is the precedent for this exact move). `ferrum-apply`'s own `secrets.rs` keeps its higher-level `ensure_all`/`ensure_authelia_secrets`/`ensure_sabnzbd_apikey`/etc. — those stay privileged-only and un-shared, since ferrumd never runs them.
- **`crates/ferrum-apply`** (existing, extended) — gains one new subcommand, `ferrum-apply run-request <path>`, that reads a JSON request file and dispatches to the *existing* `apply`/`rollback`/`preflight`/`restore-state`/`gc` logic. No new privileged capability is added — this is purely a new entry point onto code that already exists and is already tested.
- **`modules/core/daemon.nix`** (new) — provisions the `ferrum` system user, `/etc/ferrum`'s carved-out permissions (below), ferrumd's own systemd unit, the `ferrum-apply@.service` systemd *template* unit, and the polkit rule via `security.polkit.extraConfig` (the simpler of the two real mechanisms for a single small rule — avoids a separate `.rules`-file derivation for one regex check).

### The `/etc/ferrum` permission model (a refinement of the original design doc's wording)

The original doc states `/etc/ferrum` is `root:root 0755` so ferrumd "physically cannot write Nix expressions there," but also states ferrumd writes `settings.json` and `secrets/*.sops` directly — those two claims only both hold if specific *pre-existing* paths inside that directory carry looser ownership, not the directory as a blanket rule:

```
/etc/ferrum/                    root:root 0755   (ferrumd can traverse, cannot create new entries)
/etc/ferrum/settings.json       root:ferrum 0664  (ferrumd can read+write this EXISTING file)
/etc/ferrum/secrets/            ferrum:ferrum 0750 (ferrumd can create/write files inside)
/etc/ferrum/flake.nix           root:root 0644   (ferrumd cannot touch)
/etc/ferrum/hardware-configuration.nix   root:root 0644   (ferrumd cannot touch)
/etc/ferrum/custom/             root:root 0755   (ferrumd cannot touch)
```

`settings.json` and `secrets/` are provisioned once, at this exact ownership, by `nixos-anywhere`'s own initial setup (already how `settings.json` has to come into existence before the very first `ferrum.lib.mkHost` evaluation can happen) — `modules/core/daemon.nix` does not create them at runtime; it only asserts (mirroring `modules/core/storage.nix`'s existing assertion style) that they exist with the expected ownership before `ferrumd.service` is allowed to start, failing loud with an actionable message if a host was provisioned before this phase existed.

### Privilege boundary: the request flow

1. Operator (via a future UI, or `curl`) sends `POST /api/jobs` with `{"kind": "apply"}` (or `{"kind": "rollback", "to": N}`, `{"kind": "gc"}`).
2. ferrumd checks its own in-memory/SQLite "is a job currently running" flag. If yes: `409 Conflict`, no new job. This is a deliberate simplification — apply/rollback are inherently exclusive operations against the same generation sequence, so ferrumd itself serializes rather than relying on `ferrum-apply` or systemd to arbitrate concurrent runs.
3. ferrumd generates a random UUID, writes the request JSON to `/run/ferrum/requests/<uuid>.json` (tmpfs; root can always read it regardless of the file's own mode, so no special permission dance is needed beyond the directory being ferrumd-writable).
4. ferrumd inserts a row into its own `jobs` table (id=uuid, kind, status=`running`, requested_at=now).
5. ferrumd calls `org.freedesktop.systemd1.Manager.StartUnit("ferrum-apply@<uuid>.service", "replace")` over D-Bus (the `zbus` crate — async, well-maintained, the standard choice for Rust D-Bus clients). This call is itself authorized by polkit:
   ```javascript
   if (/^ferrum-apply@[0-9a-f-]{36}\.service$/.test(unit) && verb === "start")
     return polkit.Result.YES;
   ```
   The UUID inside the unit name is *never* parsed as data by anything — polkit only ever compares it against this fixed regex, and `ferrum-apply run-request`'s own request path comes from the request *file's content*, addressed via systemd's `%i` instance specifier in the unit's `ExecStart`, not by re-deriving meaning from the instance name string itself.
6. systemd starts `ferrum-apply@<uuid>.service` as root, `ExecStart = "${pkgs.ferrum-apply}/bin/ferrum-apply run-request /run/ferrum/requests/%i.json"`.
7. `ferrum-apply run-request` reads the file, dispatches to the matching existing subcommand's logic, and writes progress as JSONL lines to `/var/lib/ferrum/jobs/<uuid>.jsonl` (on `@root`, stable across the job's lifetime and across a ferrumd restart) — one line per meaningful step (`{"ts":...,"event":"preflight_ok"}`, `{"ts":...,"event":"snapshot_taken","name":"..."}`, ..., a final `{"ts":...,"event":"complete","result":"succeeded"|"degraded"|"failed","detail":"..."}` matching `ApplyResult`'s own three variants).
8. ferrumd tails that file (inotify-based, e.g. the `notify` crate) and relays each new line over SSE to any client connected to `GET /api/jobs/<uuid>/stream`. A client connecting *after* the job started is first replayed the file's own content from the start, then switched to live-tail — this is the concrete mechanism behind "a job survives a ferrumd restart and replays cleanly for a reconnecting client."
9. ferrumd also independently confirms completion via systemd's own `JobRemoved` D-Bus signal (subscribed once at startup) as a cross-check against the JSONL file's own terminal line — if the unit exits without ever writing a `complete` event (a crash before any progress), the D-Bus signal is what still lets ferrumd mark the job `failed` rather than hanging forever in `running`. On completion (from either source, first one wins), ferrumd updates the `jobs` row's `status`/`finished_at`/`result`.

### Settings API

- `GET /api/settings` — returns the current `/etc/ferrum/settings.json` content, parsed and re-serialized (never a raw passthrough, so a hand-edited file with trailing garbage can't leak into the API response verbatim).
- `PUT /api/settings` — validates the proposed document against the JSON Schema `$FERRUM_CATALOG` already provides (the existing `ferrum-catalog` Nix package, `nix/modules/flake/packages.nix`), and — only if valid — writes it to `/etc/ferrum/settings.json` directly (no privilege needed, per the permission model above). **Writing settings never triggers an apply.** The operator reviews the change, then makes an explicit, separate `POST /api/jobs {"kind":"apply"}` call — matching the existing UI philosophy that the daemon never surprises an operator with an unrequested rebuild.
- Schema staleness is an accepted, already-existing constraint, not new: `$FERRUM_CATALOG` is a build-time artifact, so a brand-new app/option only becomes visible to `PUT /api/settings`'s validation after a rebuild+switch — exactly the same rebuild an operator already needs before that app's own `service.nix` exists on the box at all.

### Secrets API

- `POST /api/secrets/<name>` with a raw request body (the plaintext secret value) — ferrumd calls `ferrum_secrets::encrypt_and_write` (the newly-shared crate) with this host's own public age recipient (derived the same way `ferrum-apply` already does, via `ssh-to-age` against the host's SSH public key — needs no privilege) and writes the ciphertext to `/etc/ferrum/secrets/<name>.sops`, always fully replacing any existing file — **never re-encrypted**, matching the existing design doc's own stated property.
- `<name>` is only accepted when it's declared in the current `settings.json`'s own `ferrum.secrets` map (the option already scaffolded in `modules/core/options.nix`, "Names ferrumd is permitted to write a secret under") — an arbitrary name is rejected with `400`, keeping the secret-write surface catalog/settings-driven rather than an open-ended file-write primitive.
- No `GET` endpoint for secrets exists, ever — this is what makes the write-only property real rather than aspirational.

### Auth

- Local accounts only (see Scope Boundary above for why). Argon2id password hashing (the `argon2` crate, in-process — unlike Authelia's own file-backend format, ferrumd owns its user table directly, so there's no external format to shell out to Authelia's CLI for).
- First-run bootstrap happens inside **ferrumd itself**, at its own startup, not via `ferrum-apply` — this is a deliberate difference from Authelia's bootstrap (Phase 1.4b), not an oversight: Authelia's `users_database.yml` has to exist *before* Authelia's own systemd unit starts, which is why that bootstrap needed the privileged pre-build step. ferrumd's own user table lives inside ferrumd's own already-owned SQLite database, in ferrumd's own already-owned state directory — there's no privilege or cross-crate coupling this needs. Concretely: on startup, if the `users` table is empty, ferrumd generates a real random password (via the shared `ferrum-secrets` crate's `random_secret_value`), hashes it with argon2id in-process, inserts the user row, and writes the one-time plaintext to `/var/lib/ferrum/ferrumd-setup-password` (mode `0400`, root-only, read by the operator over SSH) — idempotent by the same "table already has a row" check, so a restart never resets an operator's already-changed password.
- Sessions: a `sessions` table in the same SQLite DB (id, user_id, created_at, expires_at), a random session token in an `HttpOnly`/`Secure`/`SameSite=Strict` cookie. CSRF: a synchronizer token issued at login, stored server-side in the session row, required on every mutating (`POST`/`PUT`/`DELETE`) request as a header — standard, well-understood pattern, no new primitive invented.
- Rate limiting: a `login_attempts` table (ip or username, timestamp) — 5 failures within 5 minutes locks further attempts out for 60 seconds. Simple, SQLite-backed, no new infrastructure.

### Error handling

- A D-Bus call that fails (polkit denial, systemd unable to start the unit, `ferrum-apply` binary missing) surfaces as a clear `5xx` to the caller with the underlying error in the response body — never silently retried, never silently swallowed. ferrumd's own job row is marked `failed` with that detail as the reason.
- `ferrum-apply run-request` crashing before writing any JSONL line is still caught (see step 9 above) via the independent D-Bus `JobRemoved` signal — a job can never be left `running` forever in the database because its own progress file happened to be empty.
- Every mutating HTTP endpoint validates its own input against a real schema (settings against `$FERRUM_CATALOG`'s JSON Schema; job requests against a small fixed enum of kinds) before touching the filesystem or D-Bus at all — an invalid request never reaches the privileged-request machinery.

### Testing

This project's own repeatedly-confirmed lesson (at least five separate real bugs across Phase 1.4a/b/c, none of them catchable by eval-only or diff-only review) applies at full force here, arguably more so: this phase adds the project's *first* privilege boundary and *first* network-facing component. The plan built from this spec must include, not as an afterthought but as the actual proof the design works:

- A real NixOS VM test booting a real host with `ferrum.daemon.enable = true`, hitting ferrumd's real HTTP API with real requests: login with the real bootstrap password (read from the real `ferrumd-setup-password` file), a real settings write, a real secret write (confirm the resulting `.sops` file decrypts to the real value), and — the one that actually proves the core deliverable — a real `POST /api/jobs {"kind":"apply"}` against a real `ferrum-testapp`-backed host (reusing the exact mechanism Phase 1.2's own rollback tests already built for "prove state actually changed," not a mock), confirming the job reaches `succeeded` and the underlying system genuinely rebuilt.
- A dedicated privilege-boundary test, already anticipated by the original design doc's own Verification section: running commands *as the `ferrum` user* and confirming they fail — `systemctl start sshd.service` denied, writing into `/etc/ferrum/custom/` fails with `EACCES`, starting `ferrum-apply@<anything-not-matching-the-regex>.service` denied by polkit. This is what makes "compromising ferrumd only gets you the settings schema" a tested claim, not an assumed one.
- Unit tests for: JSON Schema validation against real `$FERRUM_CATALOG` output, argon2id verification, CSRF token checks, SQLite job-state transitions, JSONL progress-file parsing.

## Known Risks

1. **`zbus` (or any D-Bus crate) is new dependency surface this codebase has never used before** — Phase 1.4c's own `ureq` addition was the first new HTTP dependency; this is the first new IPC dependency. Worth a real spike (per this project's own Phase 1.0 precedent) confirming a minimal `zbus` call against a real systemd `StartUnit` + a real polkit rule actually authorizes correctly on the pinned nixpkgs revision, before committing to it in a full task plan.
2. **The JSONL-progress-file-plus-D-Bus-signal dual detection (step 9) is real complexity to get right** — two independent signals racing to mark the same job complete needs careful "first one wins, and they must agree" handling, or a job could flip status after already being reported complete to a client.
3. **`ferrum-secrets`'s extraction from `ferrum-apply` is a real refactor of already-shipped, already-reviewed code** — `encrypt_and_write` and friends are currently private functions with real production test coverage inside `ferrum-apply`; moving them to a shared library crate needs to preserve that coverage exactly, not quietly drop it in the move.
4. **Schema staleness** (settings validation only knows about what the last build produced) is an accepted tradeoff, not a defect — but it means a UI (Phase 1.5b) needs to handle "the server just told me a field I'm rendering doesn't exist" gracefully, since an operator could be looking at a stale browser tab across a rebuild.
