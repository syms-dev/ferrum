# Phase 1.5b — the web UI (and the read-only APIs it needs) Design

## Context

Phase 1.5a shipped ferrumd: an unprivileged web daemon with real session auth, a settings API, a write-only secrets API, and a real D-Bus/polkit privilege boundary that dispatches genuine `ferrum-apply` runs and streams their progress over SSE. Every one of those capabilities is exercisable today with `curl`, and `tests/daemon-end-to-end.nix` and `tests/daemon-apply-end-to-end.nix` prove they work against a real booted host.

What does not exist is the thing the whole project's second goal ("setup and maintenance without hand-editing config") rests on: `ui/` is not in the repository. This spec covers Phase 1.5b — the schema-driven single-page UI, plus the **four read-only daemon endpoints it cannot be built without**.

The original design doc (`docs/design/2026-08-19-phase-1-design.md`, "How the UI discovers the catalog") already settled the UI's central architectural claim: the UI is *generated from the catalog schema* rather than hand-built per app, which is the only reason a NixOS configuration GUI is viable at all here where every generic one has died. This spec does not revisit that. It makes it real.

**Scope boundary.** This phase adds no new privileged capability, no new job kind, and no new mutation the API does not already expose. `POST /api/jobs`, `PUT /api/settings` and `POST /api/secrets/:name` are the complete set of state-changing operations, all shipped in 1.5a. Everything new here is either read-only or client-side. Phase 1.6 (install path, docs, release) remains out of scope.

## Global Constraints

- **No build step, no npm, no bundler, no node in any closure.** The UI is hand-written HTML/CSS/ES modules served verbatim from a `pkgs.runCommand` derivation, in the same spirit as the existing `ferrum-catalog`/`ferrum-settings-schema` `writeTextFile` packages. This is a deliberate choice against a `buildNpmPackage` + `npmDepsHash` toolchain: the UI is schema-driven, so there is very little component logic to hand-roll, and a fixed-output npm hash that has to be regenerated on every lockfile bump is real, recurring friction for a project whose only build environment is CI and a dev VM. The tradeoff accepted in exchange is no type checking and manual DOM work.
- **The UI is a client of the existing API, never a second source of truth.** It renders forms from `catalog.json` + `settings-schema.json` as served by the daemon; it never hardcodes an app list, an option name, or a field type. Adding an app to `modules/apps/` must make it appear in the UI with no `ui/` change at all — that property is what `checks.catalog-consistency` and `checks.schema-uniformity` already exist to protect, and it is the one this phase must not quietly break.
- **Every new endpoint is read-only and sits behind the existing `require_session` middleware** (`crates/ferrumd/src/main.rs`'s `protected` router), inheriting session auth unchanged. No new auth path, no new CSRF surface — `GET` is already exempt from the CSRF check by `method_is_mutating`, correctly, since a synchronizer token protects mutations.
- **ferrumd gains no new write access and no new filesystem reach.** The one `ReadWritePaths` set in `modules/core/daemon.nix` stays exactly as it is. The generations endpoint reads two paths ferrumd does not currently touch (`/nix/var/nix/profiles/` and `ferrum.storage.journalDir`), both **read-only**; `ProtectSystem = "strict"` makes the whole filesystem read-only rather than invisible, so this needs no directive change, only a mode guarantee on the journal directory (below).
- **The UI must degrade honestly against a stale schema.** Known risk 4 of the 1.5a spec: an operator can be looking at a browser tab loaded before a rebuild, rendering fields the newly-built schema no longer has. The UI must surface a `PUT /api/settings` schema-validation rejection as a readable, field-anchored error rather than a generic failure — it already receives exactly that from `validate_against_schema`'s `messages.join("; ")`.
- **Rollback's confirmation dialog must state concretely what does and does not revert.** This is known risk 5 of the original design doc, verbatim: "Media files, download queues, ACME certs and Authelia users do *not* revert... Getting this wrong is how a technically correct product earns a reputation for losing data." It is a hard requirement of this phase, not a polish item.

---

## Design

### Components

- **`ui/`** (new) — `index.html`, `app.js`, `forms.js`, `api.js`, `style.css`. No dependencies, no build.
- **`nix/pkgs/ferrum-ui`** (new) — a `runCommand` that copies `ui/` to `$out/share/ferrum/ui`, exposed as `packages.ferrum-ui`.
- **`crates/ferrumd/src/catalog.rs`** (new) — `GET /api/catalog`.
- **`crates/ferrumd/src/generations.rs`** (new) — `GET /api/generations`.
- **`crates/ferrumd/src/static_files.rs`** (new) — serves `$FERRUM_UI_DIR` with an SPA fallback.
- **`crates/ferrum-state`** (new library crate, extracted) — `journal` and `generations` modules, currently private inside `ferrum-apply`. See below; this mirrors the `ferrum-secrets` extraction Phase 1.5a already established as this repo's precedent for "two crates need the identical logic."
- **`crates/ferrumd/src/jobs.rs`** (existing, extended) — adds `GET /api/jobs` and `GET /api/jobs/:id`, both derived from the JSONL job directory rather than from any database table (see below).
- **`crates/ferrum-apply`** (existing, one-line extension) — `run-request` emits a leading `started` progress event naming the job kind, so the progress file is self-describing. No new privileged capability.
- **`crates/ferrumd/src/main.rs`** (existing, extended) — adds `GET /api/session` and wires the new routes.
- **`modules/core/daemon.nix`** (existing, extended) — adds `FERRUM_CATALOG`, `FERRUM_UI_DIR`, `FERRUM_PROFILES_DIR`, `FERRUM_JOURNAL_DIR` to ferrumd's `environment`, and a tmpfiles rule for the journal directory.

### The four read-only endpoints

#### `GET /api/catalog`

Returns the `catalog.json` built by the existing `ferrum-catalog` package, read from a new `FERRUM_CATALOG` environment variable, **with the settings JSON Schema embedded under a `schema` key** so the UI fetches one document rather than racing two:

```json
{ "schemaVersion": 1, "ferrumVersion": "abc1234", "apps": { ... }, "schema": { ...settings-schema.json... } }
```

`nix/modules/flake/packages.nix:1-3` currently opens with the comment *"Builds the catalog artifact the (future) ferrumd daemon reads at runtime... Nothing consumes this yet."* This endpoint is that consumer, and the comment is updated by this phase. The two files are read and parsed per request, matching `settings.rs`'s own already-reasoned decision to read `FERRUM_SETTINGS_SCHEMA` per request rather than cache it — the cost is one file read on a human-paced endpoint, and the benefit is that a ferrumd left running across a generation switch cannot serve a catalog its own binary no longer matches.

A missing or unparseable `FERRUM_CATALOG` is a `500` naming the path, exactly as `validate_against_schema` already does for the schema — never a silently empty catalog, which would render as "this host has no apps" and invite an operator to conclude something was uninstalled.

#### `GET /api/generations`

Returns the generation list the rollback UI is built on:

```json
{ "current": 42,
  "generations": [
    { "generation": 42, "date": "2026-09-14 10:02:11", "current": true,
      "snapshot": { "snapshot": "1773...-gen42", "taken_at": "...", "quiesced": true },
      "rollbackable": true, "reason": null },
    { "generation": 41, "date": "...", "current": false, "snapshot": null,
      "rollbackable": false,
      "reason": "generation 41 has no state snapshot -- it was either applied outside ferrum-apply, or its snapshot was pruned" }
  ] }
```

`rollbackable`/`reason` come from `generations::is_rollbackable`'s existing `Result<(), String>` — the UI disables the rollback control and shows the crate's own message, rather than inventing a second vocabulary for why a generation cannot be rolled back. This is the same discipline the 1.5a spec applied to `ApplyResult`.

**Enumerating generations reads the profile directory directly, not `nix-env --list-generations`.** `crates/ferrum-apply/src/generations.rs` already has a `parse_nix_env_list` parser, written and tested against real output in Phase 1.0 probe 0.5, and it is tempting to reuse. It is the wrong mechanism *here*: shelling out to `nix-env` would put the entire `nix` closure on the unprivileged daemon's `PATH` (`modules/core/daemon.nix` currently gives ferrumd exactly `pkgs.sops` and `pkgs.ssh-to-age`, and `ferrum-apply@.service` needed `config.nix.package` added for precisely this reason), and it spawns a subprocess that talks to the Nix database on every page load of a read-only view. `/nix/var/nix/profiles/` is a directory of `system-<N>-link` symlinks plus a `system` symlink to the current one — readable with two `read_dir`/`read_link` calls, no subprocess, no new PATH entry, and it is the same data `nix-env` itself is reporting. `parse_nix_env_list` stays where it is and keeps its tests; it is not deleted, and `ferrum-apply` remains free to use it.

Generation timestamps come from each link's own `lstat` mtime, formatted to the same `"%Y-%m-%d %H:%M:%S"` shape `parse_nix_env_list` produces, so both producers agree on one format.

#### `GET /api/jobs` and `GET /api/jobs/:id`

**Correction to the 1.5a spec, confirmed against the shipped code:** that spec described a `jobs` table in ferrumd's SQLite database, holding `id`/`kind`/`status`/`requested_at`/`finished_at`. **It does not exist.** `crates/ferrumd/src/db.rs` creates exactly three tables — `users`, `sessions`, `login_attempts` — and its own test asserts that count. The implementation deliberately landed somewhere better: job state lives entirely in the per-job JSONL progress file under `$FERRUM_JOBS_DIR`, plus a single in-memory `job_running: Mutex<bool>` interlock that `main.rs` re-seeds at startup from systemd's own real view (`dbus::ferrum_apply_job_is_running`). That is *why* "a job survives a ferrumd restart" is true today rather than aspirational, and it avoids a dual-write consistency problem between a database row and the file that is the real record.

This phase keeps that design and does **not** add a `jobs` table. Both endpoints derive their answer from the job directory:

- `GET /api/jobs` lists `$FERRUM_JOBS_DIR/*.jsonl` (filename stem parsed as a UUID, anything else skipped), newest first by the first line's own `ts`, `?limit=` clamped to 100 with a default of 25. A job whose last non-empty line is a `complete` event is finished, and that line's `detail` carries the `ApplyResult` outcome; a job with no terminal line is still `running`.
- `GET /api/jobs/:id` returns that one job plus its full parsed progress log, so a reloaded tab can render a *finished* job's history without opening an SSE stream that would only replay and immediately close.

**One small change to `ferrum-apply` makes this honest.** The JSONL as written today records no job *kind* — `progress.rs` emits `{ts, event, detail}` and nothing announces whether a run is an apply, a rollback or a gc. A listing derived from those files alone could not tell an operator what a job *was*. So `ferrum-apply run-request` gains a single first line, `{"ts":...,"event":"started","detail":"<kind>"}`, written before it dispatches to the existing subcommand logic. This adds no privileged capability and changes no existing event; it makes the progress file self-describing, which is the property the whole file-as-source-of-truth design already depends on. `stream_job`'s terminal-line detection is untouched — it matches on `event == "complete"`, and `started` is not that.

`GET /api/jobs` is also what makes the existing `409 Conflict` interlock legible: the UI can name the job holding the lock instead of reporting a bare conflict.

#### `GET /api/session`

Returns `{ "username": "...", "csrf_token": "..." }` for the caller's current session, or `401`. The SPA needs both on load: the CSRF synchronizer token is stored server-side in the `sessions` row and currently only ever handed out by `login_handler`, so a client holding a valid session cookie across a page reload has a session it cannot make a single mutation with. This endpoint is what makes the session cookie's `HttpOnly` lifetime actually usable by the UI, instead of forcing a re-login on every reload.

### Static serving

`GET /` and any non-`/api/` path serves from `$FERRUM_UI_DIR` (set to `${pkgs.ferrum-ui}/share/ferrum/ui` by `modules/core/daemon.nix`), with an SPA fallback to `index.html` for unknown paths so client-side routing survives a refresh. Two hard rules:

- The fallback **must not** apply under `/api/` — an unknown API path returns `404`, never `index.html`. A JSON client silently receiving an HTML page is a genuinely confusing failure mode, and the daemon has exactly one chance to get this right.
- Path traversal is rejected by canonicalising the resolved path and confirming it is still under the root, not by string-matching `..`. The UI directory is a world-readable store path so the impact is low, but the daemon is the project's only network-facing component and this is the cheapest possible correctness guarantee.

Static assets are served **unauthenticated**; the APIs behind them are not. The UI's own HTML/CSS/JS contains nothing secret, and requiring a session to fetch the login page is circular.

### The `ferrum-state` extraction

`GET /api/generations` needs `journal::list` and `generations::{correlate, is_rollbackable, GenerationInfo}`, which today are private modules of the `ferrum-apply` **binary** crate and therefore not importable. Both are already written, already tested, and — tellingly — already carry `#[allow(dead_code)]` comments naming their intended future consumer: *"used when listing all generations, e.g. a future ferrumd-facing API"* and *"kept for a future `list-generations` consumer."* This phase is that consumer arriving.

Extraction follows the `ferrum-secrets` precedent exactly (Phase 1.5a, `8f4e7f7`): move `journal.rs` and `generations.rs` into a new `crates/ferrum-state` library crate **with their existing tests moved intact**, and have `ferrum-apply` depend on it. Known risk 3 of the 1.5a spec applies unchanged and is the thing most likely to go wrong here: this is a refactor of shipped, reviewed, production-tested code, and the test coverage must survive the move rather than being quietly dropped in it. The `#[allow(dead_code)]` attributes come *off* the items this phase genuinely uses — leaving them on would hide a real future regression.

`Cargo.lock` must be regenerated for the new workspace member. This has bitten this repo twice before (`f86c90f`, `402c8be`), both times as a CI failure after the fact.

### Journal directory readability

`ferrum.storage.journalDir` (default `/var/lib/ferrum/journal`) has no `systemd.tmpfiles` rule today — it is created by `journal::write`'s own `create_dir_all` running as root, landing at whatever the ambient umask gives (in practice `0755`). ferrumd can therefore read it *incidentally*, which is not a property to build an endpoint on. This phase adds an explicit rule alongside the existing ones in `modules/core/storage.nix`:

```
"d ${cfg.journalDir} 0750 root ${ferrumdGroup} - -"
```

reusing that file's existing `ferrumdGroup` binding, which already falls back to `root` on a host with `ferrum.daemon.enable = false` precisely so naming a nonexistent group cannot fail tmpfiles at boot. The journal becomes group-readable by `ferrum` and writable only by root — read access for the daemon, no write access, stated rather than inherited.

### The UI itself

Four views, client-side routed by hash, all rendered from the catalog:

1. **Login** — `POST /api/login`, then load `GET /api/session` + `GET /api/catalog`.
2. **Apps** — the app list from `catalog.apps`, and **one form definition for all apps**, because the submodule is uniform (the original design doc's own words). `forms.js` walks the JSON Schema and emits a control per type: `boolean` → checkbox, `integer` → number, `string` with `enum` → select, `string` → text, `array` of `string` → repeated text rows, `object` → nested fieldset. The allowlist `checks.schema-uniformity` mechanically enforces is exactly the set of types this renderer must cover — if a schema type appears that the renderer has no control for, it renders a disabled field with a visible "unsupported type" note rather than silently dropping the option, because silently dropping it would mean the operator saves a settings document with that field erased.
3. **Apply** — a diff of the edited settings against what `GET /api/settings` last returned, a `PUT`, then an explicit, separate `POST /api/jobs {"kind":"apply"}`. The 1.5a spec's rule stands and the UI must make it visible: **writing settings never triggers an apply.** Progress streams from `GET /api/jobs/:id/stream`; on load, any job still `running` per `GET /api/jobs` is reattached to automatically.
4. **Generations** — the list from `GET /api/generations`, with rollback gated behind a confirmation dialog that names the target generation, its snapshot's `taken_at`, and — per the Global Constraint above — states concretely and in the operator's own terms what will revert (the system closure and every app's state directory) and what will not (media files, in-flight downloads, ACME certificates, Authelia users and their password changes). Generations with `rollbackable: false` show the daemon's own `reason` and no control.

Secrets get a write-only control on the app form for any `ferrum.secrets` name the schema declares: a password-style input that `POST`s to `/api/secrets/:name` and, on success, shows only that a value is set — never a value, since there is no `GET` and there must never be one.

## Testing

The 1.5a spec's testing argument applies unchanged and this phase does nothing to weaken it: five real bugs across Phases 1.4a/b/c were caught by really running things and by nothing else, and the `path = [ config.nix.package ]` bug in `modules/core/daemon.nix` — every ferrumd-dispatched apply dying instantly on a missing `nix` binary — was found by a real VM test and would have been invisible to any amount of reading.

- **Extend `tests/daemon-end-to-end.nix`** to hit all four new endpoints for real against a real booted host: `GET /api/catalog` returns the real built catalog with the real app set and a real embedded schema; `GET /api/generations` returns the real generation the VM is really running, marked `current`; `GET /api/session` returns a usable CSRF token that a subsequent real mutation actually accepts; `GET /` serves the real UI's real `index.html` while `GET /api/nonexistent` returns a real `404` and not HTML.
- **Extend `tests/daemon-apply-end-to-end.nix`** so that after the real apply it already performs, `GET /api/jobs` lists that real job as `succeeded` and `GET /api/jobs/:id` returns its real, non-empty progress log. The generations endpoint is then re-queried to confirm it reports the **new** generation as current — which is the honest end-to-end proof that the rollback UI would be showing an operator the truth.
- **A new `checks.ui-renders-every-schema-type`** — a cheap, CI-safe eval check in the spirit of the existing `catalog-consistency`/`schema-uniformity` pair: walk the real `settings-schema.json` and assert every type it actually contains is one `forms.js` declares a control for. This is the mechanical guard on the claim that adding an app requires no `ui/` change; without it, the claim decays the first time someone adds an option shape the renderer never saw, and nothing fails until an operator loses a field.
- **Unit tests** for: profile-directory parsing (including a directory containing a `system` symlink and non-`system-N-link` entries), the `rollbackable`/`reason` mapping, the SPA fallback's `/api/` exclusion, path-traversal rejection, and the job-list query's `limit` clamping.

## Known Risks

1. **The no-build UI has no type checking against the schema it renders.** A typo in a schema key path fails at runtime in a browser, not at build time. `checks.ui-renders-every-schema-type` covers the type-coverage half of this; the field-path half is covered only by the real VM test actually loading the page. This is the accepted, eyes-open cost of the stack choice, and it is the risk most likely to produce a defect that reaches an operator.
2. **`ferrum-state`'s extraction is a refactor of shipped, tested code** — identical in shape to 1.5a's `ferrum-secrets` risk, and the `Cargo.lock` regeneration it requires has already caused two CI failures in this repo's history.
3. **Reading `/nix/var/nix/profiles/` directly is a second reader of a format `nix-env` owns.** It is a stable, long-documented layout, but it is not an API contract. The mitigation is that the two producers are asserted to agree on the date format, and `parse_nix_env_list` survives with its tests as the fallback path if the direct read ever proves wrong.
4. **The rollback confirmation dialog is a product risk, not a technical one.** It is the single place where "what ferrum rolls back" meets "what an operator assumed ferrum rolls back," and the original design doc names getting it wrong as how a technically correct product earns a reputation for losing data. Its wording deserves review as carefully as any code in this phase.
5. **Schema staleness across a rebuild** (1.5a known risk 4, inherited) — the UI can be rendering a form from a catalog its daemon has since replaced. Handled by surfacing the validation rejection rather than by preventing the situation, which is not preventable in a browser tab.
