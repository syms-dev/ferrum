# Road to public

The running checklist. Tick items off as they land. Kept in the repo so it survives a dead session.

Status key: `[ ]` not started · `[~]` in progress · `[x]` done

Last updated at HEAD `288f2b3`, branch `grounding-and-install-path`. Nothing pushed.

---

## Phase 1 — Finish R13 (publishing the dashboard)

- [x] **1. Security gate passes.** DONE — R13 pipeline run **completed**, all 7 gates resolved.
      Security went 1C/3H/4M -> 0C/2H/1M -> **8C/3H/6M** (once enumerated correctly) -> **0C/0H/0M
      unaccepted**. Merge `42ad546`, verified by the coordinator on the merged tree:
      `cargo test` **761 passed exit 0** (751 at base) · clippy **0 lines exit 0** · **17 of 17
      runnable nix checks pass**. The 2 nix failures are KVM-gated and were proved pre-existing by
      re-running them at the merge base. Zero regressions.
      - **Enumerating forward was the whole ballgame.** The standing map said 8 sinks, all
        constrained; the truth was **24 sinks, 17 unconstrained, 8 Criticals**. Five newly-found
        directive grammars, every one executed as root: `systemd.tmpfiles.rules`, systemd unit
        **list-fields**, fstab options, `users.groups`, sops paths. The list-field one is worth
        remembering because it contradicts a fair assumption — nixpkgs JSON-quotes `Environment=`
        but emits list-fields as raw `Key=value` lines, so `ReadWritePaths` rendered a working
        `ExecStartPre` into a real unit.
      - **Never enumerate taint backward.** A backward pass enumerates *files*, but a value
        reaches a grammar through whatever file interpolates it. `pool.branches` was filed
        "Low/fstab" because the pass began at `pool.nix` — its Critical tmpfiles sink is in
        `storage.nix`.
      - Fixed at the **write boundary**, not per sink: schema patterns + `propertyNames` on the two
        key-position namespaces + mirrored evaluation-time types. Two regression checks assert on
        **generated text**, which is what stops the next unknown sink being silent.
      - The High was injection's mirror image: a throttle that denied the **correct** password to
        every operator at once, including through the SSH-tunnel recovery route. Third instance of
        *a throttle keyed on a shared axis is a lockout*; the generalisation now lives in a doc
        comment where the mistake would next be made.
      - **2 Mediums recorded as ACCEPTED RISK, never as PASS** — `docs/security/SEC-M02…` and
        `SEC-M03…`, each bound to accepting person, evidence hash and commit, each going stale
        automatically if the code moves.

- [~] **2. A failed stage 2 leaves no web UI.** DECIDED 2026-09-23: **keep the daemon
      unpublished, but keep it RUNNING on loopback** so the SSH-tunnel route reaches a real
      dashboard. Scoped below; not yet built.
      - **Why it happens.** `modules/core/daemon.nix:60` wraps the whole module in
        `lib.mkIf ferrum.daemon.enable`, so stage 1's `daemon.enable = false`
        (`render.rs:670`) does not merely unpublish the daemon — it stops it existing. No
        service, nothing on loopback, nothing to tunnel to.
      - **Why `enable = false` was right anyway.** `daemonPublished = daemon.enable &&
        proxy.enable && baseDomain != ""` (`modules/proxy/lib.nix:76`), and stage 1 writes
        `proxy.enable` and a `baseDomain` because ACME needs them. Stage 1 also cannot enable
        Authelia (its sops secrets cannot exist before the host does). So omitting the key would
        publish settings, apply and rollback at `ferrum.<domain>`, on a real certificate that
        makes the hostname easy to find, with `auth_request` absent. Not theoretical — stage 2
        has failed on real hardware here more than once.
      - **The fix: split running from publishing.** Add `ferrum.daemon.publish` (default true).
        `daemonPublished` becomes `enable && publish && proxy.enable && baseDomain != ""`.
        Stage 1 then writes `{ enable = true; publish = false; }` — ferrumd runs, bound to
        loopback (already asserted loopback-only, `daemon.nix:58,82-90`), unreachable from the
        network, and still behind its own `__Host-ferrumd_session` login, so an SSH tunnel is
        not an unauthenticated back door.
      - **This also closes R13 deferred ticket #1.** That ticket wants `dns.nix` `daemonRecords`
        gated on `proxyLib.daemonPublished ferrum` instead of publishing a record for a hostname
        nginx closes. The same predicate change fixes both, so they should land together rather
        than one reversing the other.
      - **Touches:** `modules/core/options.nix`, `modules/lib/settings-schema.json`,
        `modules/proxy/lib.nix`, `modules/proxy/dns.nix`, `crates/ferrum-install/src/render.rs`,
        plus the `checks.nix` anti-vacuity guard that currently depends on ticket #1 staying
        unfixed. Feature-shaped: wants the pipeline, not a patch.
      - **Lands with item 11** (confirm the SSH-tunnel route in a real browser), which is the
        acceptance test for exactly this.

- [ ] **3. Push the branch and open the PR.** 141+ commits, no upstream set. Needs your explicit
      go-ahead — this is the only step that leaves your machine.

## Phase 2 — Bugs that affect a real host

- [x] **4. R17 — settings saves on a pooled host.** ALREADY FIXED, verified 2026-09-23 with the
      same method the audit used to prove it broken. The original F1: `storage` had
      `additionalProperties: false` and no `pool` key, while the installer writes `storage.pool`
      for any host with >1 data disk — so every dashboard save on your box failed validation
      because of what was already in the file, not what you changed.
      Now: `storage.properties` includes `pool` (`enable`, `branches`, `minFreeGiB`, `policy`).
      Proved end-to-end by validating the installer's exact two-disk output
      (`{"schemaVersion":1,"storage":{"pool":{"enable":true,"branches":["/mnt/ferrum-disk-0",
      "/mnt/ferrum-disk-1"]}}}`, from `render.rs:606-616` + `branch_path`) against the shipped
      schema with `Draft202012Validator`: **ACCEPTED**.
      F2's root cause is closed too — `settings-schema-covers-every-option`
      (`nix/modules/flake/checks.nix:2317`) is the missing option-tree-vs-schema check the audit
      said the repo needed and lacked, and it passes. **Worth re-testing on the real host** once
      this branch is deployed, since the proof here is against the schema, not against your
      running daemon.

- [x] **5. R21/A1 — a fresh multi-disk install puts the library on one disk.** ALREADY FIXED in
      `0993b7b`, verified 2026-09-23, and **now pinned** (it was not).
      - **Verified, not assumed.** Evaluated a pooled host with two branches and read the
        generated tmpfiles rules: `d /mnt/d0/media/movies` **and** `d /mnt/d1/media/movies`.
        Both branches are seeded, so `epmfs` ("existing path, most free space") has more than
        one candidate and can balance by free space. A disk added later is usable.
      - **The gap was that nothing held it in place.** No check referenced pool seeding; all 13
        `pool` mentions in `checks.nix` came from the new security work. Exactly the pairing
        problem F2 named — two things that must agree with no mechanical check — which is what
        let the settings schema drift until the dashboard could not save at all.
      - **Added `pool-branches-are-all-seeded`** (`nix/modules/flake/checks.nix`, wired into
        `.github/workflows/ci.yml`). It derives the expected subdirectory list from the
        generated rules for the first branch and requires the others to match, rather than
        hardcoding a third list free to drift.
      - **Mutation-proved.** Reverting `storage.nix` to the original bug makes it **exit 1**.
        Worth noting which half caught it: `divergentBranches: []`, `expectedCount: 0` — all
        three branches agreed *because all three were empty*. The branch comparison alone would
        have passed with the defect fully present; only the length floor caught it.

- [ ] **6. R14.**
- [ ] **7. The three R13 deferred tickets.**
      - `modules/proxy/dns.nix` `daemonRecords` never consults `daemon.enable`, so a daemon-off
        host still gets a DNS record for a hostname nginx closes. **Whoever fixes this must also
        update `checks.nix`'s anti-vacuity guard, which currently depends on it staying unfixed.**
      - `crates/ferrumd/src/main.rs:279-282` still says ferrumd is loopback-only and the subdomain
        is unused. R13 falsified both.
      - `examples/hosts/minimal` does not evaluate — two reasons now (missing `acme-dns`, plus the
        auth-off assertion). This is the config a new operator copies, so it matters more than its
        severity suggests.

## Phase 3 — The dashboard people will actually see

- [ ] **8. Dashboard revamp.** Today it is a settings form. The product is a window onto the
      system: what is running, is it healthy, what updates exist, one action each to update or
      roll back. The read-only APIs and the schema renderer survive a redesign; the form as the
      primary surface does not.

## Phase 4 — Prove it works, not just that it builds

- [ ] **9. Run the KVM-gated VM tests in CI.** 21 of 34 Nix checks have never run on this Mac.
      Everything about a *running* system is currently unproven rather than safe: Authelia
      actually starting, real ACME issuance, real ferrumd behind the vhost, rollback,
      install-from-nothing.
- [ ] **10. A real install on real hardware, start to finish, no manual steps.** The standing test:
      from a bare machine, does the operator end up with a working, published, logged-in system
      without being told to do anything by hand?
- [ ] **11. Confirm the SSH-tunnel recovery route in a real browser.** The `__Host-` cookie
      prefix over `http://127.0.0.1` is correct per spec and unexercised. It is the only way in
      when the proxy is broken — exactly when you need it.

## Phase 5 — The pre-public cleanup (your four steps)

- [ ] **12. Agree the comment rubric on a sample first.** 9,164 comment lines across 32,732 lines
      of Rust. Comments here are load-bearing — four separate findings this run were comments that
      had become false — so the sweep carries real risk. Rubric plus a handful of real
      before-and-afters, including one load-bearing comment, before touching the codebase.
- [ ] **13. De-verbose the comments**, via the `humanize` skill (which runs `humanizer` first).
- [ ] **14. Remove AI mentions from the working tree.** 8 tracked files, none of them source:
      `AGENTS.md`, `README.claude-sdlc.md`, `.design-sync/NOTES.md`, `.gitignore`, and four
      spec/plan docs.
- [ ] **15. Decide on git history.** 6 commit messages contain a mention. Editing them means
      rewriting history, which is destructive and has already invalidated a pipeline ledger here
      once. Separate decision from the working tree.
- [ ] **16. Deep bug-hunt across the whole codebase.** Not a diff review — a sweep.
- [ ] **17. Test sufficiency audit, unit and e2e.** Warranted: this run's test-coverage gate failed
      twice on tests that could not fail, including assertions scanning an empty corpus and an
      acceptance criterion enforced by nothing.

## Phase 6 — Housekeeping before anyone looks

- [ ] **18. Remove the run's git worktrees.** Several remain under `.claude/worktrees/`.
- [ ] **19. Decide what `.gitignore` should do with `.claude/`.** It currently ignores the whole
      directory, so claude-kit's "committed" agent-memory store is not committed.
- [ ] **20. Fix `stack-catalog.snapshot.yaml`** — diagnosed 2026-09-23, less harmful than it
      looks, but the residue is real. `.ckit/config/` (the live one the hooks read) records
      **react · typescript · python · fastapi · postgres** for a project that is Rust + Nix with
      a React `ui-kit`. ferrum contains **0 `.py`, 0 `.sql`, 0 migrations/models dirs.**
      - **Mostly inert.** `fastapi-patterns.md`, `postgres-patterns.md` and
        `database-performance.md` are `paths:`-gated to `**/*.py`, `**/*.sql`,
        `**/migrations/**` and `**/models/**` — globs nothing here matches, so they never load.
        `react-patterns.md` gates on `**/*.ts(x)` and DOES fire on 170 files, which is correct:
        `ui-kit` really is React + TypeScript.
      - **What actually leaks:** three agents that can never apply (`postgres-specialist`,
        `migration-specialist`, `db-performance-reviewer`), and ~10 Python/DB skills in the
        picker. CLAUDE.md names *substitution* — a plausible neighbour winning — as a measured
        failure mode, and a catalog advertising the wrong stack feeds exactly that.
      - **The real gap is the inverse:** there are **no Rust or Nix overlay rules at all.** The
        stack this project is actually written in has zero stack-specific guidance installed.
      - **Two snapshots disagree.** `.claude/config/` says every stack field is `none` and
        `overlay_rules: []`; `.ckit/config/` matches what is really on disk. `.claude/` is
        gitignored, so the `.ckit/` one is authoritative. Fixing this means re-running the
        claude-kit installer, which is **yours to invoke** — the model must not run
        `/ckit-command-*` skills.

---

## Carried costs — recorded, owned, not blocking

Each was accepted with a revisit trigger rather than forgotten.

- **The nginx parser gate is not a routing gate.** `nginx-config-parses` proves the config loads,
  not that it routes. A runtime probe exists and passes but is not a check. Revisit on the next
  change to any `location`, `error_page`, `auth_request` or `proxy_set_header` line.
- **Authelia's config is never validated.** `authelia validate-config` runs nowhere. If it fails
  to load, `auth_request` 500s and the dashboard and every gated app go dark.
- **HSTS is deliberately absent.** One-way door; add `max-age=300` and grow it once ACME renewal
  is boring. Never `preload`.
- **L-01, the logout CSRF gap**, needs a `ui/api.js` change and a route move landing together —
  either alone gives a silent false logout. A passing tripwire test names the other half.
- **The `apps` schema node defers 10 options.** All enums, integers, paths or already typed at
  eval; none reaches a generated directive.
- **The DNS reconciler's JSON values are unconstrained** (`staticAddress`, `cnameTarget`,
  `adoptedNames[]`). They reach Rust and the Cloudflare API, not an nginx directive.
- **Schema regression pins cannot read the real schema file** from `crates/`, because every Rust
  derivation filters `src` to `crates/`. Closing it needs three `nix/` source filters widened.
- **`main.rs:377`'s CSRF compare is not constant-time.** Pre-existing, out of R13's range.
