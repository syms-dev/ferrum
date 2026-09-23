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

- [x] **2. A failed stage 2 leaves no web UI.** DECIDED 2026-09-23: **keep the daemon
      unpublished, but keep it RUNNING on loopback** so the SSH-tunnel route reaches a real
      dashboard. **DONE 2026-09-23**, together with R13 deferred ticket #1 below — the two
      reverse each other if landed apart.
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
      - **Built as scoped**, plus three things the scope did not anticipate.
        `crates/ferrumd/src/settings.rs`'s `publication_matches_auth` is the same predicate
        written a second time, in Rust, guarding `PUT /api/settings` — without the new term it
        would have refused the exact document stage 1 writes, and told an operator who wants a
        tunnel-only dashboard that their only option is a host with no UI. `nginx.nix`'s H-03
        message offered `daemon.enable = false` as its recommended way out, which is the bug;
        it now offers `daemon.publish = false` and says plainly what the other two cost.
      - **A latent hard failure fell out of it.** The generated `flake.nix` hardcodes
        `ferrum.daemon.enable = true` in the host's own inline module, and `mkHost` feeds
        `settings.json` in as an ordinary `config.ferrum` definition — so stage 1's
        `daemon.enable = false` was an *unequal second definition of one `types.bool`*.
        Really evaluated, really failed: `error: The option 'ferrum.daemon.enable' has
        conflicting definition values: ... true ... false`. Nothing looked, because the Nix
        checks build hosts from a settings attrset without the generated flake's module and the
        installer's tests read the two files separately. Stage 1 now writes `enable: true`,
        which agrees, and `the_generated_flake_and_stage_one_settings_agree_about_daemon_enable`
        cross-checks the two rendered files so it fails whichever one moves.
      - **Added `daemon-unpublished-but-running`** (`nix/modules/flake/checks.nix`, wired into
        `.github/workflows/ci.yml`). Two fixtures differing in exactly one setting, every
        assertion a differential against the control, all of it read off the **generated**
        config: the systemd unit text, the nginx `virtualHosts` attrset, `security.acme.certs`,
        and the real DNS document `ferrum-dns` consumes. It is the only place asserting the
        conjunction — *the unit is present* **and** *the publication surface is absent* — which
        is what stops `publish = false` quietly deleting ferrumd again.
      - **Mutation-proved, both halves separately.** Reverting the `publish` term in
        `daemonPublished` makes it **exit 1** on the vhost, the certificate and the H-03
        exemption; reverting only the `dns.nix` gate makes it **exit 1** on the record alone,
        with the other assertions still green — which is the evidence that ticket #1's fix is
        load-bearing on its own and not carried by the predicate change.
      - **Lands with item 11** (confirm the SSH-tunnel route in a real browser), which is the
        acceptance test for exactly this. Item 11 is still open: nothing here has been driven
        through a real browser over a real tunnel.

- [x] **3. Push the branch and open the PR.** DONE — **PR #4**:
      https://github.com/syms-dev/ferrum/pull/4 (base `main`, 240 files, ~53k insertions).
      The harness denies `git push` to the agent ("Out-of-Place Publication"), so the owner runs
      the push; the PR picks up new commits automatically.

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
- [x] **7. The three R13 deferred tickets.** ALL THREE DONE 2026-09-23.
      - ~~`modules/proxy/dns.nix` `daemonRecords` never consults `daemon.enable`, so a daemon-off
        host still gets a DNS record for a hostname nginx closes. **Whoever fixes this must also
        update `checks.nix`'s anti-vacuity guard, which currently depends on it staying
        unfixed.**~~ **DONE 2026-09-23**, with item 2 above and deliberately in the same change:
        `daemonRecords` is now `daemonPublished && includeRecord`, so the record moves with the
        vhost, the Authelia rule and the certificate instead of on its own. `includeRecord` is
        conjoined rather than replaced — it is still the operator's one-line opt-out on a host
        that *is* publishing, which is a different statement from "this host publishes nothing".
        The `dns-record-set` anti-vacuity guard was **re-aimed, not deleted**: the proxy-off
        fixture's record list is legitimately empty now, so "this document contains a daemon
        record" could no longer carry it. It is a differential instead — `dashboardOnly` is the
        same fixture with the proxy **on** and is asserted to carry both records, so the only
        difference between two records and none is the proxy term. The proxy-off document is
        also removed from the `proxied == false` loop, whose `length > 0` term is that loop's
        own anti-vacuity half and must not be weakened to accommodate it.
      - ~~`crates/ferrumd/src/main.rs:279-282` still says ferrumd is loopback-only and the
        subdomain is unused. R13 falsified both.~~ **DONE 2026-09-23.** The paragraph above
        `session_handler` now says the same-site sibling is a present fact rather than a future
        one, and separates *published* from *binds loopback* — conflating those two is what made
        it wrong. **Pinned**, because this is the fourth comment in this tree to go quietly
        false: `no_comment_still_claims_the_daemon_has_no_vhost` scans main.rs's own comment
        prose for the four sentences R13 falsified, with
        `the_stale_claim_scan_really_reads_comments_and_only_comments` as its positive control.
        Mutation-proved: the old paragraph makes it **exit 101**.
      - ~~`examples/hosts/minimal` does not evaluate.~~ **DONE 2026-09-23 — zero failing
        assertions, proved by evaluating `config.assertions` directly.** It had **five**, not two,
        and the reason it kept failing while keeping its name is that it was not minimal: it
        published seven apps on a real domain, the same shape as `examples/hosts/template`.
        - **Three** were the committed servarr secrets, fixed by **deleting** them — the remedy
          those assertions themselves print. They were encrypted to an age recipient nobody
          cloning the repo has, so the template looked like a working starting point and was not.
        - **Two** were one fact in two messages. Exposure defaults to `public` whenever the proxy
          is on, so six apps were published; publishing needs a certificate, which needs a
          Cloudflare token that cannot be committed. Declaring the secret without shipping it only
          moves the failure from "not declared" to "declared but the file is missing".
        - **Fix: make the name true.** Every app moves to `lan`, the dashboard stays unpublished
          — a line only expressible because `daemon.publish` now exists — so no certificate and
          no secret are needed. The proxy stays **on**, so the example still demonstrates nginx
          and the lan allow rules rather than switching the interesting part off to pass a check.
          Publishing is what `template` is for, and it already carries that shape.

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

- [x] **12. Comment rubric.** AGREED 2026-09-23 — `docs/COMMENT-RUBRIC.md`. Nothing rewritten yet.
      - **The measuring changed the plan.** 30% of the Rust is comment lines (10,943 of 36,776;
        `auth.rs` is 38%), which reads like bloat until sampled. It is overwhelmingly *reasoning*.
        The longest block, `inventory.rs:197`, records an incident where an over-strict check
        retroactively invalidated every inventory file written before it — **landing past the disk
        wipe**, where it was the only remaining path and its own printed advice could not work.
      - **The failure modes are asymmetric.** Deleting a load-bearing comment destroys a decision
        that cost an incident to learn, silently, with no test to catch it. Leaving a verbose one
        costs a reader seconds. Four findings this run were comments that had gone **false** — one
        survived three review passes and was caught only by salvaging a nearly-deleted branch.
      - **Agreed shape:** the **falsity pass runs first and alone** as a correctness fix, pinning
        load-bearing claims with guards (precedent exists twice). Style rules follow. The
        subjective rules (6–8) run **file by file**, never repo-wide. Docstrings required by the
        project's documentation rule are explicitly protected.

- [ ] **13. De-verbose the comments**, via the `humanize` skill (which runs `humanizer` first).
- [x] **14. Remove AI mentions from the working tree.** DONE. Most vanished with their files —
      see item 19; the two were one decision. The five that remained were in real design docs and
      were **reworded, not deleted**, because each carried meaning the vendor name was incidental
      to: a design tool's brand, two rule-file paths, a voice-guide path. The attribution decision
      in `phase-1-9-ship-it-design.md` keeps its **full** record — the 226/186 inventory, the
      approval date, the commitment — with the name generalised, since deleting it would erase
      the audit trail of a decision the project made deliberately and still honours.
      **Two remain on purpose:** `.gitignore` must name `.claude/` in order to ignore it, and
      this file is the live checklist — review it last, not while writing against it.
- [x] **15. Git history.** DECIDED 2026-09-23: **leave it alone.** The decision is recorded here
      so it is not re-litigated at the last minute before going public.
      - **The attribution is already gone.** The `Co-Authored-By` trailers — 186 of 226 commits —
        were stripped under the plan approved on 2026-09-21
        (`docs/superpowers/specs/2026-09-21-phase-1-9-ship-it-design.md`). That plan did what the
        standing rule asks: no commit or PR claims the work was machine-authored.
      - **What remains is not attribution.** Seven commit bodies name tools and files actually
        used — `.claude/skills/humanize`, `CLAUDE.md`, `claude-kit`, `Claude Design`. They say
        what a change touched, not who wrote it. Scrubbing them would leave messages describing
        things by names that no longer appear anywhere, which is worse documentation, not better
        hygiene. Only `657a052` carries one in its subject, so only one is visible in
        `git log --oneline`.
      - **The price went up after the checklist was written.** PR #4 is open, so a force-push now
        rewrites a branch under review; ~20 commit SHAs are cited inside docs and evidence files
        and would dangle; and a rewrite has already invalidated a pipeline ledger here once.
      - **Reopen only if** the repo gains an external contributor before going public (rewriting
        after someone else has cloned is materially worse), or if a future commit message carries
        real attribution rather than a tool name — which the standing rule already forbids.

- [ ] **16. Deep bug-hunt across the whole codebase.** Not a diff review — a sweep.
- [x] **17. Test sufficiency audit.** DONE — `docs/TEST-SUFFICIENCY-AUDIT.md`. Audited on the
      axis the item was actually raised on: **vacuity**, not coverage percentage. A test that
      cannot fail is worse than no test, and this run's gate failed twice on exactly that.
      - **765 Rust tests, 41 Nix checks. Zero genuine findings.** Every candidate the heuristics
        surfaced was a false positive on inspection — the two assertion-free tests assert a few
        lines below where the detector stopped reading; the two unguarded Nix checks drive
        hardcoded literal data and assert exact equality, which cannot go empty.
      - **Why it came back clean:** `checks.nix` carries **176** occurrences of anti-vacuity
        vocabulary (`control` ×82, `vacuous` ×9, `would pass` ×7). That is a project that has been
        bitten and answered, not a style tic.
      - **The pattern worth copying** (`crates/ferrumd/src/main.rs:2124`) defends itself three
        ways: a cross-check, an `is_empty` assertion so two empty lists cannot agree their way to
        green, and **a positive control for the recogniser itself** — without which a matcher
        returning `None` unconditionally would sit green forever pinning nothing.
      - **The audit is explicit about its limits.** It establishes these tests *can* fail, not
        that they test the right things. And it names the real gap rather than burying it: this
        is item 9 — **21 of 41 checks have never executed on this machine**, so everything about a
        *running* system is unproven rather than safe. That is a bigger hole than anything found
        here.

## Phase 6 — Housekeeping before anyone looks

- [x] **18. Remove the run's git worktrees.** DONE — 16 removed, 1 left (the repo itself).
      **Checking merge status first was not a formality.** `r13-fixes` held **4 unmerged commits**
      that deleting its worktree would have destroyed; see item 7. All 15 branch refs are kept,
      so nothing is unrecoverable even now.
- [x] **19. What `.gitignore` should do with `.claude/`.** DECIDED + DONE: **the build
      pipeline does not ship in the thing being built.** 21 files untracked — the `.ckit/` tree,
      a stray skill under the otherwise-ignored `.claude/`, `AGENTS.md`, `README.claude-sdlc.md`,
      `.design-sync/NOTES.md`. Verified first that none is referenced by CI, the flake, any module
      or any crate. All still exist on disk and the hooks reading them are unaffected.
      Two would have been actively misleading in public: `stack-catalog.snapshot.yaml` records
      python/fastapi/postgres for a repo with **zero `.py` files**, and the agent-memory store is
      a running commentary on the project's own mistakes. `CLAUDE.md` was never tracked, so the
      top-level agent config was already local-only; this makes the rest consistent.
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
