# Road to public

The running checklist. Tick items off as they land. Kept in the repo so it survives a dead session.

Status key: `[ ]` not started · `[~]` in progress · `[x]` done

Last updated at HEAD `288f2b3`, branch `grounding-and-install-path`. Nothing pushed.

---

## Phase 1 — Finish R13 (publishing the dashboard)

- [~] **1. Security gate passes.** Third pass running. Two prior passes went 1C/3H/4M -> 0C/2H/1M
      -> now re-checking. Everything found so far is fixed and mutation-proved.
- [ ] **2. Decide: a failed stage 2 now leaves no web UI at all.** Stage 1 turns the daemon off so
      it cannot be published without auth. Correct for security; it means recovery from a failed
      install is SSH-only. Your call, and it bears directly on the hands-off requirement.
- [ ] **3. Push the branch and open the PR.** 141+ commits, no upstream set. Needs your explicit
      go-ahead — this is the only step that leaves your machine.

## Phase 2 — Bugs that affect a real host

- [ ] **4. R17 — settings saves are broken on a pooled host.** A live bug on your own box, and the
      dashboard is the product's face. Highest-value item after R13.
- [ ] **5. R21/A1 — a fresh multi-disk install puts the whole library on one disk.** Reproduced
      against real mergerfs: `epmfs` only picks a branch that already has the parent path, so a
      blank second disk stays inert. Your host escapes it only because both disks already held
      media.
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
- [ ] **20. Fix `stack-catalog.snapshot.yaml`**, which records the wrong stack.

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
