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

- [~] **6. R14 — updates.** The **discovery slice is BUILT, MERGED and DEPLOYED** to the owner's
      host (2026-10-05): R1 discovery + R3 preview + R6 the Updates view. `/api/updates` answers
      on the box and the view is in the served `app.js`.
      - **Deliberately NOT built**, and still open: Phase 1.6's **R2** (pin-advance
        authorization), **R4** (applying an update as a generation), **R5** (rollback of a bad
        update), **R7** (selective vs wholesale), **R8** (recording the pin a generation was built
        from). Spec: `docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md`.
      - **Live consequence on the owner's host:** nixpkgs is pinned at **2026-06-11**, so Prowlarr
        sits at 2.4.0.5397 while 2.6.5.5623 is upstream. Prowlarr cannot self-update — its binary
        is in the read-only nix store — so nothing was ever going to surface this before R14.
        **You can now SEE the update; you cannot APPLY it from the UI.** That is Phase 1.6 R4.
      - Security review of the shipped slice: `docs/security/r14-update-discovery_security-review.md`
        — 0 Critical, 0 High, both Mediums fixed before merge.

- [~] **7. The three R13 deferred tickets.** Two done; the third was ticked in error and is reopened — see below.
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
      - **`examples/hosts/minimal` STILL DOES NOT EVALUATE — my earlier tick was wrong.**
        I proved `config.assertions` is empty and called the ticket done. That was the wrong
        measure: the ticket says the example does not *evaluate*, and realizing its toplevel still
        fails with `path '.../secrets/prowlarr-apikey.sops' does not exist`.
        - **The five assertions ARE fixed** and that work stands — three stale servarr secrets
          deleted, and `daemon.publish = false` + all-LAN exposure closing the auth and acme-dns
          pair. Assertions go 5 -> 0, verified.
        - **What remains is structural, not a loose end.** `modules/apps/*/service.nix` declares
          `sops.secrets."<app>-apikey"` unconditionally with a `sopsFile` path nix must resolve at
          eval time. A real host has that file because `ferrum-apply` generates it before the
          build; a checked-out example never can. **No example host enabling a servarr app can
          fully evaluate from a clean clone**, which is why `eval-example-hosts` has always been
          excluded from CI rather than merely being expensive.
        - Deleting the committed secrets did not cause this; it moved the failure earlier. Before,
          the files existed and eval failed later on the missing `-raw` counterparts.
        - **Real options, none taken yet:** gate the sops declaration on `pathExists` (changes
          real-host behaviour and risks silently skipping a secret); ship an example that enables
          no secret-generating app (makes the example nearly contentless); or state plainly that
          examples are templates to copy rather than configurations that evaluate, and retire
          `eval-example-hosts`. **Owner decision.**

## Phase 3 — The dashboard people will actually see

- [ ] **8. Dashboard revamp.** Today it is a settings form. The product is a window onto the
      system: what is running, is it healthy, what updates exist, one action each to update or
      roll back. The read-only APIs and the schema renderer survive a redesign; the form as the
      primary surface does not.

## Phase 4 — Prove it works, not just that it builds

- [~] **9. The KVM-gated VM tests.** **Premise corrected 2026-09-23 — CI already runs them, and
      they pass.** What is actually broken is narrower and worse.
      - **`vm-tests` PASSES** on `x86_64-linux`, covering eight checks: `install-from-nothing`,
        `rollback`, `rollback-proves-necessity`, `apply-generation-switch`, `daemon-end-to-end`,
        `daemon-apply-end-to-end`, `privilege-boundary`, `state-restore-interlock`. They never run
        on this Mac (no KVM), which is not the same as never running.
      - **`stage2` and `stage2-resume` have failed on EVERY run since at least 2026-09-21** — and
        not on ferrum code. Both die on the GitHub Actions nix cache: `ResourceExhausted / rate
        limit exceeded`, surfacing as `HTTP error 418` today and `substituter ... is disabled`
        on 21 September. **`stage2` is "install a real host end to end", so the single most
        important test this project has have been returning no signal for days**, and returning
        it in the shape of a red cross that looks like a code failure.
      - **Fix direction:** stop depending on the GHA cache for these two jobs — pin
        `--option substituters`, or tolerate a disabled substituter instead of failing, so a cache
        outage degrades to a slower build rather than a false red. Until then neither job can
        confirm or deny anything about the installer.
      - **The aarch64 `smoke` leg failing is EXPECTED** and must not be counted: GitHub's ARM
        runners ship no `/dev/kvm`. It is a deliberate non-blocking live probe with a long comment
        saying exactly that, kept so it starts passing for free the day ARM runners gain KVM.
      - **2026-10-05: `stage2` now runs for 3h00m and hits its 180-minute cap**, and the four CI
        jobs beside it were **cancelled** at exactly 15m02s — identical durations across
        independent jobs, so the queue cut them loose rather than four bugs appearing at once.
        **`gh pr checks` renders "cancelled" as "fail"**, which made the run look like 8 failures
        and 1 pass when nothing in the code had broken. Read `.jobs[].conclusion`, not the summary.
      - That stage2 reaches the cap at all is progress: it is past the cache throttle, the live
        Cloudflare token check and the drifted answers fixture, and is now simply building a NixOS
        system twice inside a VM for longer than the budget allows. **Next step is a budget
        decision, not a defect hunt.**
      - **`stage2`'s REAL cause found 2026-09-23, and it is not the cache.** The `fallback = true`
        fix worked: the job now gets past the cache noise, builds ferrum-install (350 tests pass
        inside the Nix build), boots the target VM, and runs the installer — which then **exits 1
        because it validates the Cloudflare API token against the live API** and the test supplies
        `placeholder-cf-token`. `answers.rs:858`, added by **`d19c957` on 2026-09-21** — the exact
        day stage2 started failing. The cache errors were noise on top of this.
      - **The product question underneath it:** an install with a base domain cannot complete
        without a live, valid Cloudflare token. That makes the end-to-end install untestable in CI
        by construction, and unavailable offline. Either the validation needs a documented bypass
        for a test/offline path, or `stage2` must drive a no-domain install — which would stop
        exercising SSO and ACME, the parts most worth testing. **Owner decision.**
      - **`nginx-config-parses` had never passed in CI** — see the fix in `635e7d1`. It landed
        14:46 on 22 Sep; the last green run was 13:56. `nginx -t` **binds** every listen address,
        and a CI builder is unprivileged.

- [~] **10. A real install on real hardware.** **Substantially proven 2026-10-05** — the owner's
      host now runs this branch end to end: pool 17 TB across two branches, 7.0 TB library, all
      seven apps active, Authelia, qBittorrent inside a Proton tunnel with the kill switch,
      dashboard published at `ferrum.thesyms.ca` with a real certificate, nine DNS records
      correct, **zero failed units**.
      - **What is still NOT proven:** a *fresh* install from bare metal with no manual steps. This
        host was upgraded in place, not installed from nothing.
      - **The manual step that remains is R3 of the field-defects spec** — Plex is never claimed by
        the installer. The owner's Plex was claimed by hand previously.
      - Four defects were found only by running it, and are specced: see Phase 7 below.

- [ ] **11. Confirm the SSH-tunnel recovery route in a real browser.** The `__Host-` cookie
      prefix over `http://127.0.0.1` is correct per spec and unexercised. It is the only way in
      when the proxy is broken — exactly when you need it.

## Phase 7 — Field defects (found by running it, not reading it)

Spec: `docs/superpowers/specs/2026-10-05-field-defects-design.md`, approved by the owner
2026-10-05, to be done **in spec order**. Every one was invisible to the test suite: four cannot
be reproduced in a Nix sandbox or a tempdir, and the fifth was contradicted by its own comments.

- [x] **F2. A multi-address WireGuard config must work.** DONE 2026-10-05, merged.
      Parsed into one entry per line and applied in a loop; fixture is the owner's REAL provider
      output with keys replaced, because the defect is in what providers issue. **IPv6 skipped
      deliberately** — the namespace is routed v4-only (default route, veth, kill-switch fallback
      and masquerade all v4), every skipped entry is named in the journal, and an IPv6-ONLY config
      is refused rather than silently producing an empty namespace. `AllowedIPs` checked and not
      on the same defect. Two mutations caught, including one that kept the parser's file, name,
      flags and call site and changed only its behaviour.
      ~~Previously:~~ `service.nix:125` hands the
      whole `Address` value to `ip addr add`; Proton issues `10.2.0.2/32, 2a07:b944::2:2/128` and
      it is refused. **Every Proton config fails as issued.** Worked around on the host by deleting
      the IPv6 address by hand.
- [x] **F4. A data disk ferrum did not format must still work.** DONE 2026-10-05, merged.
      **Split on whether the owning UID resolves:** an orphan UID carries no intent anyone could be
      respecting and the only remedy is a chown, so ferrum normalises it; a real local account is
      somebody's deliberate arrangement, so ferrum refuses and names the path, user, UID and exact
      command. The normalise arm runs precisely the command the refuse arm prints. Four mutations
      caught; the third found a real hole mid-build — a non-zero exit cannot distinguish a refusal
      from a failed chown, **and that difference is the decision**.
      ~~Previously:~~ `/mnt/ferrum-disk-1`
      was owned by UID 1001 — a user that does not exist on the host — and `systemd-tmpfiles`
      refused the ownership transition, failing `ferrum-media-tree.service` with `CANTCREAT`.
      **Not a regression from that unit:** the previous rules met the same condition and failed
      silently at boot. Worked around with `chown root:ferrum-media`.
- [x] **F1. DDNS must detect the host's public address.** DONE 2026-10-05, merged `79cf536`. The one
      that cost a night: the updater republished a **static** address from `settings.json` and
      nothing in `crates/` ever queried a public address, while three comments claimed it corrected
      records against the host's current one. Three sources run by three different parties now have
      to agree, a quorum counts **distinct operators** rather than endpoints, and every tie resolves
      towards publishing nothing — a wrong record is worse than a stale one, because it republishes
      every hostname at somebody else's server under certificates ferrum obtained itself.
      `reconcile-dns` grew a fourth exit code so *refused* is distinguishable from *could not find
      out*, and neither writes the last-success marker, so a host behind CGNAT cannot age quietly
      into looking healthy. Verified on the merged tree: tests exit 0, clippy 0 lines, new flake
      check exit 0.
      **Left open, now folded into F3's lane:** the installer still asks for a static address and
      never offers the updater, so discovery only helps someone who hand-edits settings.
- [x] **F3. The installer must obtain a Plex claim token.** DONE 2026-10-06, merged `661531d`. The
      installer now asks when Plex is enabled and a base domain is set, states the four-minute
      expiry up front, and takes a skip in one keystroke. The token is delivered as a **sops
      secret**; a test sweeps *every rendered file* for its value, not just `settings.json`.
      **The expiry cannot be closed at this layer and the change does not pretend it can** —
      sops-nix resolves every `sopsFile` at evaluation time, so the secret must exist before a
      stage-2 build that takes far longer than four minutes. Asking later shrinks the window and
      never shuts it. So the closing report states the **measured** outcome, read from Plex's own
      `Preferences.xml` on the host, and the headline now reads "installed, with one thing
      unfinished" rather than "installed".
      **F1's leftover closed here too:** the installer offers the DNS updater *before* asking for
      an address, and an updater host is asked for none and persists none.
      Verified on the merged tree: 969 tests pass (exit 0, up from 951), clippy 0 lines.
      **Not verified locally, and will first run on CI:** `tests/stage2/run.sh` — still eleven
      prompts, 9 and 10 swapped — because it needs real KVM and a QEMU guest.
- [x] **F5. Dashboard single sign-on — AS A PAIR, in order.** DONE 2026-10-06, as two commits so
      the first is revertible on its own.
      - **First: SEC-M02 closed.** Authelia now issues two cookies —
        `ferrum_control_session` on `ferrum.<baseDomain>` and `authelia_session` on `<baseDomain>` —
        so a cookie obtained in an app's context is not a cookie for the dashboard.
        `docs/security/SEC-M02_authelia-cookie-scope.md` records the close; **the ledger transition
        is the owner's to make.** The price was not obvious and was measured, not guessed: Authelia
        refuses an `authelia_url` outside the scope it serves, so the control plane needs a portal
        hostname of its own (`auth.ferrum.<baseDomain>`) and therefore its own vhost, certificate
        and DNS record.
      - **Then: `POST /api/sso`.** ferrumd still reads no forward-auth header off any request. It
        asks Authelia, over loopback, who the caller's cookie belongs to — so the first half is
        literally what makes the second safe, and `authelia-asserts-only-its-own-scope` measures
        that on a real Authelia every build.
      - `no_source_file_reads_a_forward_auth_header` was **replaced, not relaxed**, by
        `a_forward_auth_header_is_named_only_where_authelia_is_asked`: twelve of thirteen sources
        keep the original zero-occurrence rule, and the thirteenth may name one on exactly one line.
      - Login arithmetic, re-examined as the risk acceptance asked: two before, two after, and the
        dashboard's remaining one is now the Authelia the operator already uses.
      - **Security-reviewed, and it came back BLOCKED the first time.** The cookie-scope isolation
        itself was confirmed sound three independent ways — including a run against a real Authelia
        4.39.19 binary — and the hand-rolled HTTP client in `sso.rs` was traced clean: no path from
        a parse failure, truncation or malformed input to a false success. But two Mediums were
        real and are fixed in `6cc150e`:
        - The SSO cookie's attributes were pinned by nothing. Proved by mutation, not argued:
          deleting `set_secure(true)` from the SSO path alone left the whole suite green, because
          the only attribute test drives `/api/login`. One shared builder now, plus a test on
          `/api/sso`'s real wire `Set-Cookie`.
        - `/api/sso` had no bound at all while `/api/login` has two. A semaphore of 4 now sheds
          before the cookie is read and before any socket opens — not shared with the password
          lockout, which is the way in when the proxy is broken.
        - A comment claimed every route re-checks Authelia; the SSE job stream authorises once at
          open. The comment was corrected rather than the code, because re-verifying inside that
          loop would let a blip cut an operator's view of an apply.
      - Verified on the merged tree at `6cc150e`: **998 tests pass** (exit 0, up from 969), clippy
        0 lines, and **all 46 flake checks build, exit 0, zero error lines** — run by hand because
        the re-validation pass flagged honestly that it had not re-run them itself.

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

- [x] **13. The comment sweep.** DONE 2026-09-24 — measured, and the style half had nothing to do.
      - **The mechanical rules found zero.** Scaffolding phrases (`It is worth noting`,
        `Importantly`, `As mentioned above`, …): **0**. Short comments merely restating the code
        below: **0 of 181** checked. That matches the rubric's own finding — this codebase's
        comments are reasoning, not narration — so a de-verbose sweep would have changed nothing
        while putting real decision records in the hands of a taste judgement.
      - **A precise detector found three real defects instead.** Two doc comments with no item
        between them **merge**, and rustdoc attaches the whole thing to whatever follows. Three
        instances, each leaving one function documented twice and another with none:
        `check_recovered_device` carried an `# Arguments` for `v: the raw field` (its parameter is
        `&mut Device`); `rollback_to_current_reason` appeared to take a `profiles_dir` and to
        propagate a listing error (neither is true); `disclose_foreign_beside` had acquired
        `plan_with_adoptions`' whole adoption explanation. Meanwhile `clean_required`,
        `current_generation` and `plan_with_adoptions` had **no documentation at all** — their
        words stranded up to 150 lines away. Fixed by moving each block to its function; nothing
        rewritten, because the words were right and only the position was wrong.
      - **One of the three was introduced the same day** by a bug-hunt fix lane, so this is not
        only historical drift.
      - **The detector is the durable part.** Two earlier attempts found nothing, which is equally
        consistent with a clean codebase and with a broken search. The one that works cannot be
        fooled: a single doc block cannot legitimately contain two `# Arguments` or two
        `# Returns` sections. It reported three, and reports zero now.

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

- [x] **16. Deep bug-hunt across the whole codebase.** DONE 2026-09-23 — a sweep, not a diff
      review. Three read-only hunts on disjoint surfaces, then three fix lanes.
      **32 findings: 1 Critical, 3 High, 11 Medium, 17 Low. 26 fixed, 6 deliberately deferred.**
      Verified on the merged tree: `cargo test` **807 passed, exit 0** (765 before, +42 tests) ·
      clippy **0 diagnostics, exit 0** · **37 of 37 CI cheap checks pass**.
      - **The Critical was found while fixing something else.** `inventory.rs:422` rejected any
        by-id alias containing `-part` — and **every** partition alias contains it. So
        `Filesystem::by_id` was `None` on every device the live pipeline produced, and
        `render::media` aborted **before verification was ever reached**. The install path was
        broken twice over for any host keeping a data disk, and the second break masked the first.
        Every render test hand-built its `Filesystem` with the field pre-populated — the tests
        were testing a struct the pipeline never produces.
      - **The High it was found under:** verification asked `findmnt` about the **disk** while the
        generated config mounts the **partition**, so every install keeping a data disk failed its
        last check and bailed **before printing the one-time passwords**. A working host nobody
        can log into. The existing test asserted the *wrong* command string — it pinned the bug.
      - **The other two Highs:** a failed `reboot` reported a **successful rollback** while leaving
        the state swap armed for some later, unrelated boot; and two apps could claim one
        subdomain, with the alphabetically-earlier one silently winning the vhost, the DNS record
        and the Authelia policy.
      - **The dominant class was guards that cannot fire** — not missing code. The pool assertions
        sat inside the `mkIf` they policed; the reserved-subdomain assertion sat inside
        `mkIf proxyEnabled`, absent on the host where an operator would later turn the proxy on;
        the `secretsDir` assertion had become unreachable. That is the same class the test
        sufficiency audit (item 17) looked for and did not find **in the tests** — it was in the
        assertions instead.
      - **A regression the workspace run could not see.** Two new tests invoked `/bin/false` and
        `/bin/true`, absent from a Nix build sandbox, so `cargo test` was green everywhere a human
        looked while two flake checks failed with ENOENT. Caught only by running the **full** CI
        check set against the merged tree, and fixed by having the fixture write its own script.
        Mirror image of the nginx check fixed the same day, which was green locally as root and
        red in CI unprivileged.
      - **Deferred, named not silent:** job-file pruning (`list_jobs` reads every file before
        applying `limit`, and nothing prunes the directory — the lane refused it as "a behaviour
        change dressed as a perf fix"); `verify_still` on a resume past the wipe (lost
        defence-in-depth, not an open hole); 27 of 32 module assertions have no fixture (a
        programme, not a fix); and three catalog-derivation duplications.

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
        is item 9. **Corrected after CI ran:** those checks are KVM-gated and never run on this
        Mac, but CI's `vm-tests` job runs eight of them and **passes** — including
        `install-from-nothing` and `rollback`. Saying a running system was "unproven" was true of
        this laptop and false of the project. The real residue is item 10 (real hardware) and
        item 11 (the tunnel route in a browser).

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

## Phase 6 — Competitive position, and what reading a rival surfaced about us

Analyses live in `docs/competitive/`. They exist so the positioning survives a dead session and so
a public claim can be checked before someone else checks it for us.

- [x] **21. Silo.** DONE 2026-10-06 — `docs/competitive/silo.md`. **Verdict: no threat.** Silo is a
      media server, the Plex/Jellyfin slot *inside* a ferrum stack. Its own docs name Authelia and
      mergerfs as prerequisites the operator supplies by hand, and its "connect securely" page is
      install-Caddy-and-edit-a-Caddyfile. ~24 manual steps for one app. Its own release policy
      "does not guarantee downgrade or in-place rollback compatibility between releases" and
      recovery is a lossy backup restore — which is the best external validation of our thesis
      available, and belongs in the README.

- [x] **21b. Perfect Media Server.** DONE 2026-10-06 — `docs/competitive/perfect-media-server.md`.
      **Not a competitor — documentation, and a probable ally.** The headline: its author moved his
      own box from Proxmox to NixOS in 2024, the site now has a NixOS tech-stack page and two NixOS
      install pages, and his public config uses **mergerfs + SnapRAID + btrfs + snapper** with
      `nixos-anywhere` and `disko` as flake inputs. The canonical guide in our space runs our exact
      substrate. The seam is visible and it is ours: his NixOS config handles the *substrate* and
      contains no \*arr/Plex/Jellyfin — the apps are still Ansible-generated Docker Compose in
      another repo.

Items that analysis surfaced about **ferrum**, not about the projects analysed:

- [ ] **22. ferrumd has no health or readiness endpoint.** Thirteen routes, none of them health; the
      only health logic in the project lives inside `apply.rs` and ceases to exist when the apply
      ends. There is no steady-state way to ask the box whether it is well. Two handlers and a
      struct. **Degraded must be 200, not 503** — a watcher's reflex on 503 is to restart, which is
      the wrong move for a degraded dependency — and `AppState.interlock` already holds the applying
      job's UUID, so ferrum can report `"status":"applying"` honestly where Silo makes the operator
      infer it from logs. **Point no watchdog at readiness:** `main.rs` already records "a ferrumd
      restarted mid-apply by its own generation switch".
- [ ] **23. Staleness is not a reading.** A mergerfs branch that drops out must render *unavailable*
      or *last measured N days ago*, never as free space. "qBittorrent is in the tunnel" is a
      last-known assertion and needs a timestamp — a kill switch last verified before the last reboot
      is not a verified kill switch. We have caught this bug's sibling twice already (an empty
      `systemctl list-dependencies` reading as health; `sonarr/meta.nix` probing `/ping` rather than
      trusting `is-active`). It is a data-model choice — `Option<T>` + timestamp + reason, not a bare
      number — so it is nearly free now and expensive once the health view exists.
- [ ] **24. We disclose nothing about what leaves the machine.** Self-hosters self-host for exactly
      this reason. The table writes itself: Cloudflare API, Let's Encrypt, plex.tv, the update check,
      and each app's own egress — marked by whether the call is ferrum's or the app's. State plainly
      whether there is any telemetry. Highest trust-per-byte document the project could publish.
- [ ] **25. We leak the stack into Certificate Transparency and warn nobody.** `acme.nix` issues
      "one `security.acme.certs` entry per public vhost", so `sonarr.`, `radarr.`, `qbittorrent.`
      land in public, permanently searchable CT logs advertising exactly what runs at that domain.
      Because we use DNS-01 rather than HTTP-01 we have an option others do not: a single wildcard
      `*.<baseDomain>` puts only the base domain in CT. **Right now this is a design decision made by
      accident.** Make it on purpose and document it either way.
- [ ] **26b. We pool with mergerfs and have NO parity story.** Grep `modules/`, `crates/` and the
      design docs for SnapRAID or parity: nothing. PMS's mergerfs page is blunt — mergerfs "has
      nothing whatsoever to do with parity. If a drive fails, the data on that drive is gone" — and
      the entire reason it pairs mergerfs with SnapRAID is that the pool provides no fault tolerance
      at all. We ship the convenience half and omit the survival half, and the guide every
      prospective user has already read says so. `services.snapraid` is a first-class NixOS module,
      so this is cheaper on our substrate than anywhere else. **If we add it:** exclude the btrfs
      snapshot subvolumes or parity cost explodes, and ship "parity is not backup" with it.
- [ ] **26c. `epmfs` deserves a decision, not a default.** PMS names our policy specifically as one
      that "can surprise users by concentrating data on single drives", and points at `pfrd` as
      upstream's current default. `options.nix:144` offers only `epmfs | mfs` — `pfrd` is not even
      expressible. **This is not naivety:** `storage.nix` seeds the tree on every branch precisely to
      give `epmfs` more than one candidate, because we were bitten by that failure already. The
      question is whether a hands-off installer should depend on a correct seeding step to avoid a
      pathological layout when a policy exists that needs no layout at all. A reader who knows PMS
      will notice the disagreement; have an answer better than silence.
- [ ] **26d. No SMART monitoring, no drive temps, no burn-in, no batch-failure warning.** All four
      are hard-won PMS knowledge a guide can only *tell* you and ferrum can *guarantee*. The burn-in
      one is the differentiator: `badblocks` plus a SMART long test either side takes about a week
      for an 8 TB disk, **nobody does it by hand**, and PMS reports catching a drive that died after
      19 hours. A "prepare new disk" flow that refuses to pool an un-burned-in disk without an
      explicit override is a feature no competitor has.
- [ ] **26e. TRaSH Guides deserves its own analysis.** Arguably more load-bearing for our app layer
      than PMS — it is the \*arr configuration bible and we ship \*arr apps with defaults.
- [ ] **26. The SSO lockout path is undocumented.** The dashboard is behind Authelia as of F5. The
      console password and the SSH tunnel both exist, and `POST /api/sso` correctly 404s on
      tunnel-only hosts — but none of it is written down, and it is the highest-severity
      undocumented failure mode in the product. Better still, and uniquely available to a
      declarative system: **`preflight` should hard-fail an apply whose resulting generation leaves
      no reachable authentication path**, with rollback still available and nothing yet changed.

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
