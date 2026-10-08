# Security review — R14 update discovery, read-only preview, Updates UI

Stage 5.4, cycle 1. Reviewed at integration commit `233fd5b` (branch `feat/r14-integration-2`,
base `26b14fd`). Persisted by the orchestrator on the reviewer's behalf; the reviewer runs read-only.

**Verdict: NOT CLEAR** — Critical 0 · High 0 · **Medium 2** · Low 3 · Cosmetic 0.
Security Clear requires zero Critical/High/Medium.
Separately blocking: the **owasp-reviewer lane did not return**, so its area is not counted as passed.

## Findings

| ID | Sev | File:line | Attack / exposure | Remediation |
|----|-----|-----------|-------------------|-------------|
| **M1** | Medium | `crates/ferrumd/src/jobs.rs:253`; `modules/core/daemon.nix:144-190`; `ui/app.js:841-858` | **Unbounded concurrent root-privileged evaluation.** `let takes_interlock = !matches!(req, JobRequest::CheckUpdate);` exempts the check from the single-job interlock, and there is no second cap anywhere: `grep 'RuntimeMaxSec\|TimeoutStartSec\|CPUQuota\|MemoryMax\|MemoryHigh\|TasksMax' modules/core/daemon.nix` returns **no matches**, so the `ferrum-apply@` template is uncapped and untimed; `POST /api/jobs` has no rate limit; and the UI's check button sets no in-flight disable, so its `onclick` fires a fresh `ferrum-apply@<uuid>.service` per click. Each instance is ~2N+2 full module-system evaluations plus network calls. `jobs.rs`' own comment concedes the flag "has no timeout and no cancel… can take minutes". A double-clicking operator — no attacker needed — can OOM the appliance, and the resulting inability to roll back is precisely the failure the exemption was created to prevent. | Bound the blast radius without touching the closed DA-7 decision: disable the UI button while a check is attached; consider a narrow second flag admitting one `check_update` at a time, distinct from the apply/rollback interlock so rollback stays unblocked. |
| **M2** | Medium | `crates/ferrum-apply/src/update_candidate.rs:180-196` (`git+` branch), consumed at `:274`, published via `update_check.rs:724`, `:748-752` | **Operator credentials propagated out of root-only config.** `decompose`'s `git+` branch passes the bare URL through verbatim into `git_url`, `url` and `base_url` with **no userinfo stripping**. For `ferrum.url = "git+https://user:TOKEN@host/repo"` the token then (a) becomes a literal `git ls-remote` argv element — `/proc/<pid>/cmdline` is world-readable on default Linux — and (b) is copied into `CandidateReport.input_url` and into the `check_failed` error text, reaching the report JSON, the progress summary line, and the UI. A credential whose confidentiality rested on `flake.nix` being root-only is republished to a lower trust level. | Strip `user[:pass]@` before the value reaches `input_url`, `error`, or the report; keep the authenticated form only in the argv handed to `git`, or use a credential helper. |
| L1 | Low | `update_candidate.rs:180-196`, `:274` | **git argument injection, root→root only.** `ls_remote_argv` = `["ls-remote", git_url, reference]`; in the `git+` branch both slots are unvalidated operator text, so `ferrum.url = "git+--upload-pack=<cmd>"` would make git execute `<cmd>` as root. **Not a boundary crossing** — the only writer of `/etc/ferrum/flake.nix` is root, and ferrumd provably cannot reach it (`modules/core/daemon.nix:268-280`: `ProtectSystem = "strict"`, `ReadWritePaths` lists `settings.json` and `secrets` but **not** `flake.nix`). Defence-in-depth. | Reject a `git_url`/`reference` beginning with `-`, or pass `--` before the repository argument — the discipline `is_safe_app_id` already applies for the same stated reason. |
| L2 | Low | `crates/ferrumd/src/updates.rs:119,124,186,193,205,227` | 500 bodies disclose real filesystem paths. Reachable only behind `require_session`; on a single-tenant appliance that principal is the box owner. Consistent with the existing `catalog.rs`/`generations.rs` precedent. | None required. Note only. |
| L3 | Low | `crates/ferrumd/src/updates.rs:284-287` | `Uuid::parse_str` also accepts braced `{…}` and `urn:uuid:…` spellings, and the **raw** string — not a canonical re-serialization — is interpolated into the filename. **No traversal**: the accepted alphabet contains no `/` and no `..`, so the guard holds. The effect is only that those spellings 404 instead of resolving. | Re-serialize the parsed `Uuid` before building the path. Tidiness, not a security fix. |

## Project auto-Critical checks
- **Tenant isolation** — N/A, reasoned rather than waved: ferrum is a single-tenant appliance with
  one operator principal and no per-user data separation; `/api/updates` serves host-wide state every
  authenticated principal is entitled to. No scoped query exists to be unscoped. **PASS**
- **No blocking I/O on an async path** — **PASS**. `get_updates` offloads its directory walk and file
  read via `crate::run_blocking` (`updates.rs:328-336`), matching `generations.rs:241`.
- **No hardcoded secrets** — **PASS**. Zero matches across the diff, all four new files in full,
  branch history, CI, and UI storage. `.env` untracked; the workflow has no `secrets:`/`${{ }}`.
- **No secrets/PII in logs or artifacts** — **FAIL**, per M2.
- **Error suppression / broken build** — **PASS**.

## Judgements requested

**Closed-enum invariant: HOLDS.** `CheckUpdate` is a genuine zero-field unit variant in both mirrors
(`request.rs:24`, `jobs.rs:40`). The enum is `#[serde(tag = "kind", rename_all = "snake_case")]`; an
internally-tagged **unit** variant has no field map to smuggle into, and `request_body` emits exactly
`{"kind":"check_update"}` (`jobs.rs:125`).

**Command injection into root argv: none found.** Exactly **one** process spawn exists in all new
apply code (`update_check.rs:78`, `Command::new(program).args(args)`) — an args array, never a shell.
Every argv builder was enumerated: `eval_argv`, `candidate_eval_argv`, `ls_remote_argv`,
`metadata_argv`. App ids are gated by `is_safe_app_id` (`update_check.rs:342-349`) — lowercase
alphanumeric plus hyphen, leading letter — which cannot escape a Nix attribute path (no `.`, quote,
space, `$` or `{`), and its test asserts both halves, rejecting `"a" or builtins`, `sonarr.package`
and `../x`. The candidate `rev` reaching `--override-input` is filtered by `is_full_rev`
(`update_candidate.rs:299`) to 40 hex characters. `flake_dir`/`config_attr` derive from
`$FERRUM_FLAKE_REF`, set by the root-owned unit and unreachable by ferrumd. The one residual is L1,
and it is root→root.

**Read-only guarantee: complete.** `--no-write-lock-file` is present at every eval site —
`eval_argv` (`update_check.rs:373-379`) and `candidate_eval_argv` (`update_deltas.rs:41-47`);
`metadata_argv` carries it too and targets the remote flakeref, never `/etc/ferrum`. The `0105cfc`
fix holds, and `read_only_defects` (`update_check.rs:809-835`) is a real check that can fail.

**Path traversal: guarded correctly.** `Uuid::parse_str` runs at `updates.rs:284`, strictly before
the `dir.join` at `:287` and the read at `:288`.

**Auth: correct.** `/api/updates` is on the `protected` router (`main.rs:548`) under `require_session`
(`main.rs:557`). The unauthenticated outer router carries only login/logout and the static fallback,
and `static_files.rs` refuses to fall back for any `/api/` path. GET needs no CSRF and the handler is
genuinely side-effect-free; the only job-start path is `POST /api/jobs`, already CSRF-gated.

**What `nix eval` against an attacker-controlled flake can do — the residual, stated plainly.**
`nix eval` is **not** a safe sandbox. Evaluating an attacker-controlled flake can trigger
import-from-derivation (which *builds* a derivation during evaluation and therefore runs arbitrary
build code); call `builtins.fetchurl`/`fetchGit`/`fetchTarball` to reach arbitrary network endpoints;
read files the evaluating user can read via `builtins.readFile` and path literals; and exhaust
CPU/memory. Here that happens **as root**. `--no-write-lock-file` and the absence of `--impure`
constrain writes and ambient impurity — they do **not** make evaluation of hostile Nix safe. The
read-only *check* path is therefore not meaningfully less dangerous than `apply` with respect to
malicious upstream code; what stands between the two is DA-1's accepted trust in the release ref.
That closed decision was not re-litigated. **The compensating control does exist in shipped code:**
the UI renders `currentRev` and the candidate rev as text before anything is applied
(`ui/app.js:749-752`). This belongs in the record as an accepted residual with an owner and a
revisit trigger, not left implicit.

**DoS — a finding (M1), not a story.** The trigger is an ordinary UI double-click rather than a
crafted attack, and the failure mode defeats the exact guarantee the interlock exemption was
introduced to protect.

## Scanner coverage
- **secret-scanner** — full diff, all four new files in full, branch history, CI, UI storage. Zero
  hardcoded secrets. Raised M2 as High; **adjudicated down to Medium** on evidence it had not
  checked: it argued "any local user can read the 0644 report", but the containing directory is
  `d /var/lib/ferrum/jobs 0750 ferrum ferrum` (`modules/core/daemon.nix:336`), so traversal is
  blocked and the file is not world-readable — the 0644 mode is exactly what lets unprivileged
  ferrumd read a root-written file, as intended. The surviving vector is the `/proc` argv exposure,
  plus the precondition that ferrum itself never generates a credentialed URL (only `github:…` —
  `ferrum-install/src/render.rs:384`, `examples/hosts/template/flake.nix:21`). Real, contained,
  Medium.
- **dependency-scanner** — verified rather than assumed: `git diff 26b14fd..HEAD -- crates/Cargo.lock`
  is **empty**; `ui/index.html` has one local `./app.js` and no remote script. `cargo audit` fetched
  the live RustSec DB (1,269 advisories), scanned 278 crates, exit 0, **zero** vulnerabilities,
  unmaintained or yanked crates. A genuine network-backed scan, not a degraded no-op.
- **policy-validator** — 10 items, 8 PASS with file:line, 1 Medium (M1), 1 Low note (L2). Session
  cookie `__Host-ferrumd_session` unchanged and correct (HttpOnly, SameSite=Strict, Secure, Path=/).
  No CORS layer at all, with a regression test asserting zero `access-control-*` on every API route
  including the new one. Security headers set at nginx, untouched.
- **owasp-reviewer — DID NOT RETURN.** It ran far longer than the other three and never handed back,
  and did not answer an explicit wrap-up request. **Its area is not counted as passed.** The
  coordinator closed its highest-value questions itself with cited evidence — the forward taint trace
  to every root argv, `is_safe_app_id` sufficiency, the closed-enum invariant, `--no-write-lock-file`
  completeness, the UUID guard, router gating, the async-offload check, and an XSS sweep (zero
  `innerHTML`/`insertAdjacentHTML`/`href` anywhere in the UI; `el()` uses `textContent`/
  `createTextNode` exclusively, so remote-influenced evaluator stderr and revisions render inertly).
  What remains genuinely unverified is a systematic second pass over A02/A06/A10 and any injection
  path not thought to trace. **An open coverage gap, not a clean result.**
- **pentest-scanner — SKIPPED (non-blocking).** No running host and no authorized non-production
  target. The tooling probe also found strix/shannon/zap/pentesterflow absent; recorded as
  informational, not the blocking reason.

## Defect-loop routing
- **M1** → UI lane (disable the button while a check is attached). A daemon-side bound was
  deliberately deferred to its own story because its release path shares the interlock-identity
  defect found at the merge join. Re-run **policy-validator** only.
- **M2, L1** → ferrum-apply lane, same function, same few lines. Re-run **secret-scanner** only.
- **L2, L3** — do not block.
- **owasp-reviewer** must be re-dispatched with a narrower brief (the single prompt covering nine
  areas appears to have exhausted its budget), or its non-completion recorded as an explicit accepted
  coverage gap with an owner.

Max 2 security cycles; this is cycle 1.

---

# Addendum — narrowed OWASP re-dispatch (A02 / A10 / A09)

The first `owasp-reviewer` dispatch never returned; its brief covered nine areas at once. It was
re-dispatched with a three-area brief and returned bounded.

**Verdict: FAIL** — Critical 0 · High 0 · **Medium 1** · Low 5 · Cosmetic 1.

| # | file:line | Sev | Exposure | Remediation |
|---|-----------|-----|----------|-------------|
| **A02-1** | `update_candidate.rs:528` | **Medium** | "Newer" rests **solely** on `candidate_last_modified > locked.last_modified`. Both are git **commit metadata** timestamps, freely chosen by the commit author, and **no ancestry is ever established**. (a) An **older** revision carrying a forged future date presents as `UpdateAvailable`, and the operator's only control is a 40-hex string that cannot distinguish a downgrade from an upgrade — so DA-1's compensating control does not compensate for this. (b) One commit with a far-future `lastModified` becomes `locked.last_modified` at install, after which **every genuine later release reports `NotNewer` — a silent "nothing to do", forever**, reachable by ordinary clock skew. That is exactly the class R1 forbids being silent. | Do not rest ordering on `lastModified` alone. Establish ancestry, or surface both timestamps and both revisions and warn loudly when the candidate cannot be shown to be a descendant / when `locked.last_modified` is in the future. Minimum: a candidate that cannot be shown to be newer is a **distinct, loud state**, not `UpdateAvailable` and not a silent `NotNewer`. |
| A02-2 | `update_candidate.rs:176-195` | Low | `git+` accepts **any** scheme — `git+http://`, `git+file://`, `git+ssh://` all pass into `git_url`/`base_url` with no allowlist. With no signature verification, **transport integrity is the entire trust chain**, so `git+http://` lets a network attacker choose both the revision and its metadata. Precondition is an operator-written root-owned file, so opt-in misconfiguration. | Allowlist `https`/`ssh`; refuse or loudly warn on plaintext `http`. |
| A02-3 | `update_candidate.rs:316` | Low | `parse_ls_remote` falls through to `Ok(rows[0].0)` when none of `refs/tags/X^{}`, `refs/heads/X`, `refs/tags/X`, `X` matched. `git ls-remote <url> main` matches any ref whose tail is `main` (e.g. `refs/heads/feature/main`), so **a ref the operator never named can decide the root-fetched revision**. | Fail closed: return the "ref does not exist" error instead of the first row. |
| A02-4 | `update_candidate.rs:61-67` | Low | `flakeref_for_rev` rebuilds `git+{bare}?rev={rev}` from `bare`, split at the first `?` (`:177`), so **every original query parameter is dropped** — notably `dir=`. For an operator who pinned `git+https://h/r?dir=sub`, the thing evaluated via `--override-input` is **not the thing they pinned**. | Preserve non-`rev`/`ref` params, or reject URLs carrying params the rebuild cannot reproduce. |
| A02-5 | `update_deltas.rs:87` | Low | The candidate's own Nix is evaluated **as root during the check**, before the operator reviews anything. Pure eval blocks unhashed fetches, but import-from-derivation and hashed fixed-output fetches still run. The header's "read-only / nothing is written anywhere" and `ReadOnlyGuard` cover only `flake.nix` and `flake.lock`; store writes and eval-time resource exhaustion are outside both. | No code change demanded; correct the overstated claim. Consider `--option allow-import-from-derivation false` plus an eval timeout on the candidate side. |
| A09-1 | `main.rs:530`, `:537`; error built at `update_candidate.rs:481` | Low — **a third sink for the open credential Medium** | The **entire report JSON is `println!`'d to stdout**, and ferrum-apply runs under systemd, so `candidate.inputUrl` lands verbatim **in the journal**. The `could not reach {git_url}: …` text also reaches the job's `.jsonl` progress file and stderr. The open Medium cited only the report file and `/proc` argv — **a redaction applied at those two sinks would still leak here.** | Redact at the single point where the value is produced, so stdout, progress detail, report and journal are covered by construction. |
| A09-2 | `update_check.rs:689` | Cosmetic | Doc comment says the report is written "world-readable"; the directory is `0750 ferrum ferrum`, so 0644 is ferrum-group-only. The mode is correct and intentional; the comment overstates. | Reword. |

**A02 — the chain has no substitution point.** `parse_ls_remote` admits only 40-hex
(`is_full_rev:71`); the same `candidate_rev` string feeds the metadata probe, the `UpdateAvailable`
state, `FerrumReport.candidate_rev` and the `--override-input` flakeref — built once by
`flakeref_for_rev` and never re-derived. `parse_metadata_last_modified` cross-checks Nix's reported
`revision`/`locked.rev` against the expected rev and fails closed on mismatch, though only
`if let Some(reported)`: an answer carrying neither field is accepted at face value. `github:` is
hardcoded to `https://github.com/...` and the owner/repo split cannot move the authority. **The gap
is not substitution — it is ordering (A02-1) and transport (A02-2).** The no-signature decision was
not re-litigated.

**A10 — PASS with notes.** Exactly four spawn sites reach the network, all `runner.run` with an args
array: `git ls-remote`, `nix flake metadata` on the candidate flakeref, `nix eval` of the local
`/etc/ferrum` flake (lock-pinned inputs only under `--no-write-lock-file`), and
`nix eval --override-input` on the candidate. Every destination derives from `/etc/ferrum/flake.nix`
alone. **The API caller supplies nothing** — `JobRequest::CheckUpdate` is a zero-field variant
serialized to the literal `{"kind":"check_update"}`, and ferrumd makes no outbound call at all. So
this is root→root: an unprivileged or API-level actor cannot redirect the fetch, which is why the
`git+file://`/`git+ssh://` latitude is Low rather than SSRF. Residual, not dismissed: redirects are
followed by git and Nix with no destination filter, and a candidate flake can perform hashed
fixed-output fetches at eval time — both as root, both constrained only by the operator's own pin.

**A09 — PASS with one Low.** `check_update` goes through `create_job_in` and is audited identically
to every other kind (`jobs.rs:188`, `audit::record("job-dispatch", …, detail="kind=check_update …")`)
with the escaping and `client=`/`peer=`/`client_source=` discipline intact. The resolved revision and
the evaluator's real stderr both survive to the operator via `summary_line` and the `error` fields.
Nothing sensitive is newly logged except the `inputUrl` sinks in A09-1.

**Not reached, in scope:** nothing — all three areas were covered. **Outside the brief and therefore
untouched:** A01, A03, A04, A05, A06, A07, A08 (the first three were closed by the coordinator with
cited evidence in the main review above), the UI beyond confirming no outbound call originates
there, and any dynamic verification.
