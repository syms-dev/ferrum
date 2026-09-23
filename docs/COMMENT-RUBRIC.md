# Comment rubric — the standard, agreed on a sample before any sweep

**Status:** proposed, awaiting owner sign-off. Nothing has been rewritten.

Road-to-public item 12 asks for the rubric and real before-and-afters *before* touching the
codebase, because items 13 and 16 would otherwise apply a taste judgement to 10,943 comment lines
in one pass.

## What is actually there

| Measure | Value |
|---|---|
| Rust source lines | 36,776 |
| Comment lines | 10,943 (**30%**) |
| Comment blocks of 3+ lines | 1,119 |
| — of 15+ lines | 149 |
| — of 25+ lines | 51 |
| Longest single block | 70 lines (`crates/ferrum-install/src/inventory.rs:197`) |
| `crates/ferrumd/src/auth.rs` | 566 of 1,501 lines (**38%**) |

## The finding that should shape the sweep

**These comments are overwhelmingly reasoning, not narration, and the risk is asymmetric.**

The naive read of "30% comments" is bloat. Sampling says otherwise. Even the comments that open
with the classic narration tells — `First`, `Then`, `Now`, `We` — carry a *why* immediately after:

> `// First, not last. Every line below it describes a write that will...`
> — `crates/ferrum-apply/src/dns_reconcile.rs:706`

And the longest block in the codebase is a record of a real incident: an earlier version refused
any inventory field that was not byte-identical to what the cleaner produced, which retroactively
invalidated every inventory file written before a whitespace change — landing **past the wipe**,
where it was the only path and its own advice could not work.

Against that, four separate findings in the R13 run were comments that had quietly become
**false** — including one asserting ferrumd was loopback-only that survived three review passes
and was caught only by salvaging a branch that was about to be deleted.

So the two failure modes are not symmetric:

- **Deleting a load-bearing comment** destroys a decision record that cost an incident to learn,
  silently, with no test to catch it.
- **Leaving a verbose comment** costs a reader some seconds.

The sweep should be **narrow and evidence-led**, not a style pass.

## The rubric

Apply per comment, in order. Stop at the first rule that matches.

### KEEP, verbatim — do not touch
1. It records **why** a decision was made, especially where the obvious alternative was tried and
   failed. (`inventory.rs:197`, `auth.rs`'s `coarse_axis_saturated`.)
2. It names a **defect ID, incident or date** — it is an audit trail.
3. It explains a **non-obvious constraint**: a browser rule, a nixpkgs behaviour, a mergerfs
   policy, an ordering requirement.
4. It is a **`# Arguments` / `# Returns` / `# Errors`** docstring on a public signature. The
   project's own documentation rule requires these; a de-verbose sweep must not quietly repeal it.
5. It states what a test or check is **for**, or warns that something is load-bearing. Several
   checks here pass trivially if a guard is trimmed as redundant.

### TRIM — keep the content, cut the restatement
6. The same point made twice in one block, or a summary sentence restating the paragraph above it.
7. Scaffolding phrases that add no information: *"It is worth noting that"*, *"Importantly"*,
   *"As mentioned above"*.
8. A block that opens with two sentences of preamble before reaching its point. Lead with the
   point.

### DELETE
9. It narrates **what the next line does** and nothing more (`// increment the counter`).
10. It describes code that no longer exists.
11. **It is false.** This is the highest-value class in the whole sweep, and the only one with a
    known track record here. Falsity is a *correctness* fix, not a style one, and should be pulled
    out of the sweep and done first.

## Proposed sequencing — which changes the risk more than the rubric does

1. **Falsity pass first, separately.** Rule 11 only. Every change is verifiable against code, so
   it needs no taste judgement and carries no risk of losing reasoning. Where a claim is
   load-bearing, pin it with a guard — the precedent already exists twice
   (`no_comment_still_claims_the_daemon_has_no_vhost`, `no_state_still_claims_the_dashboard_has_not_shipped`).
2. **Then rules 9 and 10**, which are mechanical.
3. **Then rules 6–8**, the only genuinely subjective part, file by file rather than repo-wide, so
   a bad judgement is a small diff.

Rules 1–5 are never applied as a sweep at all.

## Sample — one of each, real, unedited

### KEEP (rule 1) — `crates/ferrumd/src/auth.rs`, `coarse_axis_saturated`

> `succeeded = 0` is load-bearing and was missing (SEC3-H01's second fault). Successes are recorded
> in this table too, so without the filter the lockout asked "when did anything last happen here?"
> and ordinary working traffic kept an already-expired lockout alive indefinitely. […] A cooldown
> must be cleared by the passage of time, never refreshed by the traffic it is not supposed to be
> punishing.

**Verdict: keep verbatim.** Twelve lines that stop the next person reintroducing an outage.
The closing sentence reads like a flourish and is not — it is the rule that makes the fix
generalise.

### TRIM (rule 8) — `crates/ferrum-install/src/inventory.rs:197`

The 70-line block. Its *content* is all rule-1 material and stays. What can go is the ordering: it
opens on `clean`'s behaviour, then a `# Arguments` stanza, and only reaches **"Why two different
treatments, and not refusal for everything"** — the actual decision — a third of the way down.

**Proposed: move the "why" to the top, leave every fact intact.** Expected saving: 0 lines of
content, roughly 8 lines of re-reading for whoever hits it next.

### DELETE (rule 11) — the class that has already bitten, four times

> `// ferrumd is loopback-only today (nginx builds vhosts solely from exposedApps, and
> ferrum.daemon.subdomain is declared but unused)`

Every clause false since R13. Already fixed and now guarded. **This is what the sweep is for.**

## What I need from you

1. Does the rubric match your intent, especially **KEEP rule 4** (docstrings are protected) and the
   proposal that **falsity is a separate correctness pass, done first**?
2. Is the `inventory.rs` TRIM the right aggressiveness — reorder and keep every fact, rather than
   condense?
3. Rules 6–8 are the subjective ones. File-by-file, or are you happy for them to run repo-wide once
   the rubric is agreed?
