# A requirement born from "reported success while it did not work" must end in a mechanical check

**Applies when:** writing or reviewing any ferrum spec/requirement whose originating incident was
the system reporting success against an outcome nobody verified.

Found by the Phase 1.7 R1 blind planning panel (2026-09-21), which noticed an inconsistency
*inside one document*. Three of that spec's requirements terminate in a mechanical proof:

- **R5/A1** — post-install verification checks each certificate's **issuer**, so a self-signed
  fallback is a reported failure rather than a pass.
- **R8/A6** — verification asserts hardlinking actually works between the download and media
  directories: create, link, **compare inode**, remove.
- **R2/A2** — the staged copy is **verified complete before anything is erased**, not after.

**R1 was the fourth, and had none.** It is the requirement that exists precisely because
`auth.thesyms.ca` never resolved while the installer printed success — and as drafted it created
records, reported success, and re-established nothing. A7 required a dry-run *before* the change;
no criterion required a check *after* it.

## The rule

Any requirement whose originating incident was "reported success while the thing did not work"
must terminate in a **captured, mechanical assertion of the thing working** — not in the mechanism
that is supposed to make it work. Building the artifact is not running it; running it without a
target is not using it.

## The trap specific to checking your own work

The check must not be answerable by the thing that made the change. For DNS specifically the panel
required querying the zone's **authoritative nameservers**, not the local resolver — a recursive
resolver can hold a negative-cache entry for up to the SOA minimum, so "it doesn't resolve yet"
and "it will never resolve" look identical from the host that just wrote the record. The general
form: pick a vantage point that could have disagreed.

## The second-order version

A mitigation whose own failure is unobservable has not mitigated anything. R1's optional DDNS
updater was justified by "the operator cannot observe the failure it prevents" — and a timer that
has been erroring for six weeks presents identically to one that is working. Where a background
corrector is introduced, the **age of the last successful check** has to be a first-class value
somewhere the operator already looks. The useful signal is rarely "this is wrong"; it is
"nothing has confirmed this in N days."

---

## Corollary, learned the hard way on the same feature: test the caller, not the builder

Three independent passes over Phase 1.7 R1 — a tester, a senior tester, and a defect-loop cycle —
each asserted on a rich in-memory `ReconcileReport`, and **none followed it to the production caller
that discards it.** `reconcile_for_apply` returned only `failure_summary()`, so every
`SkipForeign` / `SkipForeignBeside` / `SkipUnmodelledType` disclosure was computed, tested, and then
thrown away on the apply path. The function that decides what the operator actually sees had **zero
tests**, while the function that builds the data it drops had dozens.

**Generalised: when a module returns a structured report, test the caller that renders it, not only
the function that builds it. A variant no caller prints is a variant that does not exist.**

The tell is cheap to check: `grep` the function that produces the report and the function that
renders it, and compare test counts. A large gap between them is the shape of this bug.

## And the second-order version of the original rule

The same feature nearly shipped a verifier that could not see its own failure mode. R1 exists
because a name did not resolve while the installer reported success — and as built, every check
queried the zone's **authoritative** nameservers directly (deliberately, to dodge a negative cache)
or connected to a **literal IP** with a `Host:` header. Nothing ever resolved a published hostname
through the public chain. So a zone added to Cloudflare whose registrar nameservers were never
switched produced: a passing credential check, successful record creation, a correct authoritative
answer, a 301 from the reachability probe, a green report — and NXDOMAIN in the operator's browser.

**When you add a check because something reported success it had not verified, ask what the check
itself cannot see.** A verifier that shares a blind spot with the thing it verifies is worse than
none, because it converts an unknown into a false assurance.


---

## The recurring class, named after it appeared three times in one feature

**A fact computed correctly and discarded before the surface the operator reads.**

Three instances in Phase 1.7 R1 alone:
1. `reconcile_for_apply` returned only `failure_summary()`, so every foreign-record disclosure was
   built, tested, and dropped on the apply path.
2. `gate()` computed the "Cloudflare is not answering for this domain yet" warning, printed it at
   the dry run, and returned `Result<Adoption>` — no path out — so the **final** screen said
   "installed" over a list of URLs that resolve nowhere.
3. (The original.) Records were created and success reported with nothing checking resolution.

Tests asserting on the in-memory structure (`ReconcileReport`, `DryRun`) cannot see any of these.
Only a test asserting the **rendered final output** can.

**The standing check, cheap to apply:** for every operator-visible fact, name the test that asserts
it appears in the **last** thing printed, not the first. A dry run is far up the scrollback by the
time the thing it warned about happens; the closing report is what is still on screen — and this
codebase says so about itself at `crates/ferrum-install/src/main.rs:1005-1011`, which is precisely
the invariant instance 2 violated.

**The audit is bounded, so do it rather than hunting.** Enumerate the operator-facing facts a
feature produces, then check each one reaches the final surface. In R1 there were four; three did
and one did not. That is a ten-minute audit with a definite end, not an open-ended review — and it
is a much better use of a pass than a fourth adversarial read.
