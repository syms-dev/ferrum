# Phase 1.8 — the visual installer

**Status:** draft for owner review and design. No implementation until approved.

## Why this exists

The owner ran the Phase 1.6a installer end to end and said:

> genuinely I thought that this would be like a visual step-through installer.... I hope that's
> what it ends up being

They are right, and the mismatch was never surfaced during planning. The 1.6a spec settled on
"Docker image, terminal interaction" as a delivery decision and nobody checked it against the
product's own stated identity. The design doc says *"Setup and maintenance must not require
hand-editing config files. The web UI is the point, not a nicety."* A terminal wizard is closer to
hand-editing than to the product being described.

**This is not a rewrite.** The hard parts of `ferrum-install` are the parts that took fifteen
defects and a real install to get right: the disk inventory and firmware truth table, the
serial-typed confirmation gate, the phase machine that makes a resume safe, preflight evaluation,
post-install verification, and the guard against handing an unreachable target to an unbounded
retry. All of that is a library with a CLI attached. **What changes is the interaction layer.**

It also makes several outstanding 1.7 requirements easier as screens than as terminal plumbing:
credentials that survive a failed run (R4), certificate status that distinguishes real from
self-signed (R5), and per-disk fullness in a pool (R3 A4).

---

## R1 — it is a browser, and getting there is one command

**Acceptance criteria.**
- A1. `docker run -p <port>:<port> ...` prints one URL. Opening it is the whole of "starting the
  installer".
- A2. The page is served by the installer itself. No external network, no CDN, no account — the
  operator may be installing onto a machine with no internet path to anything but the target.
- A3. The terminal remains a supported path, not a deprecated one. CI drives it, `tests/stage2/*`
  drives it, and an operator over SSH with no port forward still needs it. **The browser is a
  second front-end over one library, not a replacement.**
- A4. Closing the tab does not abort an install. Reopening the URL rejoins the run in progress —
  the phase machine already makes this true underneath.

## R2 — it must not be an attack surface

The installer holds the operator's SSH key, takes a Cloudflare token, and erases disks as root. A
casually-exposed local web server that does those things is worse than the terminal it replaces.

**Acceptance criteria.**
- A1. Bound to loopback by default. Publishing it on a LAN interface is an explicit flag with a
  stated reason, never the default.
- A2. The printed URL carries a single-use, high-entropy token; requests without it are refused.
  This is what stops another process on the same machine driving an install.
- A3. Secrets are write-only across the boundary: the Cloudflare token and the Plex claim token go
  in and are never rendered back, not even masked, and never appear in a GET response or a log.
- A4. No destructive action is reachable by GET, and none happens without the explicit
  confirmation in R4.

## R3 — the flow mirrors the phase machine, not a wizard's idea of steps

The install already has phases with real meaning: `Generated`, `PreflightPassed`, `Installing`,
`HardwareConfigured`, `Stage2Applied`, `Verified`. The UI should show those, because they are what
a resume resumes to.

**Screens, in order.**

1. **Target** — where to install, and the credential to get there. Fails here are cheap and
   common: unreachable host, root refused, wrong architecture, no serials. Each gets its own
   explanation rather than a generic error.
2. **Inventory** — every disk with size, model, serial, by-id path, existing filesystems and what
   is mounted. This is the screen the whole product's safety rests on, and it is where a table in
   a terminal is weakest: **fullness, existing data and "this is the one you are about to erase"
   are visual facts**.
3. **Plan** — hostname, domain, apps, SSO. Shows consequences as they are chosen: picking a domain
   turns SSO on and says why; declining it names every app about to be published unauthenticated.
4. **Confirm** — the destructive gate. See R4.
5. **Install** — live progress. See R5.
6. **Done** — see R6.

- A1. The operator can go back to any earlier screen before the confirmation, and cannot after it.
- A2. Every screen states what has and has not happened to the target yet. "Nothing has been
  written" is load-bearing information right up until it stops being true.

## R4 — the destructive step is unmistakable, and typed

**Acceptance criteria.**
- A1. Erasure requires typing the disk's **serial**, as the terminal does. Not a checkbox, not a
  held button. The serial is the one thing that cannot be got right by reflex, and it is already
  proven: the terminal gate is what stopped a wrong-disk install during testing.
- A2. The screen names, unambiguously and without scrolling: the disk to be erased, its size and
  serial, and **every disk that will be left alone**. The second list matters as much as the
  first — an operator with 7TB of media needs to see it is not in scope.
- A3. Existing data on the target disk is stated. "This disk currently holds a ferrum install" or
  "this disk has an ext4 filesystem mounted at /mnt/media" changes the decision.
- A4. After this point the UI says plainly that the disk is gone and a resume will not repartition.

## R5 — progress is visible, because silence was the worst failure mode

Two CI runs and one real install sat silent for hours. The terminal showed one static line while
`nixos-anywhere` looped forever on `ssh-copy-id`; nothing distinguished "building" from "hung".

**Acceptance criteria.**
- A1. The current phase is always visible, with elapsed time in it.
- A2. Output streams. A long build shows its build log, not a spinner.
- A3. **Liveness is distinguished from progress.** A step that is genuinely working but quiet says
  so and shows when it was last alive. This is the specific thing that would have turned a
  three-hour mystery into a thirty-second diagnosis.
- A4. A step that exceeds a plausible window says so and offers the diagnostic, rather than
  waiting for a timeout the operator cannot see.
- A5. The build runs on the target (`--build-on remote`, load-bearing for an aarch64 operator
  installing an x86_64 host), so its progress comes over SSH. The UI must not imply local work.

## R6 — it ends with a working system and the keys to it

**Acceptance criteria.**
- A1. Every generated credential is shown: the SSO admin login and the ferrum UI login, with where
  they live on the host. On the first real install the run failed before its report and the
  operator was locked out of a working Authelia by a password they had no way to know.
- A2. Credentials are shown **as soon as they exist**, not only at the end.
- A3. Each app is listed with its URL and whether it answered. "Installed" and "reachable on its
  own hostname with a real certificate" are different claims and the UI makes the distinction.
- A4. A self-signed fallback certificate is reported as a problem, never as success.
- A5. Anything still needing a human — a Plex claim token, a DNS record the operator must add — is
  named here with the exact action, per app. This is the list the product exists to keep empty, so
  when it is not empty it must be explicit rather than inferred.

## R7 — failure is a screen, not a stack trace

**Acceptance criteria.**
- A1. Every refusal the CLI already has keeps its explanation and its recovery: no serials, wrong
  architecture, unreachable target, kexec'd target on a resume, placeholder hardware config.
- A2. Recovery is an action where it can be. "Re-run with `--fresh`" is a button that does that,
  not a sentence about a flag.
- A3. Where a recovery genuinely needs the operator elsewhere (power-cycle the box; fetch a new
  claim token), it says so with the reason, and waits rather than failing.
- A4. The underlying command and its real output are always one click away. Every defect found
  during 1.6a was diagnosed from raw output, and hiding it would have made each of them harder.

---

## Out of scope

- Managing an existing host. This is the installer; the running system has the ferrum UI.
- Replacing the CLI (R1 A3).
- Any design decision that belongs to the design spec: layout, visual language, component
  structure, and how the disk table and progress view actually look. Those are the subject of the
  companion design work and deliberately not pre-empted here.

## Open questions

- OQ1. Does the browser installer collect the Plex claim token (four-minute expiry) at the point of
  use, with a "get one" link and a re-prompt on expiry? That is the natural place for it and is
  much better than the terminal equivalent.
- OQ2. Does it also surface the 1.7 DNS work (R1 there) — showing which records it will create,
  and which already exist and point elsewhere?
- OQ3. Is there a "dry run" mode that walks every screen and stops at the gate, for someone
  evaluating ferrum without a spare machine? Cheap, and it would have made this feature's own
  testing far easier.
