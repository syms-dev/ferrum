# Phase 1.8 — the visual installer: UI/UX design spec

**Status:** design draft for owner review. Companion to
`2026-09-20-phase-1-8-visual-installer-design.md` (requirements R1–R7), which this designs
*against* and does not re-litigate.

**Scope.** Layout, visual language, component structure, every screen's states, responsive
behaviour, accessibility, and the two things the requirements deliberately left to design: how the
disk table and the progress view actually look.

**Read alongside:** `2026-09-19-phase-1-7-hands-off-gaps-design.md` (R3 pooling — per-disk fullness
must be visible; R5 — certificate issuer, self-signed is a failure), `ui/style.css` (the visual
language this must match), `crates/ferrum-install/src/inventory.rs` (`render()` — the terminal disk
table this replaces), `crates/ferrum-install/src/confirm.rs` (the serial gate), and
`crates/ferrum-install/src/state.rs` (`Phase` — the six real phases the progress screen shows).

---

## 1. Design overview

### The one-sentence brief

An operator is sitting at a laptop, next to a machine they are about to erase, for anywhere between
forty minutes and three hours. The interface has to be **legible at a glance, honest about what it
knows, and calm enough to leave open** — and at exactly one moment it has to be deliberately hard to
get wrong.

### Visual direction

This is the same product as the ferrum dashboard, so it is the same skin: `ui/style.css`'s dark-first
panel-on-slate palette, system font stack, 0.4–0.6rem radii, one accent, no shadows, no gradients, no
illustration, no logo mark beyond the wordmark `ferrum` in the header. Nothing is imported — no CDN,
no web font, no icon font (R1 A2). Icons, where used at all, are inline SVG shipped in the binary,
and they are never the *only* carrier of a status (see §11).

Three deliberate departures from a conventional installer:

1. **No wizard chrome.** No numbered circles joined by a line, no "Step 3 of 6" chevron bar. A
   step-counter implies uniform steps, and this flow's steps take one second and forty minutes. The
   progress model is instead a **phase rail** that names the real phases from `state.rs` and shows
   each one's actual elapsed time. See §6.2.
2. **No aggregate percentage, anywhere.** There is no honest denominator. A 40 % bar that sits at
   40 % for twenty-five minutes is the same three-hour mystery in a nicer font.
3. **Density over decoration.** The disk screen is the densest thing here on purpose. Every fact the
   terminal's `render()` prints is on screen simultaneously, plus two the terminal cannot show
   (fullness, and the visual separation of "this one dies" from "these do not").

### Layout approach

A single fixed-width column, `max-width: 64rem`, centred — one wider than the dashboard's `60rem`
because the disk cards and the log pane both want it. Persistent header, a persistent **target-state
ribbon** (§5.3), and the screen body. The progress screen is the only two-column layout, and only
above 1024px.

### What "special, not Saltbox" means here, concretely

Saltbox's failure mode is that the operator is handed a series of true statements and left to
assemble the decision themselves. Three rules follow, and every screen below is checked against
them:

- **State the consequence, not the setting.** "Base domain: thesyms.ca" is a setting. "Seven apps
  will be published at `<app>.thesyms.ca`, behind a login at `auth.thesyms.ca`" is a consequence.
- **Never make the operator hold a fact in their head across a screen.** The confirm screen renders
  the chosen disk with the *identical component* the inventory screen used, so it is recognised
  rather than re-read.
- **When ferrum does not know, it says so in the same size type as when it does.** "Not yet
  confirmed booted" is a first-class state, not a caveat in grey 12px.

---

## 2. Screen inventory

| # | Route | Screen | Destructive? | Back allowed? |
|---|---|---|---|---|
| 0 | `#/` | **Connect** (R3.1 "Target") — where to install, and the credential | no | — |
| 1 | `#/disks` | **Disks** (R3.2 "Inventory") — the inventory, and the choice | no | yes |
| 2 | `#/plan` | **Plan** (R3.3) — hostname, domain, apps, SSO | no | yes |
| 3 | `#/confirm` | **Confirm** (R3.4, R4) — the typed-serial gate | **the boundary** | yes, until submit |
| 4 | `#/install` | **Install** (R3.5, R5) — live progress | past it | **no** (R3 A1) |
| 5 | `#/done` | **Done** (R3.6, R6) — credentials, per-app truth, what's left | — | no |
| 6 | `#/failed` | **Stopped** (R7) — a failure that ended the run | — | recovery actions only |

Plus two non-route surfaces present on every screen: the **target-state ribbon** (§5.3) and the
**raw-output drawer** (R7 A4, §8.4).

**Design finding — F1 (recommended change to R3).** R3 A2 asks that "every screen states what has
and has not happened to the target yet." Implemented per-screen, that is six paragraphs that will
drift out of sync with each other and with the phase machine. Implement it instead as **one
persistent ribbon bound directly to `Phase`** — one component, one source of truth, unmissable
because it never moves. This is a strictly stronger reading of A2 and cheaper to build.

---

## 3. Component hierarchy

Shared shell, present on every screen:

```
AppShell
├── Header            "ferrum" wordmark · "installing <target>" · RawOutputToggle
├── TargetStateRibbon (§5.3)  — bound to Phase, always visible
├── StatusLine        role="status" aria-live="polite"   (mirrors ui/index.html's #status)
├── <screen>
└── RawOutputDrawer   (§8.4) — collapsed by default, focus-trapped when open
```

Per screen:

```
ConnectScreen
├── Field(host)  Field(port)  SshKeyPicker
├── PrimaryAction "Check this target"
└── RefusalPanel?      one of the named R7 refusals

DisksScreen
├── InventoryHeader     "3 disks · 1 selectable as the OS disk"
├── DiskCard[]          ← the core component, §6.1
│   ├── DiskIdentity    name · model · size · serial(mono) · by-id(mono)
│   ├── CapacityBar     used/free per disk  (1.7 R3 A4)
│   ├── BadgeRow        OS-DISK? FERRUM-INSTALL? MOUNTED? EMPTY? NOT-SELECTABLE?
│   ├── FilesystemList  partition · fstype · mountpoint
│   ├── EvidenceDisclosure  "why ferrum thinks this is the OS disk"
│   └── SelectControl   radio (never a default)
├── KeptDisksPanel      ← live, updates as the selection changes
├── OverflowNotice?     "… and N more devices not shown" (MAX_DEVICES = 32)
└── PrimaryAction "Continue — nothing is erased yet"

PlanScreen
├── Field(hostname)
├── Field(baseDomain) → ConsequenceCallout (SSO, DNS, certificates)
├── AppPicker           checkbox list from the catalog
├── SsoDecision         → UnauthenticatedAcknowledgement (if declined)
├── SecretField(cloudflareToken)   write-only (R2 A3)
└── PrimaryAction "Review the disk to be erased"

ConfirmScreen              ← §6.1.4
├── DiskCard(selected, variant="doomed")     identical component, red frame
├── ExistingDataStatement                    R4 A3
├── KeptDisksPanel(variant="full")           R4 A2 — never collapsed
├── PlanRecap                                hostname · domain · apps · SSO
├── SerialGate                               R4 A1 — the typed field
└── DestructiveAction "Erase sda (WD-ABC123) and install"

InstallScreen              ← §6.2
├── PhaseRail[]           the six Phase values + elapsed
├── LivenessPanel         ← the most important widget in this spec
├── CredentialsPanel?     appears the moment credentials exist (R6 A2)
├── LogPane               follow-tail, filterable, virtualised
└── StopAction            "Stop this run" + what stopping means *at this phase*

DoneScreen                 ← §6.3
├── Verdict               one of three headlines, never generic
├── CredentialsPanel      full, with on-host paths
├── AppStatusTable        unit / reachable / certificate — three columns, never merged
├── NeedsYouList          R6 A5 — or its (celebrated) empty state
└── SecondaryActions      "Open ferrum" · "Download the full log"

StoppedScreen              ← §8
├── RefusalPanel          cause · what it means · what was and was not done
├── RecoveryActions       real buttons (R7 A2)
└── RawOutputDrawer(open) R7 A4
```

---

## 4. Layout & grid

- **Container:** `max-width: 64rem`, `margin: 0 auto`, page padding `1rem` → `1.5rem` at 768 →
  `2rem` at 1024.
- **Vertical rhythm:** a 4px base; spacing tokens `--sp-1 .25rem` … `--sp-6 2rem`. Sections are
  separated by `--sp-5`; cards are padded `--sp-4`.
- **Grid:** one column everywhere except the install screen, which becomes
  `grid-template-columns: 18rem 1fr` at ≥1024px (phase rail | log). Below that the rail collapses to
  a horizontal strip above the log.
- **Disk cards** are always full-width rows, never a multi-column card grid. Side-by-side disks
  invite comparison by *position*; stacked full-width rows force comparison by *label*, and the
  label is what the operator will type.
- **Line length:** prose is capped at `44rem` even inside the wider container. Monospace content
  (serials, by-id paths, log lines) is exempt and scrolls horizontally rather than wrapping.

---

## 5. Navigation & routing

### 5.1 Routes and the one-way door

Hash routes, matching the dashboard's `app.js` router exactly (`#/disks`, `#/plan`, …). The router
is authoritative about one rule (R3 A1):

- **Before submit on `#/confirm`:** every earlier route is reachable. Back is a real back — browser
  back, a "← Disks" ghost button, and clicking an earlier phase-rail entry all work and all preserve
  entered values.
- **After submit:** `#/install` is terminal for navigation. The earlier routes are removed from the
  router table, not merely hidden; `history.replaceState` is used on entry so browser-back cannot
  land on a screen that is now lying. Attempting an old hash lands on `#/install` with the status
  line reading *"The disk has been erased. There is nothing to go back to."*

### 5.2 Rejoining (R1 A4)

Opening the URL while a run is in progress lands on `#/install` regardless of the requested hash,
with a one-line banner: *"Rejoined a run started at 21:04. Output from before you reopened is in the
full log."* No modal, no "welcome back" ceremony.

### 5.3 The target-state ribbon (F1)

A full-bleed strip directly under the header, one line, bound to `Phase`:

| Phase | Ribbon text | Tone |
|---|---|---|
| (pre-run) | `Nothing has been written to saltbox.` | neutral, `--ok` left border |
| `Generated` | `Nothing has been written to saltbox. A configuration has been generated here.` | neutral |
| `PreflightPassed` | `Nothing has been written to saltbox. Preflight passed.` | neutral |
| `Installing` | `sda is being erased right now.` | `--danger` |
| `Installed` | `sda has been erased and written. Not yet confirmed booted.` | `--warn` |
| `HardwareConfigured` | `saltbox is installed and booted. A resume will not repartition.` | `--warn` |
| `Stage2Applied` | `saltbox is installed and booted. Apps and authentication are enabled.` | neutral |
| `Verified` | `saltbox is installed and verified.` | `--ok` |

The wording for the destructive phases is lifted from `Phase::describe()` so the browser and the
terminal say the same thing. R4 A4 ("the disk is gone and a resume will not repartition") is
satisfied by the `HardwareConfigured` row and every row after it.

`aria-live="polite"` on the ribbon, so a screen-reader user hears the transition without being
interrupted mid-sentence.

---

## 6. Data display — the three screens that matter

### 6.1 The disk screen

This is where the product's safety lives, so it gets the most space here.

#### 6.1.1 What is wrong with the terminal version

`inventory::render()` prints, per disk, four to eight fixed-width lines of equal visual weight:

```
  sda            1.8T  WDC WD20EZAZ
                       serial: WD-ABC123
                       /dev/disk/by-id/ata-WDC_WD20EZAZ_WD-ABC123
                         sda1 vfat mounted at /boot
                         sda2 ext4 mounted at /
```

Everything it says is true and correctly hardened (control-character stripping, field caps, the
32-device cap — all of which the browser must preserve, §15). What it cannot do:

- **It cannot show fullness.** `lsblk` size is capacity, not use. An operator with 7.3T of media
  reads "3.6T" and "1.8T" and has to remember which one has the media on it.
- **Every line looks equally important.** The serial — the thing they are about to type, the thing
  that decides which disk dies — is rendered in the same weight as the model string.
- **It cannot show the negative space.** "These six disks will not be touched" is the claim R4 A2
  says matters as much as the positive one, and a flat list cannot make a claim about itself.

#### 6.1.2 The DiskCard

Full-width, stacked. ASCII sketch at ~900px:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ( ) sda        1.8 TB      WDC WD20EZAZ                                      │
│     ┌──────────────────────────────────────────────────────────────────┐     │
│     │████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░│     │
│     └──────────────────────────────────────────────────────────────────┘     │
│     1.1 TB used · 0.7 TB free · 62 % full                                    │
│                                                                              │
│     [ CURRENTLY THE OS DISK ]  [ FERRUM INSTALL DETECTED ]                   │
│                                                                              │
│     serial    WD-ABC123                                                      │
│     by-id     /dev/disk/by-id/ata-WDC_WD20EZAZ_WD-ABC123                     │
│                                                                              │
│     sda1  vfat  512 MB   mounted at /boot                                    │
│     sda2  ext4  1.8 TB   mounted at /                                        │
│                                                                              │
│     ▸ Why ferrum thinks this is the OS disk                                  │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│ ( ) sdb        3.6 TB      ST4000VN                                          │
│     ┌──────────────────────────────────────────────────────────────────┐     │
│     │██████████████████████████████████████████████████████████░░░░░░░░│     │
│     └──────────────────────────────────────────────────────────────────┘     │
│     3.2 TB used · 0.4 TB free · 89 % full                                    │
│                                                                              │
│     [ HOLDS DATA ]                                                           │
│                                                                              │
│     serial    ZDH9                                                           │
│     by-id     /dev/disk/by-id/ata-ST4000VN_ZDH9                              │
│                                                                              │
│     sdb1  ext4  3.6 TB   mounted at /mnt/media                               │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│  ×  fd0          4 MB     (no model reported)                  NOT SELECTABLE│
│     This device reports no serial, so there is nothing you could type to     │
│     name it. It cannot be chosen.                                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

Field-by-field rationale:

- **Kernel name, size, model on one line, largest type on the page.** This is the identification
  line; everything else is corroboration.
- **The capacity bar is the headline addition.** It is the one thing the terminal cannot do and it
  answers "which one has my media on it?" pre-verbally. It is also directly reusable for 1.7 R3 A4
  (per-disk fullness in a pool), which is the same widget with a pool header above it — build it
  once, in `ui/`, used by both.
- **Serial in monospace, on its own labelled row, with the label to its left.** Not bolded red, not
  boxed. It needs to be *findable* and *transcribable*, not alarming — the alarm belongs to the
  confirm screen. Readability is improved with `letter-spacing` on the mono run, **never** by
  inserting separators or spaces, because the operator will type exactly what they see and
  `match_serial` compares byte-for-byte.
- **`by-id` below it, dimmed.** It is the stable identifier the generated `disko.nix` will name; it
  is corroboration for an expert and noise for everyone else, so it is present and quiet.
- **Filesystems are indented under the disk**, with the mountpoint as the rightmost, strongest
  column — "the one mounted at /mnt/media" is how people actually identify a drive.

#### 6.1.3 Badges, and what they are allowed to claim

Badges use `.pill` from `ui/style.css`, extended with tone variants. Each is a *fact with a source*,
never an inference presented as a fact:

| Badge | Condition | Tone |
|---|---|---|
| `CURRENTLY THE OS DISK` | `mounted_at()` contains `/` — i.e. `confirm::propose` picked it | warn |
| `FERRUM INSTALL DETECTED` | target is an existing ferrum host (1.7 R2 A1) | warn |
| `HOLDS DATA` | has children with a non-empty `fstype` | neutral |
| `MOUNTED AT <path>` | one badge per mountpoint | neutral |
| `EMPTY — NO PARTITIONS` | `is_blank()` | neutral |
| `NOT SELECTABLE` | `serial == None` | muted, card is dimmed and has no radio |
| `NO STABLE by-id PATH` | `by_id == None` — selection will be refused at the gate | danger |

`CURRENTLY THE OS DISK` is the strongest claim on the screen and it is deliberately **not** a
pre-selection. `confirm.rs` is explicit that the proposal is "a suggestion shown on screen, never a
default the operator can accept by pressing enter", and the browser must not quietly undo that: **no
radio is checked on load.** The disclosure "▸ Why ferrum thinks this is the OS disk" expands to the
evidence — `sda2 is mounted at /`, `sda1 is a vfat ESP`, `/var/lib/ferrum/state exists` — which is
what lets an operator disagree with it rather than defer to it.

When nothing is mounted at `/` (rescue media — common), the screen says so at the top, in the same
words as the CLI: *"No disk on this machine is mounted at /, so there is nothing to suggest. This is
normal when the target is booted from rescue or live media."*

#### 6.1.4 The kept-disks panel

Below the cards, and — critically — **also on the confirm screen, never collapsed**:

```
┌─ These disks will not be touched ────────────────────────────────────────────┐
│                                                                              │
│  sdb   3.6 TB  ST4000VN   ZDH9      3.2 TB of data, mounted at /mnt/media    │
│  sdc   7.3 TB  WD80EFAX   WD-9KL2   6.9 TB of data, mounted at /mnt/media2   │
│                                                                              │
│  ferrum only names one disk in the generated configuration. A disk that is   │
│  not named there is never opened, never partitioned and never mounted.       │
└──────────────────────────────────────────────────────────────────────────────┘
```

The closing sentence is the *structural* protection from `confirm.rs`'s module header, and it is the
sentence that will actually calm an operator with 7TB of media. It is worth the two lines.

The panel is **live** on the disks screen: it updates the instant the selection changes, so choosing
a disk visibly moves it out of the safe list. That transition is the cheapest possible way to make
the consequence felt.

#### 6.1.5 Disk-screen states

| State | Rendering |
|---|---|
| **Loading** | Skeleton: three card outlines at the right height, plus the literal line *"Reading the disk inventory from saltbox over SSH."* Never a bare spinner — say what is happening. |
| **Data** | As above. |
| **Empty** (no `type == "disk"` devices) | *"saltbox reports no block devices of type `disk`. That is not a machine this installer can install to."* + raw `lsblk` output inline + Retry. |
| **No serials anywhere** | The refusal from `check_serials_identify`, verbatim, including the virtio/libvirt/QEMU/Proxmox remedies and *"There is deliberately no flag to bypass this."* Rendered as a `RefusalPanel`, not a toast. |
| **Duplicate serials** | Refusal naming both colliding devices. The colliding cards are rendered with a `danger` frame and no radio; other disks stay selectable **only if** a unique-serial disk exists. |
| **Overflow** (>32 devices) | The cap is preserved. Notice below the list: *"… and 14 more devices are not shown. Selection is by serial, so a disk missing from this list can still be named — but check the machine if you did not expect this many."* Plus a "Show all" that raises the DOM cap to 256 with an explicit warning, and a search field. |
| **Error** (SSH dropped mid-read) | `RefusalPanel` with the command, exit code, stderr, and a Retry that re-runs only the inventory. |

### 6.2 The progress screen

The requirement this screen exists for is blunt: *two CI runs and one real install sat silent for
hours while `nixos-anywhere` looped forever on `ssh-copy-id`; nothing distinguished "building" from
"hung"*. Everything below is aimed at that one sentence.

#### 6.2.1 Layout (≥1024px)

```
┌─ phase rail ──────────────┬─ output ─────────────────────────────────────────┐
│                           │                                                  │
│ ✓ Generated        0:02   │  Building the system closure on saltbox          │
│ ✓ Preflight        0:11   │  ┌────────────────────────────────────────────┐  │
│ ● Installing      24:18   │  │ ● Working — quiet for 3m 12s               │  │
│     └ erasing sda   ✓     │  │   This step is often silent. A closure      │  │
│     └ building    22:40   │  │   build produces no output for minutes at   │  │
│   Installed         —     │  │   a time.                                   │  │
│   Hardware config   —     │  │   Last output    3m 12s ago                 │  │
│   Stage 2           —     │  │   Last alive       6s ago  (ssh channel ok) │  │
│   Verified          —     │  │   Typical         20–40 min · elapsed 24:18 │  │
│                           │  └────────────────────────────────────────────┘  │
│ Started 21:04             │                                                  │
│ Elapsed 24:31             │  ┌─ output ── [All ▾] ── 12,418 lines ────────┐  │
│                           │  │ copying path '/nix/store/…-linux-6.6.3' …  │  │
│ [ Stop this run ]         │  │ building '/nix/store/…-nixos-system.drv'   │  │
│                           │  │ …                                          │  │
│                           │  │                          [ ↓ jump to live ]│  │
│                           │  └────────────────────────────────────────────┘  │
└───────────────────────────┴──────────────────────────────────────────────────┘
```

#### 6.2.2 The phase rail

Entries are exactly `Phase`'s variants, in order, labelled with `Phase::describe()`'s vocabulary.
Sub-steps nest under the phase that owns them — `Installing` owns *kexec*, *erasing sda*,
*building the closure*, *copying*, *rebooting* — because `nixos-anywhere` is one external process
and the sub-steps are what it prints, not phases the resume machine knows about. Rendering them as
peers of the real phases would lie about what a resume resumes to.

Each entry shows: a state glyph *and* a state word (never colour alone), and a duration — **elapsed**
for the current one, **final** for completed ones. Completed durations are the quietly valuable part:
after one install the operator knows what normal looks like on their hardware.

Pending entries show **no estimate**. An estimate on an unstarted step is a promise; the only place
an expected range appears is inside the liveness panel of the step that is actually running, where
it is being measured against.

#### 6.2.3 The liveness panel — R5 A3, the core of this screen

Three distinct states, and the distinction between the first two is the whole point.

**(a) Working, talking.** Output within the last `quiet_threshold` (per-step; default 20s).

> `● Working` · `Last output 2s ago` · `elapsed 0:41`
>
> A 1 Hz pulse on the dot. This is the only animation on the screen, and it carries information: it
> is present exactly when output is flowing.

**(b) Working, quiet.** No output for longer than the threshold, but an independent liveness probe
succeeds.

> `● Working — quiet for 3m 12s`
> *This step is often silent. A closure build produces no output for minutes at a time.*
> `Last output  3m 12s ago` · `Last alive  6s ago (ssh channel ok)` · `Typical 20–40 min`
>
> The pulse **stops**. A still dot plus a running "last alive" counter is the correct signal: the
> animation has stopped because the output has, and the number that keeps moving is the one that
> proves it is not hung.

Liveness must be a *separate signal from output*, or it is just "no output" wearing a hat. Concretely
the installer needs, per step, a probe that is cheap and independent of the step's own stdout:

- the SSH master channel is open and a `ControlMaster` check-command returns (this alone would have
  caught the `ssh-copy-id` loop: the channel was fine and the *retry counter* was the anomaly);
- the remote PID for the step still exists;
- for a remote build, the target's `nix` daemon is alive and the box is doing work — a `pgrep
  nix-daemon` plus a load-average read is enough and costs nothing.

**Design finding — F2 (requirement-level, R5 A3/A4).** The liveness probe, the quiet threshold and
the plausible window belong in `ferrum-install` the **library**, not in the browser. R1 A3 keeps the
terminal a supported path, and if only the browser knows a step is overdue then the terminal keeps
the exact failure mode this phase exists to remove. Recommend: a `Step` descriptor carrying
`{ id, label, quiet_threshold, plausible_window, liveness_probe, attempt_count }`, emitted on the
same event stream both front-ends read. The browser renders it; the CLI prints it.

**(c) Overdue.** Elapsed exceeds the step's `plausible_window`.

```
┌──────────────────────────────────────────────────────────────────────┐
│ ⚠ This step has taken longer than expected                           │
│                                                                      │
│ Copying the SSH key to saltbox usually completes in under 10         │
│ seconds. It has been running for 4 minutes 30 seconds.               │
│                                                                      │
│ nixos-anywhere retries ssh-copy-id indefinitely and does not time    │
│ out. It has made 47 attempts and none has succeeded.                 │
│                                                                      │
│ Most likely: saltbox is not accepting the key, or sshd restarted     │
│ after kexec and is not up yet.                                       │
│                                                                      │
│ [ Show the last attempt's output ]  [ Test the connection myself ]   │
│ [ Stop this run ]                                                    │
└──────────────────────────────────────────────────────────────────────┘
```

This banner is the thirty-second diagnosis R5 A3 asks for, and note what does the work: not the
elapsed time, but **"47 attempts and none has succeeded"**. A retry count is the difference between
"slow" and "looping". It requires the installer to count and emit retries, which it does not do
today — that is part of F2.

The banner **does not stop the run**. It offers stopping; it waits. R7 A3's principle ("where a
recovery needs the operator elsewhere, say so with the reason, and wait rather than failing")
applies equally here.

Per-step plausible windows (starting values; they belong in the library and should be tunable):

| Step | Quiet threshold | Plausible window | Why |
|---|---|---|---|
| Target reachability | 5 s | 30 s | a TCP connect |
| Inventory read | 5 s | 30 s | two commands |
| Preflight eval | 15 s | 5 min | a local nix eval |
| kexec | 20 s | 5 min | the box reboots into the installer |
| `ssh-copy-id` / post-kexec SSH | 10 s | **60 s** | the three-hour bug lives here |
| disko (erase + partition) | 20 s | 5 min | seconds on any real disk |
| closure build on target | **5 min** | **75 min** | legitimately silent for long stretches |
| copy + install | 60 s | 30 min | network-bound |
| reboot + wait for SSH | 20 s | 10 min | a cold boot |
| hardware-config transfer | 20 s | 5 min | one file |
| stage 2 apply | 2 min | 40 min | another build |
| verification | 20 s | 5 min | HTTP + systemctl checks |

#### 6.2.4 The log pane

Build output is evidence, not decoration (R7 A4, and every 1.6a defect was diagnosed from raw
output). So:

- **Monospace, `.85rem`, no wrapping by default.** Nix store paths are 60+ characters; wrapping turns
  a scannable column into a wall. Horizontal scroll, with a "wrap lines" toggle that persists.
- **Follow-tail with an escape hatch.** Auto-scroll while pinned to the bottom. Scrolling up
  *detaches* and a `↓ jump to live (412 new)` pill appears. The view is **never** yanked back
  automatically — an operator reading an error four hundred lines up while a build streams is the
  normal case, and stealing their scroll is the single most hostile thing a log viewer does.
- **Ring buffer in the DOM.** 5,000 lines retained; older lines are dropped from the DOM with a
  `— 8,102 earlier lines are in the full log —` marker, and the full log is always downloadable and
  always on disk. Unbounded DOM growth over a three-hour run is a real hang.
- **Filter, not search-only:** `All output` / `Errors and warnings` / `ferrum's own steps`. The third
  is the installer's structured events without the build's noise, and it is what most operators
  actually want open.
- **Minimal colour.** stderr dimmed, lines matching an error shape in `--danger`. No ANSI theatre.
  The `strip_controls` allowlist already guarantees no escape sequence survives from the target, and
  the browser renderer must keep that guarantee (§15) — set `textContent`, never `innerHTML`.

#### 6.2.5 Progress-screen states

| State | Rendering |
|---|---|
| **Starting** | The rail is rendered with all phases pending and the first one `● starting`. Never an empty screen. |
| **Running, talking** | (a) above. |
| **Running, quiet** | (b) above. |
| **Overdue** | (c) above. |
| **Stream dropped** (the browser lost the SSE connection) | A banner distinct from every state above: *"Lost the connection to the installer. **The install is still running on saltbox** — this page is what disconnected. Reconnecting…"* This distinction is essential and easy to get wrong: a dropped EventSource must never look like a stalled install. |
| **Rejoined** | §5.2's banner + the log backfilled from the persisted log. |
| **Failed** | Route to `#/failed`; the log pane and rail are preserved and rendered there. |
| **Finished** | Route to `#/done`; a `View the install log` link keeps the pane reachable. |

### 6.3 The done screen

#### 6.3.1 The verdict

One of exactly three headlines, chosen mechanically, never softened:

| Condition | Headline | Tone |
|---|---|---|
| every app answered on its hostname with a CA-issued certificate, and nothing needs a human | **saltbox is installed and working.** | `--ok` |
| installed and booted, but ≥1 item needs a human or ≥1 app is not yet reachable | **saltbox is installed. 3 things still need you.** | `--warn` |
| installed but nothing is reachable, or any certificate is self-signed | **saltbox is installed but is not reachable.** | `--danger` |

R6 A4 is the reason the third row exists: **a self-signed fallback certificate puts the whole run in
the red headline, not in a footnote.** 1.7 R5's evidence is that the previous behaviour reported
success while every hostname served `CN=minica root ca`; the design position here is that a fake
certificate is a failed install with a working machine attached.

#### 6.3.2 Credentials (R6 A1, A2, 1.7 R4)

First block on the page, above the app table, because the operator locked out of Authelia is the
concrete failure this requirement was written from.

```
┌─ Your logins ────────────────────────────────────────────────────────────────┐
│                                                                              │
│  Single sign-on (Authelia)   https://auth.thesyms.ca                         │
│    username   admin                                                          │
│    password   7Qk-3xv-ZZ1-mpa                                    [ copy ]    │
│    on the host   /var/lib/ferrum/secrets/authelia-admin                      │
│                                                                              │
│  ferrum UI                   https://ferrum.thesyms.ca                       │
│    username   admin                                                          │
│    password   b4T-9wm-Lq0-ndz                                    [ copy ]    │
│    on the host   /var/lib/ferrum/secrets/ferrum-admin                        │
│                                                                              │
│  These are readable on the host at the paths above. You are not locked out   │
│  if you close this page.                                                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

Deliberate calls:

- **Shown in plain text, not masked behind a reveal.** Masking here optimises for shoulder-surfing in
  a scenario (operator alone at a laptop beside a server) where the real risk is the opposite one —
  R6 A1's actual incident. The on-host path beside each is the mitigation that matters.
- **The same panel appears on the install screen the moment the credentials exist** (R6 A2), and on a
  resumed run (1.7 R4 A3). It is one component in three places.
- **It is never rendered from a GET.** R2 A3 forbids secrets crossing the boundary in a response.
  These are generated *by this run* and pushed on the same event stream as progress; the browser
  holds them in memory only. Reloading the page after they are gone shows the on-host paths, not the
  values — and says so.

#### 6.3.3 The app table — R6 A3's distinction, made structural

"Installed" and "reachable on its own hostname with a real certificate" are different claims, so they
are different columns. Merging them into one green tick is exactly the failure mode.

```
┌─ Apps ───────────────────────────────────────────────────────────────────────┐
│ App        URL                     Service     Reachable     Certificate     │
│ ─────────────────────────────────────────────────────────────────────────────│
│ Plex       plex.thesyms.ca         ✓ active    ✓ 200         ✓ Let's Encrypt │
│ Sonarr     sonarr.thesyms.ca       ✓ active    ✓ 302 → SSO   ✓ Let's Encrypt │
│ Radarr     radarr.thesyms.ca       ✓ active    ✓ 302 → SSO   ✓ Let's Encrypt │
│ Jellyfin   jellyfin.thesyms.ca     ✓ active    ✗ no DNS      — not issued    │
│ Authelia   auth.thesyms.ca         ✓ active    ✓ 200         ⚠ SELF-SIGNED   │
└──────────────────────────────────────────────────────────────────────────────┘
```

- **Service** = the systemd unit is `active` (and `activating (auto-restart)` renders as
  `● settling`, not as failed — 1.7 R6 A1).
- **Reachable** = an HTTP request to the real hostname returned. `302 → SSO` is a success and is
  *shown as one*, because an operator who sees a redirect and assumes breakage is the confusion this
  product exists to avoid.
- **Certificate** = the issuer, read from the served certificate (1.7 R5 A1). `⚠ SELF-SIGNED` is
  `--danger`, carries the sentence *"browsers will warn, and this is not a working install"*, and
  carries a **`Retry the certificate order`** button — 1.7 R5 A2 in the form R7 A2 demands, a button
  that does the thing rather than a sentence about a command.

Clicking any cell expands the underlying evidence: the exact command, its output, the issuer DN. The
rows should be rendered from `verify.rs`'s `Check` results directly rather than reinterpreted, so
the screen and the CLI cannot disagree.

#### 6.3.4 "Still needs you" (R6 A5)

```
┌─ 2 things still need you ────────────────────────────────────────────────────┐
│                                                                              │
│  1. Plex is not claimed.                                                     │
│     A new Plex server answers "You do not have access to this server" until  │
│     it is associated with an account.                                        │
│     → Get a claim token at plex.tv/claim (valid 4 minutes), paste it here:   │
│       [                    ] [ Claim Plex ]                                  │
│                                                                              │
│  2. jellyfin.thesyms.ca does not resolve.                                    │
│     ferrum created the record 3 minutes ago; DNS has not propagated.         │
│     → Nothing to do. [ Check again ]                                         │
└──────────────────────────────────────────────────────────────────────────────┘
```

Each item: **what**, **why it matters**, and **the exact action** — as a control where one exists
(R7 A2). Item 1 is OQ1 answered *yes*: collect the claim token at the point of use, with the four-
minute expiry handled by re-prompting rather than documented (1.7 R2 A4). The browser is the right
place for this precisely because it can hold a form open and re-prompt.

The empty state is the product's thesis and gets celebrated, not omitted:

> **Nothing needs you.**
> Every app ferrum published answered on its own hostname with a real certificate.

---

## 7. Forms & inputs

| Field | Type | Validation | Error placement |
|---|---|---|---|
| Target host | text | non-empty; resolves or is an IP literal; validated on blur and on submit | inline under field, `aria-describedby` |
| SSH port | number | 1–65535, default 22 | inline |
| SSH key | picker over the mounted `--ssh-dir` | must exist and be a private key | inline + "no keys found in /ssh" empty state |
| Hostname | text | RFC1123 label; live-normalised **visibly** (shows what it changed and why) | inline |
| Base domain | text | domain shape; optional | inline + **consequence callout** (below) |
| ACME email | email | `type="email"`, required when a domain is set | inline |
| Cloudflare token | password, write-only | non-empty; **trailing-whitespace and non-printable check with the offending codepoint named** (1.7 R7 A2); verified live against the zone (1.7 R1 A5) | inline, with the codepoint |
| Apps | checkbox list | ≥1 | summary under list |
| SSO | radio: on / off | — | consequence callout |
| Plex claim token | text | 4-minute expiry timer shown; re-prompt on expiry | inline |
| **Disk serial** | text | §7.2 | §7.2 |

### 7.1 Consequence callouts

The plan screen's job is to show consequences as they are chosen (R3.3). Two callouts, both live:

**Setting a domain:**
> Setting `thesyms.ca` turns single sign-on on. Every app will be published at
> `<app>.thesyms.ca` behind a login at `auth.thesyms.ca`, with certificates from Let's Encrypt.
> ferrum will create the DNS records; it will not overwrite a record it did not create.
> *Reaching these names from inside your own LAN depends on your router's NAT hairpin, which many
> do not do. That is not an install failure.* (1.7 R1 A6 — this one bit the owner.)

**Declining SSO:**
> ⚠ Sonarr, Radarr, Prowlarr, Bazarr, qBittorrent and SABnzbd will be reachable from the public
> internet with **no login at all**. Anyone who finds the hostname can use them.
> ☐ I understand these 6 apps will be published unauthenticated.

The acknowledgement is unchecked by default and its label enumerates the apps by name. This is not
the serial gate — it is reversible and non-destructive, so a checkbox is proportionate — but it is
deliberately not a silent default, because ferrum's standing position is that a published app is an
authenticated app.

### 7.2 The serial gate (R4)

```
┌─ Type the serial of the disk to erase ───────────────────────────────────────┐
│                                                                              │
│  You are erasing      sda · 1.8 TB · WDC WD20EZAZ                            │
│  Its serial is        WD-ABC123                                              │
│  It currently holds   an ext4 filesystem mounted at /, and a ferrum install  │
│                                                                              │
│  Everything on it will be gone. This cannot be undone.                       │
│                                                                              │
│  Serial   [                              ]                                   │
│           Exactly as shown, including case and dashes.                       │
│                                                                              │
│           [ Erase sda (WD-ABC123) and install ]        [ Cancel ]            │
└──────────────────────────────────────────────────────────────────────────────┘
```

Behaviour, with reasoning for each call:

- **No paste blocking.** Blocking paste is theatre: it cannot stop a screenshot-and-retype and it
  drives a frustrated operator to transcribe from a second window, which is *more* error-prone. The
  gate's value is that a **typo refuses** (`match_serial`'s property), not that fingers were used.
- **No copy button on the confirm screen.** Every other serial in the UI has one; this one does
  not. The inventory screen is for identifying; this screen is for committing.
- **No live "✓ matches" feedback.** A green tick as the last character lands is a reflex reward and
  turns the gate into a fiddling exercise. Validation happens on submit, and a mismatch shows
  `match_serial`'s own message verbatim, including *"Nothing has been changed."*
- **One exception, and it is important: a live check for the *wrong disk*.** If the typed value
  exactly matches a **different** disk's serial, warn immediately and loudly rather than waiting for
  submit:
  > ⚠ `ZDH9` is **sdb** — the 3.6 TB disk holding your media. You selected **sda**. Go back and
  > change the selection, or type sda's serial.
  >
  This is the wrong-disk case; it is the one the whole gate exists for; it must not be discovered
  one keystroke later.
- **No normalisation.** `autocapitalize="off" autocorrect="off" spellcheck="false"
  autocomplete="off"`, and the value is sent byte-for-byte. `confirm.rs`'s tests assert `os-123`
  fails where `OS-123` succeeds; a UI that uppercases would silently diverge from the library it is
  a front-end for.
- **Enter does not submit.** This is the one place to break a browser convention. In a single-field
  form the browser submits on Enter, and Enter-after-typing is precisely the reflex this gate
  exists to defeat. Instead Enter moves focus to the destructive button, which is then activated
  deliberately with Space or Enter. One extra keystroke, visible focus movement, and a button whose
  label names the disk. Hard to do by accident; two seconds to do on purpose.
- **The button is disabled only while the field is empty.** Not "until it matches" — a mismatch must
  produce the library's explanatory refusal, which teaches; a permanently-dead button does not.
- **The button label names the disk and the serial.** `Erase sda (WD-ABC123) and install`. Never
  "Continue", never "Confirm".
- **Cancel is `.ghost`, to the right, and returns to `#/disks` with the selection intact.**

Gate states:

| State | Rendering |
|---|---|
| Empty | button disabled; hint visible; no error |
| Typing | no feedback (except the wrong-disk check above) |
| Submitted, no match | `match_serial`'s "no disk on this machine reports serial …" verbatim, in a `role="alert"` region; field retains value and keeps focus |
| Submitted, matches a different disk | the wrong-disk warning, escalated; submission refused |
| Submitted, disk has no `by-id` | `confirm.rs`'s refusal about `/dev/sdX` not being stable across boots |
| Submitted, firmware conflict | `infer_firmware`'s "conflicting signals" refusal, with the legacy-BIOS explanation |
| Submitted, device changed since inventory | `verify_still`'s refusal, plus a Re-read the inventory action |
| Accepted | the button becomes a non-interactive `Erasing sda…`, the ribbon flips to `--danger`, and the route advances. **Irreversible from here.** |

---

## 8. Interactive elements & failure states (R7)

### 8.1 Buttons

Four variants, all from `ui/style.css`:

| Variant | Use | Style |
|---|---|---|
| primary | the one forward action per screen | `button` (accent fill) |
| ghost | back, cancel, secondary | `button.ghost` |
| danger | erase, stop the run, roll back | `button.danger` |
| quiet | inline toggles (wrap lines, show evidence) | text + underline on hover |

There is exactly **one** primary action per screen, bottom-right of the content column. Two primary
buttons is the Saltbox feeling.

### 8.2 The RefusalPanel — every R7 refusal uses one component

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ⚠ saltbox refused the connection                                             │
│                                                                              │
│ ssh root@192.168.2.50 -p 22 returned "Permission denied (publickey)".        │
│                                                                              │
│ ferrum installs over SSH as root. Most live images accept a key placed in    │
│ /root/.ssh/authorized_keys but refuse password logins.                       │
│                                                                              │
│ Nothing has been written to saltbox.                                         │
│                                                                              │
│ [ Try again ]   [ Use a different key ]   [ Show the full output ]           │
└──────────────────────────────────────────────────────────────────────────────┘
```

Four mandatory parts, in this order: **what happened** (with the real command), **what it means**,
**what has and has not happened to the target**, and **what to do** — as controls, not prose
(R7 A2). The named refusals from R7 A1 each get their own copy:

| Refusal | Recovery offered |
|---|---|
| No serials on the machine | none — the message names the virtio/hypervisor fix and says there is no bypass |
| Duplicate serials | none — names both devices |
| Wrong architecture | none — states the detected arch and that `--build-on remote` does not help |
| Unreachable target | `Try again`, `Change the address` |
| Root refused | `Try again`, `Use a different key` |
| kexec'd target on a resume | `Power-cycle the box, then [ Check again ]` — waits, does not fail (R7 A3) |
| Placeholder hardware config | `Re-transfer the hardware configuration` (a button that runs it) |
| Prior run conflicts with this target | `Start fresh — this WILL erase <disk> again` (a real `--fresh` button, red, behind its own typed confirmation if the prior phase was destructive) |

### 8.3 Stopping a run

`Stop this run` is always available on the install screen, and its confirmation dialog says something
different at every phase, because stopping means something different:

- before `Installing`: *"Nothing has been written. Stopping costs you nothing."*
- during `Installing`: *"sda is being erased or written right now. Stopping leaves saltbox with no
  working operating system. You will need to resume or start over."*
- after `Installed`: *"saltbox is installed. Stopping now leaves it booted but without apps or
  authentication. Re-running will resume from here and will not repartition."*

### 8.4 The raw-output drawer (R7 A4)

A header toggle, present on every screen, opening a bottom drawer (full-height panel ≥1024px) with
every command the installer has run, its exit status, and its full output — including the ones that
succeeded. Focus-trapped while open, `Esc` closes, focus returns to the toggle. This is not a debug
mode; it is always one click away, because every 1.6a defect was diagnosed from raw output.

---

## 9. States — the matrix

Every data-driven surface, with all four states defined.

| Surface | Loading | Empty | Error | Data |
|---|---|---|---|---|
| Target check | "Connecting to saltbox…" + elapsed | n/a | RefusalPanel per §8.2 | green summary: arch, kernel, EFI, uptime |
| Disk inventory | 3 skeleton cards + "Reading the disk inventory over SSH" | "no block devices of type disk" + raw lsblk | RefusalPanel + Retry | §6.1 |
| Kept-disks panel | hidden until inventory loads | "sda is the only disk on this machine. There is nothing else to keep." | inherits inventory error | list |
| App catalogue | skeleton checkbox rows | "no apps in the catalogue" (a build problem — says so) | RefusalPanel | checkbox list |
| Cloudflare token check | "Checking the token against thesyms.ca…" | n/a | names the codepoint / the API error | "✓ can list the zone thesyms.ca" |
| Phase rail | all pending, first `starting` | n/a | failed phase in `--danger` with its journal tail | §6.2.2 |
| Liveness panel | "starting…" | n/a | "stream lost — the install is still running" | (a)/(b)/(c) |
| Log pane | "waiting for the first line…" | "this step produced no output" (explicitly, not blank) | "the log stream ended unexpectedly" | lines |
| Credentials | skeleton rows while generating | "no credentials have been generated yet" | n/a | §6.3.2 |
| App status table | one skeleton row per enabled app | "no apps were enabled" | per-row error with the failing command | §6.3.3 |
| Needs-you list | skeleton | **celebrated empty state** (§6.3.4) | n/a | numbered items |

---

## 10. Responsive behaviour

The target is a browser window on a laptop. It must not *break* narrower, and it must not assume a
phone.

| Width | Behaviour |
|---|---|
| **≥1280** | Container `64rem` centred. Install screen two-column (`18rem` rail + log). Disk cards full-width with the capacity bar inline. |
| **1024–1279** | Same, rail narrows to `15rem`. |
| **768–1023** | Single column. Phase rail becomes a horizontal strip above the log: current phase expanded, others as a compact `✓ ✓ ● ○ ○ ○` row with names. Log pane min-height `20rem`. |
| **640–767** | Disk card internals stack: identity line, capacity bar, badges wrap, `serial`/`by-id` labels move above their values. App status table keeps its columns (they are short) but scrolls horizontally in a wrapper. |
| **<640** | Everything single column, page padding `1rem`. `by-id` paths truncate with a middle ellipsis and a tap-to-expand. App status table becomes one card per app (Service / Reachable / Certificate as labelled rows). Log pane `min-height: 14rem`, wrap-lines defaults **on** below 640 because horizontal scroll plus vertical scroll on a small screen is unusable. |

Touch targets: every control is ≥44px high below 768px, and a `DiskCard` is a whole-card click target
for its radio (a 12px radio is not a tap target).

**The R4 A2 "without scrolling" constraint, honestly.** On a 1280×800 window with three disks, the
confirm screen fits and A2 is met literally. On a short window with eight disks it cannot be, and
pretending otherwise would mean collapsing the kept-disks list — which is the one thing A2 forbids.
The design call:

- The kept-disks list is **never collapsed, never scrolled inside its own box, and never truncated**.
- Below `700px` of viewport height, each kept disk compresses to a single line
  (`sdb · 3.6 TB · ST4000VN · ZDH9 · untouched`).
- If it still overflows, **the serial field and the destructive button are placed *below* the
  complete list**. Reaching the gate then *requires* scrolling past every disk that will survive.

That inverts the failure: where the letter of A2 cannot be met, the scroll is turned into the
mechanism rather than the problem. Recommend amending A2 to state this explicitly.

---

## 11. Accessibility

Target: WCAG 2.1 AA. The destructive gate is specified keystroke by keystroke.

### 11.1 Landmarks and headings

`<header>`, the ribbon as `<div role="status">`, `<main>`, one `<h1>` per screen (the screen name),
`<h2>` per block. No heading levels skipped. A skip link to `#main` as the first focusable element.

### 11.2 Keyboard path through the disk gate

Disks screen:

1. Tab → skip link → header → ribbon (not focusable) → first disk's radio.
2. **Radios are one tab stop**, arrow keys move between disks (native radiogroup semantics), which
   is correct here: the disks are a single-choice set, and arrowing through them reads each card's
   accessible name. `role="radiogroup"` with `aria-labelledby` pointing at "Choose the disk to
   erase".
3. Each radio's accessible name is the whole identification: `"sda, 1.8 terabytes, WDC WD20EZAZ,
   serial W D dash A B C 1 2 3, currently the OS disk, 62 percent full, mounted at slash"`. Serials
   are marked so they are read **character by character** (an `aria-label` with spaced characters;
   the visible text is unchanged) — a screen reader saying "wd-abc one hundred twenty-three" is
   useless for transcription.
4. Non-selectable disks are `aria-disabled="true"` and **remain focusable**, so their reason is
   announced rather than skipped silently.
5. The evidence disclosure is a `<button aria-expanded>`; the kept-disks panel is
   `aria-live="polite"` so selecting a disk announces `"sdb and sdc will not be touched."`

Confirm screen:

1. On entry, focus moves to the `<h1>` (`tabindex="-1"`), not to the input. Landing in a text field
   with no context is disorienting and, here, dangerous.
2. Tab → the disk card's evidence disclosure → the kept-disks list (a `<ul>`, not focusable) → the
   **serial input**.
3. The input has `<label for>`, `aria-describedby` pointing at both the hint ("exactly as shown,
   including case and dashes") and the live error region, and `aria-invalid` toggled on refusal.
4. **Enter in the field moves focus to the destructive button** (§7.2) and announces, politely,
   `"Serial entered. The erase button is now focused."`
5. The destructive button's accessible name is its full label, plus
   `aria-describedby` → *"This erases sda permanently. It cannot be undone."*
6. Errors render into a `role="alert"` region so they are announced immediately, and focus returns
   to the input.
7. `Esc` anywhere on this screen activates Cancel. Cancel is safe; the gate is not.

No keyboard shortcut anywhere in the app triggers a destructive action. No `accesskey`. No
`autofocus` on any button, ever.

### 11.3 Colour and contrast

Colour is never the sole indicator: every status carries a glyph **and** a word (`✓ active`,
`⚠ self-signed`, `✗ no DNS`). Capacity bars carry a percentage in text. The phase rail carries state
words, not just colour.

**Design finding — F3 (a real defect in `ui/style.css`, inherited if copied).** The light-mode block
overrides only `--bg`, `--panel`, `--line`, `--text`, `--muted`. It leaves `--danger #e2574c`,
`--ok #56b96b` and `--accent #5aa9e6` at their dark-mode values, which on `#fff` are approximately
**3.6:1**, **2.3:1** and **2.8:1** — all failing AA for body text, and `--ok` failing badly. The
installer leans much harder on red/green semantics than the dashboard does, so this must be fixed
before it is inherited. Recommended light-mode overrides (to be added to `ui/style.css`, benefiting
both surfaces — exact ratios to be re-measured at implementation, not taken from this table):

```css
@media (prefers-color-scheme: light) {
  :root {
    --accent: #1a6fb5;
    --danger: #b3261e;
    --ok:     #1e7a35;
    --warn:   #8a5300;
  }
}
```

Dark mode also needs a new `--warn` (there is none today); `#e0a458` on `--panel #1c1f26` is
comfortably above 4.5:1.

Focus: never `outline: none`. A 2px `--accent` outline with a 2px offset, plus — on the destructive
button only — a 2px `--danger` ring, so focus on *that* button is visibly different from focus
anywhere else.

### 11.4 Motion

Only two animations exist: the 1 Hz liveness pulse and a 120ms panel expand. Under
`prefers-reduced-motion: reduce`, the pulse is replaced by the already-present "last output Ns ago"
counter (which carries the same information, more precisely) and expansion is instant. Nothing
animates for three hours.

### 11.5 Long-running announcements

The install screen must not announce every log line. `aria-live` is on the **liveness panel and the
phase rail only**, `polite`, and rate-limited to one announcement per 30s plus one per phase
transition plus one per overdue escalation. The log pane is `aria-live="off"` with an
`Announce new errors` toggle for operators who want it.

---

## 12. Animations & transitions

| Element | Interaction | Behaviour |
|---|---|---|
| Buttons | hover | `filter: brightness(1.08)`, no transform |
| Buttons | focus | 2px `--accent` outline, 2px offset (destructive: `--danger`) |
| Buttons | active | `filter: brightness(0.92)` |
| Buttons | disabled | `opacity: .6`, `cursor: not-allowed`, and an `aria-describedby` saying *why* |
| DiskCard | hover | border → `--accent` at 40 % |
| DiskCard | selected | 2px `--danger` border + a `WILL BE ERASED` badge; the card grows no taller (no layout shift) |
| Kept-disks panel | selection change | 120ms cross-fade of the list; no slide |
| Disclosure | open/close | 120ms height, `prefers-reduced-motion` → instant |
| Liveness dot | talking | 1 Hz opacity pulse `1 → .35 → 1` |
| Liveness dot | quiet | **static** — the stopped animation is the signal |
| Phase rail | phase completes | the row's duration fades in over 200ms; no confetti, no checkmark animation |
| Route change | any | none. No slide, no fade. A three-hour session should not have transitions. |
| Log | new lines | appended; no highlight flash (a flash on every line of a build log is strobing) |

---

## 13. Design tokens

Inherited verbatim from `ui/style.css`: `--bg --panel --line --text --muted --accent --danger --ok`,
the system font stack, `.4rem`/`.5rem`/`.6rem` radii, `1px solid var(--line)` borders.

New tokens required, to be added to `ui/style.css` so the dashboard and the installer stay one
product:

```css
:root {
  --warn: #e0a458;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
          "Liberation Mono", monospace;

  --sp-1: .25rem; --sp-2: .5rem;  --sp-3: .75rem;
  --sp-4: 1rem;   --sp-5: 1.5rem; --sp-6: 2rem;

  --fill-used: var(--accent);   /* capacity bar, < 80 % */
  --fill-tight: var(--warn);    /* 80–94 %               */
  --fill-full: var(--danger);   /* >= 95 %               */
  --fill-track: var(--line);
}
```

Type scale (rem, `16px` base — nothing below `14px` anywhere): `.875` hint · `1` body · `1.125` card
title · `1.375` h2 · `1.75` h1. Monospace content renders at `.9rem` in cards and `.85rem` in the
log pane, matching `pre.log`.

No new colours beyond `--warn`. No shadow tokens — this design has no shadows.

---

## 14. Component reuse

**Reused from `ui/` unchanged** — these must be the same CSS file, not a copy:

`header` / `nav` · `#status` (role=status, aria-live) · `.hint` · `.error` · `.field` + `label` +
`input` · `button` / `.ghost` / `.danger` · `.row` / `.rows` · `fieldset` / `legend` · `.card` /
`.cards` · `.pill` / `.pill.on` · `table` / `th` / `td` / `tr.current` · `pre.log` / `pre.diff` ·
`dialog.confirm` + `::backdrop` · `details.advanced`.

**Reused from `ui/app.js` as patterns, not copied code:** the `el()` helper, the hash router, the
`setStatus` convention, `localTime()`, and — most importantly — the **SSE attach/reattach pattern**
in `applyView()`, which already solves R1 A4's "reopening rejoins the run in progress". The
installer's progress screen is that pattern with a richer renderer.

**Reused from `ui/api.js` as a pattern:** the single-module API boundary, the `ApiError` shape with
`.status`, and the write-only secret call (`putSecret` posts a raw body and there is no GET) — which
is exactly R2 A3's requirement, already solved once.

**New components (7).** Deliberately few; everything else is composition:

| Component | Why it cannot be composed from existing parts | Reusable elsewhere? |
|---|---|---|
| `DiskCard` | the identification unit; nothing like it exists | — |
| `CapacityBar` | new visual primitive | **yes** — 1.7 R3 A4's per-disk pool fullness is this exact component |
| `KeptDisksPanel` | the negative-space claim | — |
| `SerialGate` | the typed destructive gate | possibly, for a future destructive dashboard action |
| `PhaseRail` | phase + elapsed + sub-steps | **yes** — the dashboard's apply job could use it |
| `LivenessPanel` | the R5 A3 widget | **yes** — the dashboard's apply has the same silent-build problem |
| `LogPane` | `pre.log` with follow-tail, filter, ring buffer | **yes** — a strict upgrade for the dashboard's apply log |

Four of seven are shared wins for the dashboard. That is the argument for building them in `ui/`
rather than inside the installer binary's own asset tree, and for the installer to serve the same
files.

---

## 15. Edge cases

**Disk screen**

- *A 200,000-character model string.* `strip_controls` caps at 64 chars with a visible `...`. The
  browser must not undo this: render the **already-cleaned** value from the library, never re-fetch
  raw `lsblk`. CSS truncation is not a substitute — the cap is a security control.
- *Bidi and control characters.* Already handled by the ASCII-graphic allowlist. The browser adds
  one requirement: **`textContent` only, never `innerHTML`**, for every field originating on the
  target — model, serial, size, fstype, mountpoint, device name, and every log line.
- *A model string that imitates the table's columns.* The space-run collapse handles it in the
  terminal. In the browser the columns are DOM structure, not alignment, so the attack does not
  translate — but the collapse is preserved anyway because the value is shared.
- *5,000 devices.* The 32-device cap holds; the overflow notice is rendered; "Show all" raises it to
  256 with a warning and a filter field. Above 256, the notice is final.
- *One disk only.* The kept-disks panel shows its own empty state rather than disappearing — the
  absence of the panel would itself be ambiguous.
- *A disk with no serial.* Dimmed, focusable, `aria-disabled`, reason stated inline.
- *A disk with no `by-id`.* Selectable (so the operator learns why it fails) but refused at the gate
  with `confirm.rs`'s explanation.
- *Identical model and size on two disks.* This is the dangerous ordinary case — two same-batch
  drives. The card treats serial and mountpoint as the discriminators and, when two cards share a
  model+size, renders a `SAME MODEL AND SIZE AS sdc — check the serial` note on both.

**Progress screen**

- *A three-hour run.* Ring-buffered DOM, no unbounded arrays, no growing animation state. Elapsed
  counters derive from timestamps rather than incrementing, so a laptop that slept is correct on
  wake.
- *The laptop sleeps.* On `visibilitychange` → visible, the browser re-reads job state rather than
  trusting its in-memory copy, and the banner reads *"You were away for 47 minutes. Catching up."*
- *A step produces no output at all.* The log pane says so explicitly rather than looking broken.
- *Output arrives faster than render.* Batch DOM writes on `requestAnimationFrame`; drop nothing
  (the full log is on disk regardless).
- *Clock skew between browser and installer.* All durations are computed by the installer and sent
  as durations, not as absolute timestamps to be subtracted client-side.

**Done screen**

- *Zero apps enabled.* The app table shows an explicit "no apps were enabled" state; the verdict
  headline still distinguishes reachable from not.
- *A very long domain or app name.* Hostnames truncate with a middle ellipsis and a `title`; URLs
  are always also present in full in the copyable link.
- *Credentials for a run that already ended.* Values are not re-fetchable; the panel shows the
  on-host paths and says the values are readable there.
- *Every certificate self-signed.* Red verdict, and a single top-level `Retry every certificate
  order` in addition to the per-row buttons.

**Everywhere**

- *Permission variations.* There is exactly one role — the operator holding the URL token. There is
  no permission-gated UI, and there must not be, because a partially-authorised installer is a
  confusing installer.
- *No JavaScript.* Not supported, and says so in a `<noscript>`: *"This installer needs JavaScript.
  The terminal installer is a fully supported alternative: `ferrum-install --help`."* (R1 A3.)
- *The token is missing or wrong.* A bare page: *"This URL is missing its access token. Copy the
  whole URL that the installer printed."* No login form — there is no password to guess, and
  offering a field implies there is.

---

## 16. Design decisions

| # | Decision | Alternative rejected | Why |
|---|---|---|---|
| D1 | Phase rail with per-phase elapsed; **no overall percentage** | a progress bar | The steps span three orders of magnitude. A bar stuck at 40 % for 25 minutes reproduces the exact failure this phase exists to fix. |
| D2 | Liveness is a **separate signal** from output, with its own probe and its own "last alive" clock | inferring liveness from output | "No output" is the symptom the three-hour bug presented as. Distinguishing them requires an independent probe; there is no way around it. |
| D3 | A stopped pulse means quiet; a running counter means alive | a spinner | A spinner spins identically whether the process is building or dead. It is the least informative widget available here. |
| D4 | Full-width stacked disk cards | a table, or a card grid | A table is what the terminal already does. A grid invites comparison by position; the operator must compare by label, because a label is what they will type. |
| D5 | The capacity bar is the headline addition | showing size only | It is the one thing the terminal cannot show, it answers "which one has my media on it" pre-verbally, and it is reused verbatim for 1.7 R3 A4. |
| D6 | No radio pre-selected, ever | pre-selecting `propose()`'s suggestion | `confirm.rs` is explicit that the suggestion is not a default. A checked radio is a default however it is labelled. |
| D7 | Kept-disks panel is live and never collapsible | a "show other disks" link | R4 A2 gives the second list equal weight. A collapsed list has none. |
| D8 | Confirm screen renders the **same** `DiskCard` component | a summary line | Recognition, not recall. A summary makes the operator confirm against remembered facts. |
| D9 | Enter in the serial field moves focus rather than submitting | native form submit | Enter-after-typing is the reflex the gate exists to defeat. One deliberate extra keystroke; visible focus movement. |
| D10 | No live match feedback; validate on submit | a green tick on match | A green tick rewards fiddling and converts a gate into a puzzle. `match_serial`'s refusal teaches; a tick does not. |
| D11 | **Except** a live warning when the typed serial belongs to a *different* disk | waiting for submit | This is the wrong-disk case. It is the only thing the gate genuinely protects against, and it must not wait. |
| D12 | Paste is allowed; no copy button on the confirm screen | blocking paste | Blocking paste is unenforceable and pushes operators to transcribe from a screenshot — strictly worse. The gate's value is that a typo refuses. |
| D13 | Credentials shown in plain text with their on-host paths | masked behind a reveal | R6 A1's actual incident was an operator locked out, not a shoulder-surf. The on-host path is the durable mitigation. |
| D14 | `Service` / `Reachable` / `Certificate` as three columns | one status per app | R6 A3 says these are different claims. Merging them into a tick is the failure mode, structurally prevented. |
| D15 | A self-signed certificate turns the whole verdict red | a warning badge | R6 A4 and 1.7 R5. A run that reported success while serving `CN=minica root ca` is the evidence. |
| D16 | The "needs you" empty state is celebrated, not omitted | hiding the empty section | That empty list *is* the product. Seeing it empty is the moment the operator learns ferrum is different from Saltbox. |
| D17 | One persistent target-state ribbon instead of per-screen prose (F1) | six paragraphs | One binding to `Phase`; cannot drift; cannot be missed. |
| D18 | No route transitions, no decorative motion | polished slide transitions | The operator may be looking at this for half an hour. Calm is a feature. |
| D19 | Build the seven new components in `ui/`, served by both binaries | a separate asset tree in the installer | Four of the seven are direct upgrades for the dashboard, and the requirement "they must look like one product" is far easier to keep true if they *are* one stylesheet. |
| D20 | Log defaults to no-wrap with a toggle (wrap on below 640px) | always wrap | Nix store paths are 60+ characters. Wrapping turns a scannable column into a wall of text. |

### Design findings that touch the requirements

| ID | Finding | Recommendation |
|---|---|---|
| **F1** | R3 A2 ("every screen states what has and has not happened") implemented per-screen will drift | One persistent ribbon bound to `Phase`. Stronger and cheaper. |
| **F2** | R5 A3/A4's liveness probe, quiet threshold, plausible window and **retry count** must live in the library, not the browser | Add a `Step { id, label, quiet_threshold, plausible_window, liveness_probe, attempt_count }` descriptor to the shared event stream. Otherwise the terminal path (R1 A3, supported not deprecated) keeps the three-hour failure mode while the browser fixes it. **This is the highest-value change in this document.** |
| **F3** | `ui/style.css`'s light-mode block does not override `--danger`, `--ok`, `--accent`; on white they are roughly 3.6:1, 2.3:1, 2.8:1 — all fail AA, `--ok` badly. There is no `--warn` at all. | Fix in `ui/style.css` (§11.3) before the installer inherits it. This is a live accessibility defect in the shipped dashboard, not only a design note. |
| **F4** | R4 A2's "without scrolling" is unsatisfiable on a short window with many disks | Amend A2: the kept-disks list is never collapsed or truncated, and where it overflows, the gate is placed *below* it so reaching the gate requires scrolling past every surviving disk. |
| **F5** | R2 A2's token in the printed URL will be in browser history, and the done screen links out to `plex.tv/claim` | Put the token in the URL **fragment** (never sent to the server, never in a `Referer`), exchange it once for a session cookie on load, then `history.replaceState` it away. Add `rel="noopener noreferrer"` to every external link. |
| **F6** | R6 A3's status has three independent dimensions, but `verify.rs` returns a flat `Check` list | Have the browser render `Check` results directly, keyed by app and dimension, rather than reinterpreting them. Two renderers agreeing by construction beats two renderers agreeing by review. |
| **F7** | OQ1 (Plex claim token at the point of use) | **Yes.** §6.3.4. The browser is the only front-end that can hold a form open and re-prompt on a four-minute expiry; doing it here is strictly better than the terminal equivalent. |
| **F8** | OQ2 (surface the 1.7 DNS work) | **Yes, on the plan screen**, as a dry-run table: which records will be created, which already exist and point elsewhere (1.7 R1 A3/A7). It is the same `RefusalPanel`/table machinery and it prevents the silent-overwrite class. |
| **F9** | OQ3 (dry-run mode) | **Yes, and it is nearly free.** Every screen here is fed from a data shape; a fixture set drives the whole flow to the gate and stops. It makes this feature's own testing possible, gives the owner something to show, and is the only way to exercise the "eight disks on a short window" layouts without eight disks. |

---

## Self-review

- [x] Every screen has loading, empty, error and data states (§9).
- [x] Every interactive element has hover, focus, active and disabled states (§12).
- [x] Every form has validation rules and error placement (§7).
- [x] Responsive behaviour at <640 / 640 / 768 / 1024 / 1280 (§10), including the honest treatment of
      the one requirement that cannot be met literally (F4).
- [x] Touch targets ≥44px below 768px; disk cards are whole-card click targets (§10).
- [x] Contrast reviewed against `ui/style.css`'s real values — and a failing case found and fixed
      (F3). Exact ratios to be re-measured at implementation.
- [x] Keyboard path documented keystroke by keystroke through the destructive gate (§11.2).
- [x] ARIA on every interactive element, including character-by-character serial announcement and
      rate-limited live regions for a three-hour run (§11).
- [x] Existing `ui/` components reused rather than reinvented; only 7 new components, 4 of which are
      shared wins for the dashboard (§14).
- [x] Tokens taken from `ui/style.css`; the three new ones are justified and additive (§13).
- [x] Edge cases: hostile `lsblk` fields, 5,000 devices, one disk, identical drives, three-hour runs,
      sleeping laptops, no JavaScript, missing token (§15).
- [x] No section is TBD.

### What this spec does *not* establish

Nothing here has been rendered in a browser. The ASCII sketches are layout intent, the contrast
figures in F3 are estimates that must be re-measured with a real checker, and the per-step plausible
windows in §6.2.3 are starting values derived from the 1.6a run's evidence, not measurements across
hardware. Treat all three as design decisions to be verified, not as verified facts.
