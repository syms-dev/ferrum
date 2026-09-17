# Phase 1.6a — pull and install

*Status: DRAFT, planning gate open. No implementation code until the panel
resolves.*
*Pipeline run `f81bafcf-bc88-4ba8-805f-2cfca8e884f1`, Mode B.*

## Why

`docs/INSTALL.md` is 311 lines across eight steps. A new user must identify
disks by `/dev/disk/by-id/`, determine the firmware boot mode, copy a
template into a fresh git repository, hand-edit eleven `CHANGE-ME` values
across four files, generate `hardware-configuration.nix`, **install once
with an empty `apps` block**, keep a second `settings.stage2.json`
alongside, dry-run, VM-boot-test, install, verify `/etc/ferrum` ownership by
hand, and only then swap in the real settings and apply again.

The Phase 1 design doc says *"the user never installs NixOS themselves"*.
That is true of NixOS and false of everything around it: the user authors
the entire host flake by hand. It also says the install path is *"the thing
most likely to rot"*, and its own postmortem records that the first real
install found ten defects, **six of which no VM test could see**, because
*a test that never acts like a human never finds what a human hits*.

This phase replaces the eight manual steps with one command.

## Decisions taken before this spec (by the owner, 2026-09-17)

- **DEC-A — sequencing.** The install path comes before the Phase 1.6
  updates work. The updates spec
  (`2026-09-16-phase-1-6-updates-design.md`) stays closed, its planning
  register resolved and both spikes passed; nothing in it is discarded.
- **DEC-B — delivery vehicle.** The installer ships as a **Docker image**.
  It requires only Docker on the operator's machine, which is the actual
  constraint on this project's own workstation (no native `nix`). A
  `nix run` entry point is out of scope for 1.6a.
- **DEC-C — scope.** Full end-to-end: detect → confirm → generate → preflight
  → install → stage 2 → verify → report. One command from bare metal to a
  working host.

## Requirements

### R1 — one command, from the operator's machine

**User story.** As someone who has never used Nix, I run one command against
a machine I can SSH into as root, answer a short set of questions, and end
up with a working ferrum host.

    docker run --rm -it \
      -v ~/.ssh:/ssh:ro \
      -v ~/ferrum-host:/host \
      ghcr.io/syms-dev/ferrum-install root@192.168.2.50

**Acceptance criteria.**
- A1. The image contains everything needed: `nix`, `nixos-anywhere`, `disko`,
  `openssh`, and the `ferrum-install` binary. No tool is required on the
  operator's machine except Docker.
- A2. The image is built by Nix (`dockerTools.buildLayeredImage`) from this
  repository, so its contents are pinned by `flake.lock` rather than by a
  Dockerfile's `apt-get`.
- A3. Running it with no target argument prints usage and exits non-zero
  without contacting anything.
- A4. `~/ferrum-host` (the `/host` mount) receives the generated host
  repository and it **survives the container**. The operator owns that
  repository afterwards; it is not ephemeral.
- A5. The SSH key is mounted read-only and is never copied into any image
  layer, log line, or generated file.

**Edge cases.** The `/host` directory already contains a host repository →
see R7 (resume). The mount is missing → refuse before contacting the target,
naming the missing mount. The SSH key is passphrase-protected → forward the
operator's agent (`SSH_AUTH_SOCK`) rather than reading the key; if neither a
usable key nor an agent is present, refuse before contacting the target.

### R2 — detect the target, and make the operator approve an inventory

**User story.** As an operator, I am shown exactly what the installer found
on the machine and exactly which disk it is about to destroy, and nothing
destructive happens until I confirm that specific disk.

This is the **restricted** requirement of this phase. disko repartitions
unconditionally: no merge, no preserve, no prompt. A wrong disk here is
unrecoverable data loss, and the protection today is entirely structural
(a disk not named in `disko.nix` is never opened).

**Acceptance criteria.**
- A1. The installer SSHes to the target and collects, in one pass:
  `lsblk -O --json` (name, size, model, serial, fstype, mountpoint, uuid),
  `ls -l /dev/disk/by-id/`, the firmware mode from
  `[ -d /sys/firmware/efi ]`, the current IP and whether it came from DHCP,
  and the CPU architecture.
- A2. It renders an inventory naming **every** block device with its size,
  model, serial, stable `by-id` path, and the filesystems currently on it.
- A3. It proposes an OS disk but **never** defaults to it. The operator must
  type the disk's serial (not "y", not a menu index) to proceed. A typo is a
  refusal, not a different disk.
- A4. `by-id` paths are always the `model_serial` form. `-part<N>` and
  `wwn-` aliases are filtered out of both the proposal and the accepted
  input.
- A5. **`/sys/firmware/efi` is authoritative.** The `vfat` signal is
  corroboration only, and only when the chosen disk is non-blank. The rule is
  a truth table with exactly one outcome per input:

  | `/sys/firmware/efi` | chosen disk | `vfat` present | outcome |
  |---|---|---|---|
  | present | blank/wiped | (irrelevant) | **UEFI** |
  | present | non-blank | yes | **UEFI** |
  | present | non-blank | no | **stop and report** — conflicting signals |
  | absent | any | no | **BIOS** (GPT + `EF02` + GRUB) |
  | absent | any | yes | **stop and report** — conflicting signals |

  The earlier "no vfat anywhere ⇒ BIOS" heuristic is **deleted**. It is
  `docs/INSTALL.md`'s rule for an *already-installed* machine, whose premise
  ("a UEFI machine cannot boot without an ESP") is false for the blank or
  live-booted target this phase exists to install. Importing it would
  silently generate an unbootable BIOS host on a genuinely UEFI machine —
  the design doc's "the template assumed UEFI" defect, inverted.
- A6. Every disk the operator did not name is **absent from the generated
  `disko.nix`**. The structural protection is preserved, not replaced by a
  runtime check.
- A7. The approved inventory is written to the host repository as
  `install-inventory.json` before anything destructive runs, and the
  post-install verification re-reads it (R6 A4).
- A8. **A serial is only an identifier if it is unique and non-empty.** The
  installer refuses when the inventory contains an empty serial, or two
  devices answering to the same one, naming the colliding devices and
  requiring the full `by-id` path instead. Empty and duplicate serials are
  ordinary on virtio devices, USB bridges that report the enclosure's serial,
  and same-batch drives.
- A9. **The approved device is re-verified at the last safe moment.** Inside
  the kexec'd installer, immediately before disko runs, the approved `by-id`
  path is re-resolved and its serial re-compared against
  `install-inventory.json`; a mismatch aborts before any write. kexec loads a
  different kernel with a different driver set, and that is the one moment
  device enumeration can legitimately change.

**Edge cases.** One disk only → still requires typed confirmation. No
`/dev/disk/by-id/` entry for the chosen device (some virtio setups) → refuse
and name the device, rather than falling back to `/dev/sdX`. The target has
a mounted filesystem on the chosen OS disk → report what is mounted as part
of the inventory. Target is not `x86_64-linux` → refuse; the catalog is not
built for anything else.

### R3 — generate the host repository, with no CHANGE-ME left

**User story.** As an operator, I never open a `.nix` file.

**Acceptance criteria.**
- A1. The installer asks for, or derives: hostname, base domain, ACME email,
  **the SSO admin email (see R9)**, **the Cloudflare DNS-01 API token**, SSH
  public key(s), which catalog apps to enable, and the data disks to mount (from the R2 inventory, by `by-id`,
  with their existing filesystem type detected rather than asked).
- A2. It writes a complete host repository into `/host`: `flake.nix`,
  `disko.nix`, `settings.json`, `custom/media.nix`. `hardware-configuration.nix`
  does not exist yet — it is produced during R6's install and committed back
  then (R6 A2).
- A3. **No generated file contains any placeholder sentinel** — `CHANGE-ME`,
  `example.invalid`, `YOUR-USER`, or `AAAA...`. Asserting only `CHANGE-ME`
  would be structurally blind to `settings.json`, whose placeholders are
  `example.invalid`; an unresolvable domain reaching a real host means ACME
  issuance fails against a name that does not exist. The installer asserts
  this itself before the preflight, not the operator.
- A4. It runs `git init && git add -A && git commit` in `/host`. Nix silently
  ignores untracked files inside a git tree, so an untracked `disko.nix`
  fails during install with a message that names the wrong cause.
- A5. `ferrum.url` is pinned to a **specific revision**, never a branch. The
  revision is the one the installer image itself was built from, so the
  installed host and the installer provably agree.
- A6. The data-disk mounts go in `custom/media.nix`, never in `disko.nix` —
  a mistake there costs a failed mount instead of a wiped drive.
- A7. **The generated `disko.nix` reproduces the fixed btrfs subvolume layout
  verbatim** — `@root`, `@nix`, `@state`, `@snapshots`, with their mount
  options — differing from `examples/hosts/template/disko.nix` only in the
  device name and the firmware branch. These names are load-bearing, not
  cosmetic: `crates/ferrum-apply/src/restore_state.rs` hardcodes `@state`,
  and `modules/core/state-restore.nix` asserts `@snapshots` is on the same
  btrfs volume. A generated layout that drifts here produces a host that
  installs, boots, and **silently cannot roll back** — the one property
  ferrum exists to provide.

- A8. **The Cloudflare token is collected up front and delivered at stage 2
  through a new `ferrum-apply put-secret` subcommand.** Naming the mechanism
  matters: an earlier draft of this criterion said the token is delivered "so
  `ferrum-apply` can encrypt it", which **described a capability that does not
  exist**. `ferrum-apply`'s subcommands are exactly `Preflight | Apply |
  Rollback | RestoreState | Gc | RunRequest | PreviewMigration`
  (`crates/ferrum-apply/src/main.rs:20-43`), and every function in
  `secrets.rs` *generates* a value it invents — `ensure_all`,
  `ensure_authelia_secrets`, `ensure_first_authelia_user`,
  `ensure_sabnzbd_apikey`. There is no operator-value ingestion anywhere;
  `modules/core/secrets.nix:15-17` records it as "a later ferrumd change".

  So this phase adds one, **declared as new implementation surface rather than
  assumed**: `ferrum-apply put-secret <name>`, reading the value from stdin
  and encrypting it to the host's own age recipient with the encrypt path
  `secrets.rs` already has. It is preferred over the two existing routes
  because ferrumd's `POST /api/secrets/:name` sits behind `require_session`
  **and** CSRF and would make the installer hold a web session over an SSH
  tunnel, and because the manual `sops`/`ssh-to-age` procedure depends on
  binaries that exist on the host only inside `ferrum-apply`'s own wrapper
  PATH (`nix/pkgs/ferrum-apply/default.nix:21`).
- A8b. **Three details an implementer would otherwise get wrong**, all from
  `README.md:78-94`: the plaintext is the env-file line
  `CLOUDFLARE_DNS_API_TOKEN=<token>`, **not the bare token**, because it is
  consumed as a systemd `EnvironmentFile=` (`modules/proxy/acme.nix:98-106`);
  the stage-2 `settings.json` must also **declare** `"acme-dns"` in its
  `secrets` map, or `credentialProvided` is false and `acme.nix:52` fires even
  with the file present; and the write must happen **before** the stage-2
  `nix build` (`apply.rs:220`), because `acme.nix:63-71` additionally asserts
  the `.sops` file exists at evaluation time.
- A8c. The token is held in memory only, written to no file on the operator's
  machine, and appears in no log line.
  `modules/proxy/acme.nix:52` asserts `publicApps == { } || credentialProvided`,
  and `dnsProvider` is an enum of exactly `["cloudflare"]`
  (`modules/core/options.nix:109-118`). Because `exposure` defaults to
  `public` whenever the proxy is on, **the default install path hits that
  assertion** — an installer that never asks for the token cannot complete a
  default install. It is nonetheless a *stage-2* artifact, not a stage-1 one:
  the token must be encrypted to the host's own age recipient, which is
  derived from the host's SSH key, which does not exist until the host does.
  The installer therefore delivers it during R4's stage 2, per A8b's ordering.

**Edge cases.** The operator enables no apps → valid; produces a bare host
with just the daemon, and the token is not required. A hostname that is not a valid DNS label → reject at
input. A base domain with no `ferrum.proxy.enable` → the daemon is
loopback-only and the installer says so in its final report.

### R4 — the two-stage bootstrap is the installer's problem, not the operator's

**User story.** As an operator, I say which apps I want once, at the start,
and the installer deals with the fact that they cannot be enabled on the
first build.

The constraint is real and documented in `modules/core/secrets.nix` and
`nix/modules/flake/checks.nix`: every app **that declares a sops secret**
(prowlarr, qbittorrent, radarr, sabnzbd, sonarr — verified at HEAD; jellyfin
and plex declare none)
and sops-nix requires each `sopsFile` to be a Nix path pointing at a file
that **physically exists at evaluation time**. On a machine being installed
from nothing, `/etc/ferrum/secrets/` does not exist and neither do those
files — they are generated by `ferrum-apply` on the host, on its first
apply, encrypted to the host's own SSH key, which cannot exist before the
host does.

**Acceptance criteria.**
- A1. Stage 1 installs with `settings.json` = `{"schemaVersion": 1,
  "apps": {}}` plus the proxy/domain/ACME configuration. The operator's real
  app selection is held as `settings.stage2.json` in the host repository.
- A2. **The host repository is transferred to the target as part of the
  install**, via `nixos-anywhere --extra-files`, landing at `/etc/ferrum`
  root-owned with its `.git` intact, every file tracked, and the working tree
  clean. Nothing in the module tree does this today:
  `modules/core/bootstrap.nix` creates only the directory, `settings.json`,
  `secrets/` and `custom/` through tmpfiles, and `nixos-anywhere` installs a
  closure, not a source tree. **`docs/INSTALL.md` has the same hole** — its
  Step 8 tells the operator to edit "the host flake repo" on the target,
  which no earlier step ever put there. Without this, stage 2 cannot run at
  all, because `ferrum-apply` resolves `FERRUM_FLAKE_REF` to
  `/etc/ferrum#nixosConfigurations.<hostname>`.
- A2b. **The installer repairs `/etc/ferrum/settings.json`'s ownership after
  first boot, before R6 A3 asserts it.** `--extra-files` copies files
  **root-owned** ("Copied files will be owned by root unless specified by
  `--chown`"), and it cannot do better by name, because the `ferrum` group
  does not exist yet at copy time. The tmpfiles rule will not repair it
  either: `modules/core/bootstrap.nix:91` is
  `C /etc/ferrum/settings.json 0664 root ferrum`, and `C` copies **only if
  the path does not already exist**, so after a transfer it is a permanent
  no-op that never corrects group or mode. The only other code that looks at
  this (`bootstrap.nix:112-119`) merely *warns*. Left unfixed, `ferrumd`
  cannot write settings.json and the dashboard renders correctly while
  silently saving nothing — a failure mode this project has already shipped
  once. So: `chown root:ferrum /etc/ferrum/settings.json && chmod 0664`, over
  SSH, immediately after first boot — and **again after A3's stage-2 write**,
  since whether ownership survives depends on the copy mechanism (an in-place
  truncating write preserves owner and mode; a temp-file-plus-`mv` or
  `install` resets it to `root:root`). R6 A3 asserts the final state either
  way, so a regression here is loud rather than silent.
- A3. The installer then copies the stage-2 settings over
  `/etc/ferrum/settings.json`, **delivers the Cloudflare token (R3 A8) so
  `ferrum-apply` can encrypt it to the host's age recipient**, commits, and
  runs the stage-2 apply. The commit is a **no-op on a second attempt** — git
  has nothing to commit when the content already matches — so a resume that
  re-enters here is safe to repeat.
- A3b. **The stage-2 apply passes every stage-1-derived variable explicitly.**
  This is possible only because `modules/core/overlays.nix:154` uses
  `--set-default`, not `--set` — the caller's environment wins over the value
  baked in at build time.

  **The rule, stated once:** the installer writes stage-1 `settings.json` as
  the stage-2 document *minus* `apps` and *minus* `auth`. Therefore **exactly
  those wrapper variables derived from `ferrum.apps.*` or `ferrum.auth.*`
  differ between the stages, and all of them must be overridden.** Walking
  `overlays.nix:168-183` in full, that is five of fourteen:

  | Variable | Derived from | Consumer | Failure if not overridden |
  |---|---|---|---|
  | `FERRUM_SERVARR_APPS` | `enabledServarrApps` (`overlays.nix:54-56`) | `main.rs:165` | Baked empty. `unwrap_or_else` fires only when **unset**, so an empty string survives to `.filter(\|s\| !s.is_empty())` → empty list → `ensure_all` generates nothing → sonarr/radarr/prowlarr `sopsFile` missing at eval. |
  | `FERRUM_AUTH_ENABLED` | `auth.enable` (`:179`) | `main.rs:174` | `ensure_authelia_secrets` skipped (`apply.rs:206`) → both Authelia `sopsFile`s missing. |
  | `FERRUM_ADMIN_EMAIL` | `auth.adminEmail` (`:181`) | `main.rs:181` | Empty → `ensure_first_authelia_user` has no address for the generated user. |
  | `FERRUM_SABNZBD_STATE_DIR` | `apps.sabnzbd.*` (`:182`) | `main.rs:182` | Baked `""` → `.filter(!is_empty)` → `None` → `ensure_sabnzbd_apikey` skipped (`apply.rs:210`), while `modules/apps/sabnzbd/service.nix:36` declares the `sopsFile` unconditionally. |
  | `FERRUM_SABNZBD_PORT` | `apps.sabnzbd.port` (`:183`) | `main.rs:186` | Falls back to `8080`; a host whose sabnzbd runs elsewhere gets the wrong port written into its ini. |

  The other nine (`STATE_DIR`, `SNAPSHOT_DIR`, `JOURNAL_DIR`, `MIN_FREE_GIB`,
  `FLAKE_REF`, `KEEP_GENERATIONS`, `HEALTH_CHECK_TIMEOUT_SEC`, `SECRETS_DIR`,
  `HOST_KEY_PUB`) derive from storage/host configuration identical in both
  stages, and `AUTHELIA_STATE_DIR` is a hardcoded literal. They need no
  override — but the rule above, not this list, is what a future phase
  applies: **adding any `--set-default` derived from `apps.*` or `auth.*`
  adds a row here.**
  **This commit is a bounded exception to DA-5** (the sibling updates spec's
  decided rule that ferrum tooling never commits in `/etc/ferrum`, because
  "that tree is theirs"). The exception holds only because it happens once,
  during bootstrap, *before the operator owns the tree* — there is no
  operator work to clobber yet. After `stage2-applied` the rule resumes in
  full and no ferrum tool commits there again. The installer asserts the tree
  is clean before committing and refuses if it is not.
- A4. The operator is never asked to perform, name, or understand the swap.
- A5. After stage 2 the host repository in `/host` contains the **stage-2**
  `settings.json` as the tracked file, so a later reinstall from the same
  repository is not silently app-less. `settings.stage1.json` is retained for
  provenance.
- A6. If stage 2 fails, the machine is already installed and reachable. The
  installer reports that distinction explicitly — "the host is installed;
  enabling apps failed" — and R7's resume re-enters at stage 2.

**Edge cases.** The host takes a long time to come up → A2 polls for the
observable condition (SSH answers, then `ferrumd` is active), never a fixed
sleep, with a stated timeout and a clear message on expiry. An app's
secret generation fails → stage 2 fails loudly; the host is intact.

### R5 — a two-tier preflight, each tier where it can actually run

**User story.** As an operator, the installer proves the configuration is
sound before it destroys anything — and it does not lie to me about which
kind of proof it managed.

The original single-tier version of this requirement was **not implementable**.
It demanded a real `x86_64-linux` VM build *before* the destructive step —
that is, before kexec, when the target still runs its original OS and no
x86_64 Nix builder exists anywhere in the system. `--build-on remote` cannot
help: it works precisely because nixos-anywhere has already kexec'd the target
into an installer environment with a working Nix daemon. So the proof is split
by what each moment can actually support.

**Tier 1 — operator-side, every run, unskippable. Evaluation, not building.**
- A1. `nix eval` / `nix build --dry-run` of
  `.#nixosConfigurations.<host>.config.system.build.toplevel` against the
  generated repository. This needs **no builder** and catches every evaluation
  error: a bad option, a missing file, a malformed `settings.json`, a sops
  path that does not exist. A failure stops the run with the real Nix error
  and the target untouched.
- A2. The placeholder assertion (R3 A3) and an assertion that the flake's
  `nixosConfigurations` attribute name equals `networking.hostName`.
- A3. **The R9 authentication assertion**: no app resolves to
  `exposure = "public"` while `ferrum.auth.enable` is false, unless the
  operator passed R9's second confirmation.
- A4. Tier 1 is not skippable by a flag. If it were, it would be skipped.
- A5. Failures are reported with the failing command and its real output,
  never a summarised "build failed".

**Tier 2 — CI-side, on every change to this repository, not on every install.**
- A6. The full build-and-boot proof lives in CI, on a KVM-capable Linux
  runner, as R8's install-from-nothing test. That is where it belongs: the
  design doc's concern is that *the install path rots between releases*, which
  is a property of the repository, not of any one operator's laptop. A green
  CI run is what licenses a release; re-proving it on every operator's machine
  buys nothing and is impossible on Docker Desktop for macOS, which exposes no
  `/dev/kvm`.
- A7. The installer's final report states plainly which tier ran: "evaluation
  verified; boot verified by CI for this revision". It never implies it booted
  the configuration when it did not.

**Edge cases.** A cold Nix store makes Tier 1 slow → report progress; do not
add a timeout that turns a slow first run into a failure. A revision whose CI
boot proof is absent (a dirty or unreleased ferrum ref) → say so in the report
rather than claiming a proof that does not exist.

### R6 — install, verify, and report something the operator can act on

**User story.** When the installer finishes, I am told the URL, the password,
and that it actually checked.

**Acceptance criteria.**
- A1. The install is a single `nixos-anywhere --generate-hardware-config
  nixos-generate-config ./hardware-configuration.nix --flake .#<host>
  root@<target>` invocation. `--generate-hardware-config` is used always, so
  the target is not required to already run NixOS (Step 3's fork disappears).
- A2. The generated `hardware-configuration.nix` is committed back into
  `/host`, so the repository the operator keeps is the one that built the
  machine.
- A3. After first boot the installer asserts, over SSH:
  `/etc/ferrum/settings.json` is `root:ferrum 0664`; `/etc/ferrum/secrets/`
  is `ferrum:ferrum 0750`; `/etc/ferrum/custom/` is `root:root 0755`;
  `ferrumd` is active; `ferrum-apply` resolves on `PATH` **as a bare
  command** — the operator's own interface, which is precisely how three of
  the first install's ten defects were found.
- A4. It re-reads `install-inventory.json` and asserts every data disk named
  there is mounted with the filesystem the inventory recorded. A data disk
  that failed to mount is a **loud** failure, not a missing directory
  discovered weeks later.
- A5. The final report prints: the host's IP and hostname, the UI URL, **both
  one-time credentials**, each enabled app's URL with its certificate status,
  and the path to the host repository the operator now owns. There are two
  credentials, not one: `ferrumd-setup-password` (generated by
  `ensure_first_user` in `crates/ferrumd/src/auth.rs`, written to
  `/var/lib/ferrum/daemon/ferrumd-setup-password`, mode 0400 — root can read
  it over SSH without weakening its mode), and, whenever R9 enabled SSO,
  `authelia-setup-password`, written at mode 0400 by `ferrum-apply` during
  the very stage-2 apply R4 performs. Printing only the first would report
  success while leaving the operator locked out of every app.
- A6. Each credential is printed exactly once, to the terminal, and appears
  in no file the installer writes.
- A7. Certificate issuance is **reported per app, never assumed**. Each
  `public` app requests its own certificate and Let's Encrypt rate-limits per
  registered domain, so a seven-app install issues **eight** certificates
  (the `auth.<domain>` vhost has its own) and a
  re-run or a second machine on the same domain can exhaust the quota. A
  build-time check cannot catch a runtime quota, so the installer reports what
  actually happened.
- A8. It asserts `authelia-main.service` is active and its users database
  exists whenever SSO is on.

**Edge cases.** A DHCP address that differs from the pre-install address →
reported explicitly, since the doc warns a static-addressed machine comes
back elsewhere. `ferrumd` active but not answering → reported as such.

### R7 — resumable, because the destructive step is not the last step

**User story.** If something fails after the disk is wiped, re-running the
same command does not wipe it again.

**Acceptance criteria.**
- A1. The installer records its progress in `/host/install-state.json` with
  an explicit phase: `generated`, `preflight-passed`, **`installing`**,
  `installed`, `stage2-applied`, `verified`.
- A1b. **`installing` exists because the wipe happens *inside* the
  `nixos-anywhere` invocation, before it returns.** Without that phase, a
  crash after disko but before nixos-anywhere completes leaves the disk gone
  while the state file still reads `preflight-passed` — an unrecorded
  destructive action, which is exactly the boundary this requirement exists
  to protect. The phase is written *before* the invocation starts.
- A1c. Every phase transition is written **atomically** — temp file, fsync,
  rename — so there is never a real destructive action with no record of it.
- A1d. Resuming from `installing` re-invokes `nixos-anywhere` **without** a
  fresh typed confirmation (R2 A3): the named disk is already gone, so
  re-confirming protects nothing and only trains the operator to retype.
  Resuming from `preflight-passed` does require it, since nothing was
  touched.
- A2. Re-running with an existing `/host` resumes at the first unreached
  phase and says so. It never repeats `nixos-anywhere`.
- A3. Re-running past `installed` requires no disk confirmation, because no
  disk is touched.
- A4. Starting over from scratch is explicit (`--fresh`) and re-runs R2's
  typed confirmation in full. It is never implied by a stale directory.
- A5. `install-state.json` recording `installed` while the target does not
  answer SSH is reported as a conflict for a human, not silently re-installed.

### R8 — the installer is itself tested from nothing

**User story.** As the maintainer, the install path does not rot, because
something exercises it the way a human does.

The design doc's own conclusion: *"Install-from-nothing is its own test
target. Every VM test starts from a built host, so nothing before that point
was covered until a real machine."*

**The harness constraint, stated up front.** Every existing VM test is a
sandboxed `pkgs.testers.runNixOSTest` with **no network and no in-guest
nixpkgs evaluation**. `tests/daemon-apply-end-to-end.nix` works around that by
injecting a pre-built closure via `virtualisation.additionalPaths` and
pointing a fixture flake at `builtins.storePath`. **That trick cannot work for
stage 2**, because stage 2 exists precisely so the `sopsFile` is created at
runtime on the guest — the stage-2 closure cannot be pre-built. So the test
target splits by what the sandbox can hold.

**Acceptance criteria.**
- A1. **Sandboxed, in `nix flake check`:** a two-node `runNixOSTest` where one
  node runs `ferrum-install` against a peer whose disk starts blank, covering
  `generated` → `preflight-passed` → `installed`. It asserts R6 A3's checks on
  the result: `/etc/ferrum/settings.json` is `root:ferrum 0664`, `secrets/` is
  `ferrum:ferrum 0750`, `custom/` is `root:root 0755`, `ferrumd` is active,
  and `ferrum-apply` resolves **as a bare command on `PATH`** — the
  operator's own interface, which is how three of the first install's ten
  defects were found.
- A2. **Networked, KVM-capable CI job, separately gated:** the same install
  continued through stage 2 with **`sonarr` enabled** — a secret-declaring app.
  Naming matters: `jellyfin` and `plex` declare no sops secret at HEAD, so
  "at least one real catalog app" would otherwise be satisfiable by an app
  that exercises **none** of the two-stage bootstrap this criterion exists to
  cover. This job is also R5 Tier 2's boot proof.
- A3. **Rollback still works on an installer-generated host.** The test takes
  a generation, changes a setting, applies again, and rolls back, asserting
  the system closure *and* the application state both revert. This is what
  catches a generated `disko.nix` that drifted from the `@root`/`@nix`/
  `@state`/`@snapshots` layout (R3 A7) — a defect that would otherwise
  install, boot, and look perfectly healthy.
- A4. **Resume after a partial install is tested.** `nixos-anywhere` is killed
  mid-run, after disko and before completion, and the test asserts a resume
  re-invokes it without re-requesting disk confirmation and reaches a working
  host. This is the exact scenario R7 exists for and nothing currently proves
  `docs/INSTALL.md`'s "Recovering a failed install" claim, which that document
  itself asserts without demonstration.
- A5. The R2 guards are **mutation-tested**: a wrong serial refuses; a
  duplicate or empty serial refuses (R2 A8); the post-kexec re-verification
  aborts on mismatch (R2 A9). Deleting each check must make a test go red. A
  guard whose test passes when the guard is deleted is not a guard.
- A6. `ferrum-install`'s pure logic — inventory parsing, `by-id` alias
  filtering, the R2 A5 firmware truth table, host-repository rendering, state
  transitions — is unit-tested without touching a network or a disk. Follow
  `ferrum-apply`'s convention of `_in` function variants taking an explicit
  path so tests never mutate process-wide environment.
- A7. The Docker image is built in CI, so a broken image is caught before a
  user pulls it.

### R9 — published means authenticated

**User story.** As an operator, I cannot accidentally put an unauthenticated
admin panel on the public internet.

**Owner decision, 2026-09-17:** force SSO on whenever a domain is set.

The gap this closes is between two defaults. `ferrum.auth.enable` is an
`mkEnableOption` and so defaults to **false**
(`modules/core/options.nix:132`), while an app's `exposure` defaults to
`"public"` whenever the proxy is enabled, and `modules/proxy/nginx.nix` emits
its `auth_request` block only when Authelia is on. Enabling apps on a host
with a domain therefore publishes Sonarr, Radarr, Prowlarr, SABnzbd and
qBittorrent admin interfaces on real certificates with **no login** — and the
original R6 A5 printed those URLs as its success report. qBittorrent and
SABnzbd accept arbitrary download paths, so this is a remote-code-execution
surface, not an information leak.

**Acceptance criteria.**
- A1. Whenever a base domain is configured, the installer asks for an SSO
  admin email and enables `ferrum.auth.enable` — on by default, not opt-in.
  `modules/proxy/authelia.nix:21-23` asserts `adminEmail` is non-empty.
- A1b. **`auth.enable` is off in the stage-1 `settings.json` and on in
  `settings.stage2.json`, alongside the app selection.** Turning it on in
  stage 1 is impossible for exactly the reason R4 already documents for apps,
  applied to a switch that is not an app: `modules/proxy/authelia.nix:25-34`
  declares `sops.secrets."authelia-jwt-secret"` and `"authelia-storage-key"`
  with real `sopsFile` paths under `/etc/ferrum/secrets`, and the stage-1
  evaluation runs on the operator's machine, where those files cannot exist
  because the host does not exist. Deferring it is not sufficient on its own
  either: `modules/core/overlays.nix:179` bakes
  `--set-default FERRUM_AUTH_ENABLED ${if ferrum.auth.enable then "1" else "0"}`
  into the installed wrapper **from the stage-1 config**, so a bare
  `ferrum-apply apply` would carry `0` and
  `crates/ferrum-apply/src/apply.rs:206-209` would skip
  `ensure_authelia_secrets` — after which the stage-2 build fails on the
  missing `.sops` files. R4 A3b's explicit environment is what closes it.
- A2. An operator who declines must pass a **second, differently-shaped typed
  confirmation** that names every app it is about to publish without
  authentication. Not a `y`, and not the same gesture as R2's.
- A3. R5 Tier 1 refuses the install when any app resolves to
  `exposure = "public"` while `auth.enable` is false, absent that
  confirmation. **This check reads `settings.stage2.json`, not the stage-1
  evaluation** — stage 1 has `apps: {}`, so no app resolves to `public` there
  and a check driven off `nix eval` would always pass vacuously. It is a
  JSON-level check against the stage-2 document plus the catalog's exposure
  default, and it is the one part of Tier 1 that is not a Nix evaluation.
- A4. R6 verifies it for real: `curl -sI https://<app>.<domain>/` returns a
  redirect to the auth host, not `200`. `modules/proxy/nginx.nix:63` emits
  `error_page 401 =302 https://auth.<domain>/?rd=$target_url`, and the
  `auth.<domain>` vhost and its certificate genuinely exist
  (`nginx.nix:101-108`, `acme.nix:108-116`), so the redirect target answers
  rather than hitting the `_ferrum_unmatched` 444 catch-all. **After an A2
  decline the assertion inverts**: a `200` is then the expected result and a
  redirect would be the failure. It is one line and one round-trip, and it is
  the earliest signal that catches this whole class.
- A5. Plex and Jellyfin are the recognised exception — they carry their own
  login — but that is a property of those two apps, recorded explicitly, not
  a reason to weaken the default.

## Dependencies (authorized by the owner, 2026-09-17)

The owner's standing policy makes adding or bumping a real package a hard
stop. These were surfaced at planning time and authorized:

- **`nixos-anywhere` as a flake input.** Not an input today — `flake.nix`
  declares only `nixpkgs`, `flake-parts`, `disko`, `sops-nix`. Required for
  R1 A2's claim that the image's contents are pinned by `flake.lock` rather
  than fetched at runtime.
- **`ferrum-install`, a new workspace crate.** A sixth member alongside
  `ferrum-apply`, `ferrum-reconcile`, `ferrum-secrets`, `ferrum-state`,
  `ferrumd`. A cargo-produced path-dep edge, plus the new package name.
- **SSH by shelling out to `ssh`/`scp`**, both bundled in the image. This
  matches the established convention — `ferrum-apply` already shells out to
  `nix`, `btrfs` and `authelia` via `Command::new` — and adds **zero
  third-party Rust dependencies**. A Rust SSH client (`russh`, `ssh2`) was
  also authorized but is deliberately **not used**; it would pull a real
  dependency tree for no benefit the shell-out does not already give.
- **A new `ferrum-apply put-secret <name>` subcommand** (R3 A8). New
  implementation surface in an existing crate, not a new dependency, and the
  first operator-value ingestion path ferrum has had.
- New Nix surface: `nix/pkgs/ferrum-install/`, wired into **both**
  `nix/modules/flake/packages.nix` **and** `nix/overlays/default.nix` — a
  package referenced as `pkgs.<name>` that is missing from the overlay has
  been a repeated defect in this repository (four instances).

## Out of scope for 1.6a

- **`nix run` as a second entry point.** DEC-B chose Docker. The flake app
  is a small addition later and is not part of this phase.
- **App-level self-setup.** ferrum knows `plex` and `thesyms.ca`, and should
  set Plex's remote-access URL itself — the reason the Plex phone app sees
  the library as offline while a browser works. This is real and wanted, but
  it is `ferrum-reconcile`'s surface (per-app convergence), not the
  installer's, and specifying it inside this phase would couple two
  independent pieces of work. **Recorded here so it is not lost.**
- **Pooled data disks** (mergerfs, LVM, RAID, ZFS). Out of scope for Phase 1
  by the design doc; the installer detects a pool and refuses to guess,
  directing the operator to `custom/`.
- **Non-`x86_64-linux` targets.**
- **Re-installing over an existing ferrum host** while preserving its state.
  R7 resumes an interrupted install; it does not migrate a live one.
- **Anything that would let the installer choose a disk without a human.**
  No `--yes`, no `--disk=auto`, no non-interactive mode in 1.6a.

## Assumptions

1. The target is reachable as `root` over SSH with a key, from the
   operator's machine, before the install. nixos-anywhere requires this and
   this phase does not change it.
2. The operator has out-of-band access (IPMI/KVM/monitor+keyboard). The
   installer cannot supply this and must not pretend the VM preflight
   removes the need for it — it reduces the risk, it does not eliminate it.
3. `ghcr.io/syms-dev/ferrum-install` is publishable from this repository's
   CI. Not yet verified.
4. Docker on the operator's machine can reach both the target's SSH port and
   the public internet (for the Nix substituters and the flake inputs).

## Open questions — resolved by the panel

- **OQ1 — cross-architecture building. RESOLVED.** `--build-on remote` is not
  speculative; it is already this project's practice for provisioning an
  x86_64 target from the aarch64 dev machine, and `docs/INSTALL.md:233-235`
  documents it. It works because nixos-anywhere kexecs the target first, so
  the build happens on the target's own hardware. Confirmed locally that a
  `linux/amd64` Nix container runs on this arm64 Mac (`uname -m` = `x86_64`,
  `nix 2.35.2`), so the image itself is viable under emulation; the heavy
  build never happens there. The sub-problem the original OQ1 missed —
  building for R5's VM preflight *before* kexec, where no builder exists — is
  resolved by R5's two-tier split.
- **OQ2 — KVM. RESOLVED** by R5 Tier 2: the boot proof moves to a KVM-capable
  CI runner and out of the operator's path entirely. `nixos-anywhere
  --vm-test`, which the design doc names as "the cheap way to cover most of
  it", is the mechanism for the CI job.
- **OQ3 — the first-user password. RESOLVED at HEAD.** `ensure_first_user` in
  `crates/ferrumd/src/auth.rs` writes
  `/var/lib/ferrum/daemon/ferrumd-setup-password` at mode 0400, under a
  `ferrum:ferrum 0750` directory inside a root-owned parent. Root reads it
  over SSH without weakening its mode. R6 A5 additionally covers Authelia's.
- **OQ4 — registry.** Still open, and the only remaining one.
  `ghcr.io/syms-dev/ferrum-install` needs a publish credential this repository
  does not have. It does not block spec approval; it blocks the first release.
- **OQ5 — authenticating the pinned revision. PARTLY RESOLVED, and it got
  harder.** The sibling spec accepted DA-1 on the grounds that "the operator
  already made a trust decision when they pointed `ferrum.url` at this
  project". On a **fresh** install the operator points at nothing: R3 A5 has
  the installer choose the pinned revision, and the only thing trusted is a
  mutable image tag. The image must therefore be pulled by digest, or the
  pinned revision verified against a signature, before the first release.
  Carried forward as a release-blocking requirement rather than an open
  question.

## Traceability

| Req | Replaces (INSTALL.md) | Primary surface |
|---|---|---|
| R1 | — (new entry point) | `crates/ferrum-install/`, `nix/modules/flake/packages.nix` |
| R2 | Step 1 | `crates/ferrum-install/src/inventory.rs` |
| R3 | Step 2 | `crates/ferrum-install/src/render.rs`, `examples/hosts/template/` |
| R4 | Steps 4 and 8 | `crates/ferrum-install/src/stages.rs` |
| R5 | Steps 5 and 5b | `crates/ferrum-install/src/preflight.rs` |
| R6 | Steps 3, 6 and 7 | `crates/ferrum-install/src/install.rs`, `verify.rs` |
| R7 | "Recovering a failed install" | `crates/ferrum-install/src/state.rs` |
| R8 | — (new test target) | `tests/install-from-nothing.nix`, CI |
| R9 | — (new; closes a defect the manual path also has) | `crates/ferrum-install/src/render.rs`, `preflight.rs`, `verify.rs` |


## Revision 2 — what the blind panel changed

Panel: technical-architect · senior-backend-reviewer · devils-advocate, run
blind and in parallel against generation 1
(`cee8afeb8e7e52959f8f8a8e1bbac939459e4eed8a2c3ed26eb519867ea26ae8`). **All
three returned FAIL**; the devil's advocate verdict was UPHELD. Consolidated
register: Critical 2, High 8, Medium 6, Low 4. Full evidence at
`.ckit/state/evidence/phase-1-6a-planning-panel.md`.

Structural changes, not wording:

1. **R9 is new.** Generation 1 would have published five admin panels with no
   authentication and printed their URLs as its success message.
2. **R5 was not implementable** and is now two tiers. It demanded an x86_64
   build before kexec, when no x86_64 builder exists.
3. **R4 gained the missing transfer.** Nothing put the host flake at
   `/etc/ferrum`, so stage 2 could not have run. `docs/INSTALL.md` has the
   same hole and should be corrected alongside the implementation.
4. **R2's firmware rule was inverted-dangerous** on the blank disk this phase
   exists to install, and is now a truth table with `/sys/firmware/efi`
   authoritative.
5. **R8 was unachievable** in the sandboxed harness and is now split, with
   the app named rather than left to chance.
6. **R3 A7, R6 A7, R7 A1b–A1d, R2 A8–A9** close gaps that would each have
   produced a host that looks healthy and is not: broken rollback, exhausted
   certificate quota, an unrecorded wipe, a wrong disk.

**The pattern worth keeping.** Three of the findings share one shape: *the
spec inherited a prose claim from a sibling document instead of deriving it
from source, and the claim was false at HEAD.* R4's "every enabled app
declares a sops secret" (false — jellyfin and plex declare none); R2 A5's
vfat heuristic (true for an installed machine, false for a blank one); R4's
"`/etc/ferrum`'s git worktree" (copied from the host template's *aspirational*
header, describing a state no code produces). Same class as the stale README
that claimed `ferrum-apply gc` was a stub. **A spec may cite a document for
intent, but every load-bearing factual claim is re-derived from source, and
cites the source rather than the document describing it.**

## Revision 3 — the recheck's two disputes, plus one the panel found and parked

The generation-2 recheck returned **architect PASS** (all seven IDs fixed) and
**devil's-advocate UPHELD** (nine of eleven fixed, one disputed, one new). The
open set was therefore not a strict subset of generation 1's, which is a human
checkpoint under `quality-gates.md` §3, not another autonomous cycle. The owner
authorized one bounded revision covering exactly three findings.

1. **DA-B — `settings.json` ownership (R4 A2b).** `--extra-files` copies
   root-owned and cannot set the `ferrum` group by name because that group does
   not exist at copy time; tmpfiles' `C` rule never repairs an existing file,
   and the only other code merely warns. Unfixed, `ferrumd` could not write
   settings.json and the dashboard would render correctly while saving nothing.
2. **DA-M — SSO could not be enabled in either stage (R9 A1b, R4 A3b).**
   Enabling `auth.enable` declares two `sopsFile`s, so stage 1 cannot evaluate
   it — the constraint R4 already documents at length for apps. Stage 2 alone
   does not fix it either, because the wrapper bakes `FERRUM_AUTH_ENABLED` from
   the stage-1 config. The fix is viable only because that is `--set-default`
   rather than `--set`.
3. **OBS-1 — the Cloudflare DNS-01 token (R3 A8).** Raised by the panel and
   deliberately parked as out-of-scope for the recheck, because it predates
   generation 2 — it follows from `9656ab2`, "Publish apps by default". Folded
   in here because it is the same class and the same fix conversation: with
   `exposure` defaulting to `public`, the **default install path** trips
   `modules/proxy/acme.nix:52`, so an installer that never asks for the token
   cannot complete a default install.

**These three, and R4's original subject, are one idea.** App secrets,
Authelia's two secrets, the Cloudflare token, and correct file ownership are
all *facts that cannot exist until the host does*. The spec modelled that for
app secrets and nowhere else, and each place it was not modelled produced a
High. If a future phase adds anything else to `/etc/ferrum` or to
`sops.secrets`, it belongs in stage 2 by default and needs a reason to be in
stage 1 — not the other way round.

**Second blind-spot pattern, worth keeping alongside the first.** *When a
revision flips a default, re-run every constraint already written in the spec
against the newly-enabled surface — not just the requirement that changed.*
R4 spends three paragraphs on the sopsFile-at-eval-time constraint; R9 then
turned on a switch that declares two sopsFiles, and nobody connected them. It
is the sibling of revision 2's lesson: that one was *inheriting* a claim
instead of deriving it, this one is *failing to re-apply* a claim already
correctly derived a few paragraphs above.

**`docs/INSTALL.md` needs the same corrections**, since the manual path has
every one of these defects too: it never transfers the host repo (R4 A2), never
mentions the ownership repair, never enables SSO, and its Step 4 app-less
install says nothing about the token.

## Revision 4 — the enumeration that should have happened in revision 3

The revision-3 verification pass returned DA-B `fixed` and two **new** High
findings, both inside the three authorized fixes, and both instances of the
pattern revision 3 itself had just named. That is three generations in a row
producing the same class, so revision 4 is deliberately a different *activity*
rather than another round of the same one.

**What changed method, not just content.** Revisions 2 and 3 reasoned about the
variable under discussion. Revision 4 **enumerates**: every `--set-default` in
`modules/core/overlays.nix:168-183` is listed, classified, and given its
consumer in `main.rs` and its concrete failure mode. Fourteen variables, five
of which differ between stages — and they are exactly the five derived from
`ferrum.apps.*` or `ferrum.auth.*`, which is provable rather than observed,
because the installer writes stage-1 settings as stage-2 minus `apps` minus
`auth`. The table in R4 A3b is falsifiable in thirty seconds against the file.

**And one claim was replaced with a mechanism.** R3 A8 said the token would be
delivered "so `ferrum-apply` can encrypt it". `ferrum-apply` cannot: its seven
subcommands are enumerated in `main.rs:20-43` and every function in
`secrets.rs` generates a value it invents. Revision 4 declares
`ferrum-apply put-secret <name>` as **new implementation surface**, and records
the three details — the `CLOUDFLARE_DNS_API_TOKEN=` payload form, the
`ferrum.secrets` declaration, the before-build ordering — that the two existing
routes make easy to get wrong.

**Third blind-spot pattern, and the most useful of the three.** *A spec that
asserts capability X of component Y must cite the `file:line` in Y that
provides X. "So that `<tool>` can do Z" is a claim, not a design.* Its sibling:
*when reasoning about a list, walk the list.* Both previous lessons were about
deriving claims from source; this pair is about **exhaustiveness** — deriving
one claim correctly and stopping is how revision 3 fixed `FERRUM_AUTH_ENABLED`
and missed the four variables around it.

**Not adversarially re-reviewed.** The panel's revision budget is spent. The
owner authorized this single enumeration pass and the gate closes on it. The
evidence is mechanical and self-checkable rather than argued, which is the
property that makes closing here defensible — but it is not the same assurance
as a fourth adversarial pass, and the implementation should treat R4 A3b's
table and R3 A8's new subcommand as the two highest-risk items to verify first
in code.
