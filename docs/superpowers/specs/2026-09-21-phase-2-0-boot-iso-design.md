# Phase 2.0 — R30: boot it, open a URL, done

**Status:** drafted 2026-09-21. Owner's direction: *"let's build the option that beats saltbox…
that's all I care about."* Open questions OQ1–OQ4 carry recommendations.

## The problem this solves

ferrum's install is "one command" only if you already have the hard part done. The real journey
today is:

1. Get the target machine running some Linux, reachable over SSH, with root login working.
   nixos-anywhere kexecs from whatever is already booted, so a **blank machine cannot be installed
   onto at all**.
2. Install Docker on your own machine.
3. `docker run … ghcr.io/syms-dev/ferrum-install root@<ip>`

Step 1 is undocumented, is the hardest step, and is where a homelab user with bare metal in a
closet actually is: download a NixOS ISO, write it to USB, boot it, find the IP, set a root
password, enable sshd. That is five manual steps before ferrum's "one command" begins, and it is
precisely the bogged-down feeling the product exists to remove.

A Saltbox user never meets this, because Saltbox installs onto the Ubuntu box they already have.
So on the single dimension that decides whether someone tries ferrum at all — the first ten
minutes — ferrum is currently **worse** than the thing it is replacing.

## R30 — the whole entry point is a USB stick

**User story.** I write ferrum to a USB stick, plug it into the machine, turn it on, and the
screen tells me a URL to open. I open it on my laptop. There is no second machine to prepare, no
Docker, no SSH, no IP to hunt for.

What the console shows, and this is the entire pre-browser experience:

```
        ferrum installer

  Open this on any computer on your network:

        http://192.168.2.50:7777

  Pairing code:  4417
```

**Acceptance criteria.**

- **A1.** A bootable image, built from this repository as another `nixosSystem` output, containing
  the installer and everything it needs. It is pinned by `flake.lock` like every other artifact
  here, not assembled by a script.
- **A2.** It boots, acquires an address, starts the installer, and displays the URL and pairing
  code on the console. Nothing else is required of the operator before the browser.
- **A3. No DHCP is a supported case, not a dead end.** A console fallback sets a static address.
  A machine that boots and shows no URL with no way forward is the worst possible failure here,
  because the operator has no other channel to diagnose it.
- **A4. The target is this machine.** Disk inventory runs locally instead of over SSH, which is
  simpler and removes a whole class of remote-execution failure.
- **A5. No kexec.** The installer is already the running system, so `nixos-anywhere`'s kexec step
  disappears — and with it the failure that cost the most time in Phase 1.6a: the kexec'd system
  accepting only the keys the first run installed, which made resume-after-kexec impossible and
  produced a silent `ssh-copy-id` retry loop for 150 minutes.
- **A6. The Docker/SSH path stays supported and is not deprecated.** VPS operators genuinely want
  the remote path, `tests/stage2/*` drives it, and CI depends on it. Phase 1.8's R1/A3 already
  says the browser is a second front-end over one library; this is a third entry point over that
  same library, not a fork of it.
- **A7.** Writing the image is documented for macOS, Windows and Linux, because the operator's own
  machine is not necessarily a Linux box.

## R31 — the pairing code is a real control, not decoration

Phase 1.8's R2 assumed a loopback-bound installer where the threat was another process on the same
machine. **The ISO breaks that assumption**: it is on the LAN by construction, because being
reachable from the operator's laptop is the entire point. R2/A1's "bound to loopback by default"
cannot hold, so what replaces it has to be stronger than a printed token.

This matters because of what the installer holds: it erases disks as root, it takes the Cloudflare
token, and under R4 it now takes the admin password that opens the dashboard and every app.

**Acceptance criteria.**
- **A1.** The pairing code is shown **only on the physical console**, and is required before any
  answer is accepted or any disk is read. Possession of the screen is the authentication.
- **A2.** It is generated per boot, never derived from anything predictable — not the MAC, not the
  time, not a build-time constant.
- **A3.** Wrong codes are rate-limited and a run is abandoned after a small number of failures,
  because the code is necessarily short enough for someone to read off a screen and retype.
- **A4.** It is exchanged once for a session, following Phase 1.8 R2/A2's existing mechanism —
  fragment, not query string, so it never lands in history or a `Referer`.
- **A5.** R2/A3 and A4 hold unchanged: secrets write-only across the boundary, nothing destructive
  reachable by GET.
- **A6.** The installer serves only on the interface it advertised, and says which one. A machine
  with a second NIC facing somewhere less friendly must not silently answer there too.

## Why this is the thing that beats Saltbox

Saltbox's install is a shell script run against an Ubuntu box you built yourself. Its first ten
minutes are: provision a machine, install Ubuntu, configure SSH, install dependencies, run a
script, and read the output to find out whether it worked.

ferrum's becomes: write a USB, boot it, open a URL. That is the TrueNAS and unRAID experience,
which is what people expect from an appliance and what a media server actually is.

The rollback story is the better *argument*, but nobody reaches it if the first ten minutes are
worse than what they already have.

## Open questions

- **OQ1.** Does the ISO also support installing onto a machine that already runs Linux, in place?
  `nixos-anywhere` can kexec from an existing Ubuntu, which is exactly the Saltbox user's
  situation and is how R27's migration would actually happen. Recommendation: **yes, but as the
  remote path rather than the ISO** — the ISO's promise is "blank machine, one USB", and bending
  it to also handle live systems muddies both.
- **OQ2.** Should the ISO offer to install onto a *different* machine on the network, rather than
  itself? It could, since the library is the same. Recommendation: **no.** "This machine" is the
  promise; a disk picker that spans hosts is how someone erases the wrong box.
- **OQ3.** How long is the pairing code? Four digits is easy to read and weak; a six-character
  alphanumeric is meaningfully stronger and still transcribable. Recommendation: **six
  alphanumeric, unambiguous alphabet** (no `0`/`O`, no `1`/`l`), with A3's rate limit.
- **OQ4.** Does the ISO self-destruct after a successful install — refusing to run again on an
  already-installed machine unless the operator forces it? Recommendation: **yes, refuse and say
  why.** Leaving a USB in a rebooting server should not be able to reinstall it.

## Out of scope

- Wi-Fi. A machine being installed as a server is on ethernet, and a wireless setup flow before
  the installer is a second installer.
- PXE and netboot. Legitimate for a rack, irrelevant to the audience this is for.
- Unattended or scripted installs from the ISO. The remote path already covers automation.
