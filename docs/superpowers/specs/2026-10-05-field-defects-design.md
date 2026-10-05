# Field defects found by running ferrum on real hardware

**Date:** 2026-10-05. **Status:** spec, awaiting owner approval before implementation.

Every requirement below came from operating the owner's host, not from reading code. Each is
recorded with the evidence that produced it, because the shared property of all five is that they
were **invisible to the test suite** — four of them cannot be reproduced in a Nix sandbox or a
tempdir at all, and the fifth was contradicted by its own comments.

---

### R1: Dynamic DNS must detect the host's public address

**Description**: `ferrum.proxy.dns.ddnsUpdater` must discover this host's current public IPv4
address and publish that, rather than republishing a static value from `settings.json`.

**User Story**: As an operator on a residential connection, I want my apps to stay reachable when
my ISP changes my address, so that a hostname I gave someone keeps working without me noticing
anything happened.

**Evidence**: The owner's address moved from `184.148.39.165` to `142.180.179.64`. Seven records
kept pointing at the old one and every app became unreachable from outside, while the host stayed
healthy and reported nothing. `modules/proxy/dns.nix:96` sets
`target = { mode = "a"; address = dns.staticAddress; }`, and `dns_reconcile.rs:201`
(`ConfiguredTarget::A { address }`) publishes exactly that. **No code anywhere in `crates/`
queries a public address** — verified by searching for every plausible spelling.

**The feature's own words are false today**, which is why nobody noticed it was missing:
- `modules/proxy/dns.nix`: *"re-check the host's real public address"*
- the unit description: *"Correct the DNS records ferrum owns against this host's current public address"*
- `modules/core/options.nix`: *"The updater exists to correct an A record when this host's public address changes"*

**Acceptance Criteria**:
- [ ] With `ddnsUpdater.enable = true`, the timer discovers the current public IPv4 and publishes
      it, without the operator editing `settings.json`.
- [ ] A changed address updates every record ferrum owns, in one pass, and is visible in the
      reconcile journal with both the old and new values named.
- [ ] Discovery uses at least two independent sources and refuses to act on disagreement — a wrong
      answer republishes every hostname at someone else's server, which is worse than a stale one.
- [ ] A discovery failure is reported as a failure, never as "no change". An unreachable check
      must not be indistinguishable from a clean result — the rule R1's own update-discovery spec
      already establishes.
- [ ] `staticAddress` keeps working unchanged when the updater is off, and the two are never
      silently in conflict: with the updater on, a `staticAddress` that disagrees is a warning
      naming both.
- [ ] The three false comments above are corrected in the same change.

**Edge Cases**:
- Host behind CGNAT, so the discovered address is not routable to it: publish it anyway but warn,
  because ferrum cannot know the operator's port-forwarding story — and say so.
- Discovery sources return a private or reserved address: refuse, never publish.
- The address flaps between two values: rate-limit so a flapping link cannot burn the Cloudflare
  quota, and record that it is flapping.
- IPv6: out of scope. `staticAddress`'s own contract is that ferrum publishes no AAAA record.

---

### R2: A WireGuard config with more than one address must work

**Description**: `qbt-vpn-netns-setup` must accept a standard WireGuard `[Interface]` block
carrying several comma-separated addresses, which is what every mainstream provider issues.

**User Story**: As an operator, I want to paste my provider's config file in unmodified, so that
setting up the VPN is a copy and not a debugging session.

**Evidence**: The owner's Proton config has `Address = 10.2.0.2/32, 2a07:b944::2:2/128`. The setup
script passes the whole line to `ip addr add`, which refuses it:

```
Error: any valid prefix is expected rather than "10.2.0.2/32,2a07:b944::2:2/128".
qbt-vpn-netns-setup.service: Main process exited, code=exited, status=1/FAILURE
```

Worked around on the host by deleting the IPv6 address by hand. **Every Proton config fails
as-issued**, and the error names `ip`'s complaint rather than the config line that caused it.

**Acceptance Criteria**:
- [ ] `Address` and `DNS` accept a comma-separated list, with or without spaces, and each entry is
      applied separately.
- [ ] An IPv6 address in the list is handled or skipped deliberately — not passed to a command
      that will reject the whole line — and which was chosen is stated to the operator.
- [ ] A genuinely malformed entry fails with a message naming **the config line**, not `ip`'s
      stderr.
- [ ] A regression check parses a real multi-address provider config. Fixtures are real provider
      output, not hand-written minimal ones: the defect is in what providers actually issue.

**Edge Cases**:
- IPv6-only config: refuse with a clear message rather than silently producing a namespace with no
  address.
- Trailing comma, or whitespace-only entry: ignored rather than fatal.
- `AllowedIPs` has the same comma-separated shape — check it is not sitting on the same defect.

---

### R3: The installer must obtain a Plex claim token

**Description**: An install that enables Plex must end with Plex claimed, or must tell the
operator plainly that it did not and why.

**User Story**: As an operator, I want a finished install to be finished, so that I am not sent to
a web UI to complete setup the installer could have completed.

**Evidence**: `modules/apps/plex/service.nix:48` wires `PLEX_CLAIM` from
`apps.plex.settings.claimToken`; `meta.nix:87` defaults it to `""`; and **the installer never asks
for it** — `plex` appears in `answers.rs` only as a selectable app name. A fresh install with Plex
enabled therefore ends with an unclaimed server.

**Acceptance Criteria**:
- [ ] When Plex is among the chosen apps and a base domain is set, the installer asks for a claim
      token, with the plex.tv URL to fetch it from.
- [ ] The question states the four-minute expiry, because an operator who fetches it early and
      answers late gets a failure that looks like a bad token.
- [ ] Skipping is allowed and is reported in the closing summary as an unfinished step with the
      command to complete it later — never silently.
- [ ] The token is written as a sops secret, never into `settings.json`. It is a credential.

**Edge Cases**:
- Token expires mid-install: Plex starts unclaimed; the closing report must say so rather than
  implying success.
- Operator has no Plex account: skipping must be one keystroke.
- Re-running an apply on an already-claimed server must not re-claim or disturb it.

---

### R4: A data disk ferrum did not format must still work

**Description**: Pool branch roots must end up with ownership ferrum's own tooling can traverse,
whatever state the disk arrived in.

**User Story**: As an operator reusing disks from a previous system, I want them to join the pool,
so that migrating to ferrum does not mean reformatting several terabytes.

**Evidence**: On the owner's host `/mnt/ferrum-disk-1` was owned by UID **1001**, a user that does
not exist on the system — a leftover from whatever populated the disk before. `systemd-tmpfiles`
refused the ownership transition and `ferrum-media-tree.service` failed:

```
Detected unsafe path transition /mnt/ferrum-disk-1 (owned by 1001) → .../media (owned by root)
ferrum-media-tree.service: status=73/CANTCREAT
```

Note this is **not a regression from the media-tree unit added the same day**. The previous plain
tmpfiles rules met the identical condition and failed silently at boot. The new unit's only sin is
making a pre-existing failure visible, which is what it was written to do.

**Acceptance Criteria**:
- [ ] A branch root whose owner is not root is normalised during apply, or refused at evaluation
      with a message naming the path, the owner found and the command to fix it.
- [ ] Whichever is chosen, it is a decision recorded in the module, not an accident — changing
      ownership of an operator's disk is not obviously ferrum's business.
- [ ] A check covers a branch root with a foreign owner. Every existing fixture creates its own
      directories as root, so none can reach this state.

**Edge Cases**:
- Owner is a real local user rather than an orphan UID: likelier deliberate, so prefer refusing.
- Several branches, only one foreign: the message names which.
- Read-only branch: refuse early with the mount named.

---

### R5: Single sign-on for the dashboard — and the control it would remove

**Description**: Reaching the dashboard requires two logins today: Authelia, then ferrumd's own.
The owner wants one. This is achievable, but **not on its own** — the second gate is load-bearing.

**User Story**: As an operator, I want one login for everything, so that the control plane feels
like part of the system rather than a separate appliance.

**Evidence and the constraint**: ferrumd deliberately ignores forward-auth headers, and a test
enforces it: `no_source_file_reads_a_forward_auth_header`, beside
`forged_forward_auth_headers_authenticate_nobody`. That is not an omission — it is the
**compensating control** recorded against the accepted risk in
`docs/security/SEC-M02_authelia-cookie-scope.md`. Authelia's cookie is scoped to the whole base
domain and shared with catalog apps that carry deliberately unauthenticated bypass paths, so
clearing Authelia's edge gate must not by itself reach the control plane. ferrumd's own
`__Host-ferrumd_session` is what guarantees that.

**Trusting forward-auth headers without changing the cookie scope would delete that guarantee**
and silently convert an accepted Medium into a live one.

**Acceptance Criteria** — ordered, because the order is the point:
- [ ] **First**: the dashboard gets its own session cookie scope, so a cookie obtained in an app's
      context cannot authenticate at `ferrum.<domain>` (Authelia v4.38+ multi-domain
      `session.cookies`). This is the fix SEC-M02 deferred.
- [ ] **Only then**: ferrumd accepts an Authelia-asserted identity, and only from the proxy — a
      forged header from any other source still authenticates nobody, and the existing forged-header
      tests must keep passing unchanged.
- [ ] The SSH-tunnel recovery route keeps working without Authelia, because it is the way in when
      the proxy is broken. It must not become dependent on the thing it exists to survive.
- [ ] `SEC-M02` is closed with evidence, not left accepted while its control is removed.
- [ ] The cost the owner was told about when deferring M02 — a second login at the control plane —
      is re-examined here, since this requirement is that cost arriving.

**Edge Cases**:
- Authelia down: the dashboard must remain reachable over the tunnel, or a failed proxy takes away
  the tool for fixing the proxy.
- Operator's Authelia identity does not match a ferrumd user: decide whether to provision or
  refuse, and do it the same way every time.
- Session revocation: logging out of Authelia should not leave a live ferrumd session behind.

---

## Sequencing

**R2 and R4 first.** Both are small, both have a captured failure, and both block a real operator
today — R2 blocks every Proton user, R4 blocks every reused disk.

**R1 next.** It is the one the owner actually lost a night to, and it needs real design work:
address discovery is a trust decision, not a lookup.

**R3 after.** It is a question and a secret write, but it touches the interactive install flow,
which has drifted from its test fixture twice this week already.

**R5 last, and only as a pair.** Its first half is a security fix and its second half is a feature;
shipping the second without the first is a regression wearing a feature's clothes.

## What this document does not do

It does not re-litigate the four risks already accepted with owners and revisit triggers
(`SEC-M02`, `SEC-M03`, job-file pruning, `verify_still` on a resumed install). R5 is the exception
and it says so.
