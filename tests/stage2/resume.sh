#!/usr/bin/env bash
# Phase 1.6a story S13, second half: R8 A4 -- resume after a partial
# nixos-anywhere.
#
# This is the scenario R7's whole phase machine exists for, and the one
# docs/INSTALL.md's "Recovering a failed install" section asserts works
# without ever demonstrating it. The disk is gone; the record says
# `installing`; re-running must NOT repartition and must NOT ask for the
# serial again, because re-confirming a disk that is already erased
# protects nothing and only trains the operator to retype.
#
# Needs its own blank target -- the other half of S13 leaves its machine
# installed.
set -uo pipefail

WORK="$(mktemp -d)"
STEP="starting"
step() { STEP="$*"; echo "::group::$*"; }
ok()   { echo "::endgroup::"; }
die()  { echo "::error::FAILED at [$STEP]: $*"; tail -40 "$WORK/target.log" 2>/dev/null; exit 1; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -o ConnectTimeout=10 -p 2222)
tssh() { ssh "${SSH_OPTS[@]}" -i "$WORK/ssh/id_ed25519" root@127.0.0.1 "$@"; }
wait_for_ssh() { for _ in $(seq 1 "${1:-120}"); do tssh true 2>/dev/null && return 0; sleep 5; done; return 1; }

step "build and boot a blank target"
mkdir -p "$WORK/ssh" "$WORK/host"
ssh-keygen -t ed25519 -N "" -f "$WORK/ssh/id_ed25519" -q || die "ssh-keygen"
PUBKEY="$(cat "$WORK/ssh/id_ed25519.pub")"
nix build --no-link --print-out-paths .#ferrum-install > "$WORK/i" || die "build installer"
INSTALLER="$(cat "$WORK/i")/bin/ferrum-install"
nix build --no-link --print-out-paths --impure --expr "
  let f = builtins.getFlake (toString ./.); in
  import ./tests/stage2/target-vm.nix {
    nixpkgs = f.inputs.nixpkgs; system = builtins.currentSystem;
    sshPublicKey = \"$PUBKEY\";
  }" > "$WORK/v" || die "build target VM"
( cd "$WORK" && "$(cat "$WORK/v")/bin/run-nixos-vm" > "$WORK/target.log" 2>&1 & )
wait_for_ssh 120 || die "target never answered SSH"
SERIAL="$(tssh "lsblk -no SERIAL /dev/vdb | head -n1 | tr -d '[:space:]'")"
[ -n "$SERIAL" ] || die "no serial on the blank disk"
ok

step "start the install, then kill it once the disk has been touched"
# hostname, base domain (empty), apps, serial. With NO domain, collect()
# skips the ACME contact, the SSO question and the Cloudflare token -- an
# extra blank here is consumed as the serial, which the first run proved by
# failing with "no serial typed".
{ echo "s13resume"; echo ""; echo "sonarr"; echo "$SERIAL"; } > "$WORK/answers"
"$INSTALLER" root@127.0.0.1 --ssh-port 2222 --host-dir "$WORK/host" --ssh-dir "$WORK/ssh" \
  < "$WORK/answers" > "$WORK/install1.log" 2>&1 &
INST_PID=$!

# Wait for the state file to record that the destructive phase STARTED.
# That phase exists precisely because the wipe happens inside
# nixos-anywhere, so a crash between those two moments must not look like
# "nothing was touched".
# Generous: before `Installing` the installer runs Tier 1, which is a real
# `nix build --dry-run` of the generated flake against the pinned ferrum
# revision -- and the CI cache is routinely throttled, so it comes from
# cache.nixos.org. Ten minutes was not enough on the first real run.
for _ in $(seq 1 360); do
  grep -q '"Installing"' "$WORK/host/install-state.json" 2>/dev/null && break
  kill -0 "$INST_PID" 2>/dev/null || break
  sleep 5
done
grep -q '"Installing"' "$WORK/host/install-state.json" 2>/dev/null \
  || die "the installer never recorded the Installing phase; log: $(tail -20 "$WORK/install1.log")"

pkill -P "$INST_PID" 2>/dev/null
kill -9 "$INST_PID" 2>/dev/null
wait "$INST_PID" 2>/dev/null
pkill -9 -f nixos-anywhere 2>/dev/null
echo "killed mid-install; recorded phase: $(grep -o '"phase":[^,]*' "$WORK/host/install-state.json")"
ok

step "R7 A1b: the record says the disk may already be gone"
grep -q '"Installing"' "$WORK/host/install-state.json" \
  || die "the record does not show Installing -- an unrecorded destructive action"
ok

step "R7 A1d: a resume refuses FAST instead of hanging, and does not re-ask"
# What this used to assert, and why it was wrong.
#
# It expected the resume to complete and produce a working host. It cannot.
# The first run kexec'd the target, and the system now in its RAM accepts
# only the keys THAT run installed. A second nixos-anywhere invocation
# generates a fresh keypair and ssh-copy-id's it using the operator's
# credentials, which that environment does not accept -- and nixos-anywhere
# then retries forever rather than failing. Measured on run 35354737401:
# 150 minutes of silent looping on "Permission denied
# (publickey,keyboard-interactive)", killed by the outer timeout, with no
# output an operator could act on.
#
# So the installer now refuses to hand control to nixos-anywhere in that
# state, and this asserts the refusal: fast, and with a recovery that
# works. The recovery itself -- power-cycle, then --fresh -- is an ordinary
# fresh install, which tests/stage2/run.sh already covers end to end.
{ echo ""; } > "$WORK/answers2"
START=$(date +%s)
timeout 900 "$INSTALLER" root@127.0.0.1 --ssh-port 2222 \
  --host-dir "$WORK/host" --ssh-dir "$WORK/ssh" < "$WORK/answers2" \
  > "$WORK/install2.log" 2>&1
RC=$?
ELAPSED=$(( $(date +%s) - START ))
tail -40 "$WORK/install2.log"

grep -qi "Type the SERIAL" "$WORK/install2.log" \
  && die "the resume re-asked for the serial after the disk was already erased"

# It must FAIL, not hang: 124 is the timeout firing, which is the bug.
[ "$RC" -ne 124 ] || die "the resume HUNG again (timeout fired after ${ELAPSED}s)"
[ "$RC" -ne 0 ] || die "the resume reported success, but it cannot reach the kexec'd target"

# Fast: the probe window is 5 minutes, so anything near the old 150 is a
# regression even if it eventually exits.
[ "$ELAPSED" -lt 600 ] || die "the refusal took ${ELAPSED}s -- it must be prompt"

# And it must say what to do. This is the whole point: the operator is
# standing at a half-installed machine.
grep -q "cannot authenticate" "$WORK/install2.log" || die "no explanation of the failure"
grep -q "kexec"               "$WORK/install2.log" || die "does not name the cause"
grep -q -- "--fresh"          "$WORK/install2.log" || die "does not name the recovery"
grep -q "power-cycle"         "$WORK/install2.log" || die "does not say to reboot the target"
ok

echo
echo "================================================================"
echo "S13 RESUME PASSED: killed mid-install, and the resume REFUSED"
echo "promptly with a recovery -- instead of looping on ssh-copy-id"
echo "for 150 minutes as it did before."

