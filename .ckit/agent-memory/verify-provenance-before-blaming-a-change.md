# Establish that a failure predates your change — don't assume it

When a broad check fails during a gated change, the question "is this mine?" must be answered with a
command, not an inference. Assumed provenance is an uncited verdict under
`.claude/rules/quality-gates.md` §2.5.

The cheap, decisive method: extract pristine `HEAD` and run the **identical** command.
```
git archive HEAD crates | tar -x -C <scratch>
# confirm the new file is absent, then run the same command there
```

On Phase 1.5b Task 3, `cargo clippy --workspace --all-targets -- -D warnings` failed with 3 errors.
Pristine `HEAD` produced the **identical** three, proving they were pre-existing. That turned a
would-be blocker into a noted Low — and it also surfaced that the repo's *enforced* clippy gate is
three Nix derivations (`nix/modules/flake/checks.nix` ~:332-371) that all run
`cargo clippy --offline -- -D warnings` **without `--all-targets`**, so CI never lints `#[cfg(test)]`
code at all.

Two corollaries:
- **Scope a gate's claim to what was actually proven.** `build-green` here means "adds zero new
  clippy findings", **not** "workspace clippy is clean" — state that framing in the evidence so a
  later reader cannot mistake one for the other.
- **A lane's narrow check can hide a broader failure.** The developer ran `clippy -p ferrumd` (clean);
  the orchestrator's own `--workspace` re-run is what caught it. Re-run the checks yourself.
