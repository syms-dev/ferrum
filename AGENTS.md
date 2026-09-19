# Project agent guide

> Exported by **claude-kit**. This file gives your editor's agent claude-kit's engineering standards and SDLC discipline. It is a projection of a Claude Code configuration — see the fidelity note at the end for what carries over and what doesn't.

## Project-specific rules

Configured by **claude-kit**, SDLC profile
**Standard — full SDLC, parallel lanes, security gate**. The agnostic pipeline rules apply unchanged; the conventions below make
them concrete for this stack.

### Stack & conventions


Match your repository's actual layout — claude-kit configures the workflow, not your directory
structure. Point each agent at the overlay rule for the lane it works in.

# SDLC workflow guide (portable)

> Exported by **claude-kit** for the **Standard — full SDLC, parallel lanes, security gate** profile. When the
> destination host supports named delegation, run this as a multi-agent pipeline with enforced
> quality gates and independent reviewers. Otherwise use the same phases as a single-agent
> self-check checklist; the discipline remains even when the host cannot enforce the gate.

Move every non-trivial change through these phases in order. A phase "passes" only when it has **zero
open Critical/High/Medium issues** — if you find one, fix it and re-check before moving on.

## 1. Spec first

- Write down what you are building **before** writing code: the goal, the acceptance criteria, and the
  edge/empty/error cases. For UI work, note the screen states (empty, loading, error, success),
  interactions, responsive behavior, and accessibility.
- State your assumptions explicitly. If there are multiple valid interpretations, surface them instead
  of silently picking one.

## 2. Self-review the plan (stand in for the planning panel)

Before implementing, challenge your own spec across frontend/backend feasibility, architecture,
delivery, and adversarial concerns, then make one accountable decision rather than simulating a
role-to-role approval chain:

- Is this the **simplest** approach that solves the problem? Remove anything speculative.
- Does it fit the existing architecture and conventions? Any scalability or integration risks?
- For work that splits into independent lanes (the canonical example is a backend lane and a frontend
  lane), keep the **API contract** — request/response shapes and the types that consume them — in sync
  across both.

## 3. Implement

- Only after the plan holds up. Make **surgical** changes — touch only what the task requires; match
  the surrounding style; don't refactor unrelated code.
- Document as you go: a header on each new/modified file, a docstring on each public function
  (arguments, return, errors), and full type annotations on public signatures.

## 4. Code-review your own change

Re-read the diff as an independent reviewer would, looking for bugs, security issues, performance
problems, and spec mismatches. Every changed line should trace directly to the spec.

## 5. Tests green

- Add tests for the happy path, the edge cases, and the error cases you listed in the spec.
- Run the test suite and make it pass:
  - (Replace with your project's real test command if these don't match.)
- Confirm every acceptance criterion in the spec is actually covered — no gaps.

## 6. Lint, types, and a security pass

- Run lint/format/type checks and fix what they report:
- Do a security self-check: no hardcoded secrets or keys, inputs validated at the boundary, access
  control enforced, dependencies free of known-vulnerable versions.

## 7. Ship

- Build and verify:
- Write a clear commit/PR description: what changed, why, and how it was verified.

## Defect loop

On any failure, regression, or spec mismatch: document it, classify its severity, update the spec if
the expected behavior was unclear, then re-run **only the affected part** back through the relevant
phases above. Don't patch around the process.

## Fast-track

For a reversible, unambiguous, single-boundary low-risk change with no sensitive or public-contract
surface, select the fast track and go straight to Implement → self-review → tests → ship. File count
is only a hint; sensitive, cross-boundary, contractual, or irreversible work uses the full flow.

## What ports from Claude Code — and what doesn't

claude-kit's home is **Claude Code**, where this configuration runs as a multi-agent SDLC pipeline with
**enforced** quality gates: independent reviewer subagents, a parallel security scan, and a defect loop
that *blocks* a change from advancing on an unproven verdict. Those gates and subagents are
Claude-Code-only.

**What this export gives you here**

- The full **engineering rule set**, plus the **design-system / stack overlays** for your stack.
- The **project charter** above (stack, commands, independent lanes).
- The **SDLC workflow** as a single-agent self-check checklist.
- Your configured **MCP servers** (Cursor target only).

**What it does not reproduce:** the enforced gates, the independent reviewer subagents, and the
automated defect loop. Apply the workflow as **self-discipline** — you are one agent playing every
role. Where a rule is cited as `.claude/rules/<name>.md`, the same content is exported here as
`.cursor/rules/<name>.mdc` (Cursor) or summarized in the rule index below (AGENTS.md / Copilot).

## Engineering rules (index)

claude-kit installs these conventions. In Claude Code they load on demand and are enforced through the pipeline; apply them here as well. The full text of each rule is available by exporting the Cursor target (`.cursor/rules/*.mdc`), or under `.claude/rules/` if this project also uses Claude Code.

**Core rules**

- **agent-guardrails** — Safe operation of the agents themselves — distinct from securing the product they build
- **agent-memory** — the coding agent maintains a project-scoped knowledge base in `.claude/agent-memory` that persists learnings across sessions
- **agent-resilience** — How the agent machinery itself behaves when something goes wrong: a tool errors, a command fails,
- **autonomy-levels** — How much an agent may do on its own before a human must act
- **code-organization** — Codified patterns extracted from the existing codebase
- **continuity** — Cross-session, cross-compaction working memory
- **design-patterns** — Mandatory design patterns for backend and frontend code
- **devops-observability** — Two delivery-side phases that run after the test-coverage merge gate (MR3 VERIFIED) and before the PR Raiser, so that pipeline and observability artifacts ship *inside* the same PR as the code
- **documentation** — Mandatory documentation standards for all code in this repository
- **evals** — How to measure the quality of AI/agent-powered features — anything whose output is produced by a
- **frontend-best-practices** — These rules are enforced on all code generated or modified by coding agents in this project
- **goal-setting-and-monitoring** — An agent that can't say *what done looks like* and *whether it's getting there* drifts
- **human-in-the-loop** — The pipeline is autonomous, not unsupervised
- **linting-and-formatting** — All code MUST pass the project's linter with zero warnings and zero errors before committing
- **mandatory-workflow** — This document defines two development workflows: one for bug fixes and one for features
- **model-tiers** — Each agent declares a semantic model tier in its definition — pick the tier deliberately
- **quality-gates** — This rule adds three things on top of the existing pipeline in `mandatory-workflow.md`:
- **rarv-cycle** — A short self-check every agent runs before declaring its stage done and handing off
- **reasoning-techniques** — How an agent should *think* before and while it acts
- **resilience-engineering** — failure modes, then go prove they're handled.
- **responsive-and-accessibility** — All new and modified UI components MUST be responsive and usable on mobile devices (375px+), tablets (768px+), and desktop (1024px+), and MUST meet accessibility standards
- **risk-classification** — Classify every task before acting so the right amount of caution, review, and human approval is
- **testing** — All new code and modified code MUST have accompanying unit tests with a minimum 90% coverage threshold across all metrics (or as defined by the project's coverage policy)
- **tool-design** — When you build a tool, MCP server, script, or slash command for an agent to use, design it for an
- **wave-orchestration** — When a single run is too big to be one feature pipeline — a migration, a repo-wide refactor, a
