# Competitive analyses

Written so the positioning survives a dead session, and so a public claim can be checked before
somebody else checks it for us.

| Page | Verdict |
|---|---|
| [`landscape.md`](landscape.md) | **Read this first.** The uniqueness claim as currently worded is wrong; the scoped version is defensible. Nearest threats, and the gap nobody fills. |
| [`saltbox.md`](saltbox.md) | The project ferrum was started against. Three of our own claims were wrong and are corrected here. |
| [`perfect-media-server.md`](perfect-media-server.md) | Not a competitor — documentation, and already on NixOS. Exposes our missing parity story. |
| [`silo.md`](silo.md) | A media server, not a stack installer. Its own docs are the best validation of our thesis. |

## The rule these pages follow

**Every claim about another project is checked against its source or its documentation, with a date,
and anything unverified is labelled unverified.**

That is not politeness. The Saltbox analysis found that ferrum had been publicly asserting Saltbox
ships a default password of `password1234` — a claim that was already eleven months stale when it
was written, against a project that now carries a validator explicitly *rejecting* that value. Any
Saltbox user would have found it in under a minute and stopped reading everything else we said.

Two habits follow from that:

- **Lead with structural facts, not bug reports.** A closed issue is a stale weapon. "Zero releases,
  zero tags, 171 roles pinned to a floating image tag" is checkable in thirty seconds and cannot be
  fixed by a patch.
- **State the rows where we lose as sharply as the rows where we win.** An analysis that concedes a
  forty-to-one catalog gap reads as credible. One that doesn't reads as marketing, and the first
  reader to notice stops trusting the rest.
