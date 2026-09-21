---
name: humanize
description: ferrum's voice for any text an operator reads — UI copy, installer prompts, CLI output, error messages. Use with the installed `humanizer` skill, which does the general work; this adds only what is specific to ferrum.
---

# ferrum's voice

**Run the `humanizer` skill first.** It carries the 25 AI-writing patterns
(`blader/humanizer`, from Wikipedia's "Signs of AI writing") and does the general
work. This file adds only the decisions that are ferrum's and that a generic
editor cannot know.

Give humanizer this page as the writing sample, so it matches the register here
rather than inventing one.

## Who is reading

One person, setting up a media server in their own house, not being paid to be
there. They are technical enough to have found ferrum and impatient enough to
have left Saltbox. They are often reading at the exact moment something is
wrong.

## What ferrum calls things

- The operator is **you**. Never "the user", never "the system administrator".
- ferrum is **ferrum**, lower-case, and says **I** for an action it took
  ("I couldn't reach the disk"). Never "we" — there is no we.
- Their hardware is a **disk** and a **box**, which is what they call it. Not
  "storage device", "target host", "the deployment".
- Product names keep their own capitalisation: Plex, Sonarr, qBittorrent,
  Authelia, Jellyfin.

## The line humanizer cannot draw: precision outranks voice

Never trade a real number, path, serial, unit or exit code for a friendlier
vagueness. "8.0 TB" beats "a big disk"; `/data/media/tv` beats "the media
folder". Where §12–§16 would strip a word, keep it if it is load-bearing.

Two ferrum-specific cases where humanizer's rules would cost meaning, and the
meaning wins:

- **§6 forced triads.** Some of ferrum's lines make a real distinction that
  happens to be a contrast — that a safety property is structural rather than a
  setting, for instance. Keep the distinction; rewrite it as a plain statement
  instead of deleting it.
- **§11 passive voice.** Correct, with one exception: a destructive action gets
  the passive when naming an actor would imply the operator has already done it.
  "This disk is erased" is a fact about the disk; "You erased this disk" is an
  accusation.

## Failures

A failure message does three things and stops: what broke, what it means, what
to do. No apology, no blame, no reassurance.

> Sonarr didn't start. It can't write to `/data/media/tv`.

Never soften a failure into a warning. A self-signed certificate is a failure.
Drift is a failure. Saying so is the product working.

## Length

Every one of these rewrites should come out shorter. If it got longer, it got
worse.

## Check before shipping a string

1. Read aloud — would you say it to someone sitting next to you?
2. Is every number, path, name and unit still exact?
3. Did it get shorter?
4. If it is a failure, does it say what to do next?
5. No "just", no "simply", no exclamation mark, no em-dash you didn't choose.
