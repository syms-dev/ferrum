# design-sync notes — ferrum ui-kit

## Repo facts a re-sync needs
- The design system is `ui-kit/`, package name **`@ferrum/ui-kit`** (scoped). `cfg.pkg`
  MUST be the scoped name: with `"pkg": "ui-kit"` every authored preview failed to
  compile with `Could not resolve "@ferrum/ui-kit"`, and the converter's hypothesis
  line blames `extraEntries`, which is a red herring.
- No Storybook and none planned. `shape: package` is pinned in the config.
- Build: `npm --prefix ui-kit run build` (esbuild + `tsc --emitDeclarationOnly`).
  `ui-kit/dist/` is gitignored, so a fresh clone MUST build before the converter runs.
- Converter invocation that works here (run from the repo root):
  `--node-modules ./ui-kit/node_modules --entry ./ui-kit/dist/index.js`.
  The package cannot self-install into its own `node_modules`, hence `--entry`.
- playwright's browser cache on macOS is `~/Library/Caches/ms-playwright`, NOT
  `~/.cache/ms-playwright` as the skill's check suggests. chromium build 1243.

## Defects this sync found in the library (all fixed in ui-kit, not worked around)
- **Everything rendered in the browser's serif default.** Only `AppShell` declared a
  `font-family`, so any component used on its own — which is how the design agent
  uses them — lost the sans stack. `tokens.css` now sets `body`'s font, colour and
  background. This is the highest-value find of the run: it affected every card.
- `DiskCard` always formatted size as TB, so a 240 GB boot SSD read "0.3 TB".
  Now switches to GB below 1 TB.
- `Badge` had no `danger` tone, so `AppTile` painted "Not running" and "No
  authentication" in the same informational blue as "Behind SSO".
- `LivenessPanel.plausible` is spliced into a carrier sentence and expects a bare
  duration ("20 to 40 minutes"). Passing a full sentence produced a broken one. The
  prop doc now says so with an example.
- `SchemaField` rendered an empty-string default as a bare "default:".

## Config decisions
- `overrides.SchemaField.cardMode = "column"` — its inputs are wider than a grid cell
  (`[GRID_OVERFLOW]` named exactly this remedy).
- No `provider`: the kit has no context of any kind. Do not add one.
- No `extraFonts` / `runtimeFontPrefixes`: the kit deliberately ships no web font, so
  `[FONT_MISSING]` should never appear. If it does, something added a font.

## Known render warns
None. The final validate was clean: 18/18 render, 0 bad, 0 thin, 0 variants-identical,
0 floor cards. **A warn on a future run is new** — look at it, don't assume it is noise.

## Re-sync risks — what can silently go stale
- **Previews hard-code prop shapes.** `.design-sync/previews/*.tsx` pass literal
  objects (`Disk`, `CatalogApp`, `AppStatus`, `Generation`, `ApplyStep`). Renaming or
  requiring a field in `ui-kit/src` breaks the preview's compile, and a component whose
  preview fails to compile silently drops to the floor card rather than erroring. After
  any prop change, check the build log for `! preview build failed`.
- **`conventions.md` enumerates all 16 tokens and 9 component names by hand.** They
  were verified against `ds-bundle/_ds_bundle.css` and `components/general/` at sync
  time. Renaming a token or component makes the header lie to the design agent, which
  is worse than saying nothing. Re-verify before uploading.
- **Example hostnames are `*.example.com` on purpose.** They are illustrative, not the
  operator's real domain. Keep it that way — these cards are visible in the workspace.
- The sizes, serials and models in the previews are realistic but invented. They are
  not read from any real machine, so they never go stale, but don't cite them as facts.
- Grades live in the gitignored `.design-sync/.cache/`; carry-forward across machines
  comes from the uploaded `_ds_sync.json`, not from git.

## Voice (added in the second sync)
- ferrum's copy is governed by two skills: the installed plugin **`humanizer@humanizer`**
  (`blader/humanizer`, 25 AI-writing patterns from Wikipedia's "Signs of AI writing") and
  `.claude/skills/humanize/SKILL.md`, which is a THIN FERRUM LAYER over it — who is
  reading, what ferrum calls things, and the rule that precision outranks voice.
  Do not let the ferrum skill grow into a competing rule set; that was its first draft
  and the user replaced it with the real base.
- **The preview `.tsx` copy is part of the deliverable**, not scaffolding. The design
  agent imitates it. The first voice pass rewrote only the component strings and left
  the previews reading like a product; it took a second build to notice.
- Two documented exceptions where ferrum overrides humanizer: keep a contrast when it
  marks a real distinction (structural vs a setting), and keep the passive for a
  destructive fact ("This disk is erased" is a fact; "You erased this disk" accuses).

## Re-sync risks — additions
- **Grades key on the PREVIEW sources, not the component sources.** Changing a string
  inside `ui-kit/src` does NOT clear the grade, so a carried-forward grade can vouch for
  words nobody has looked at. After any copy change in `ui-kit/src`, delete the affected
  `.design-sync/.cache/review/<Name>.grade.json` by hand, or read the contact sheets.
- A hand-reconstructed `remote-sync.json` is rejected as malformed if `sourceHashes` is
  omitted. That is safe (it re-verifies everything) but slow — fetch the real file with
  `DesignSync(get_file, path: "_ds_sync.json")` and save it byte-for-byte.
