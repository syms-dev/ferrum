# Building with the ferrum UI kit

ferrum is a NixOS-based media-server appliance. This kit is the two surfaces it
ships: a **visual installer** (disk selection, the destructive-erase gate, install
progress) and a **dashboard** (apps, secrets, apply, generations/rollback). Every
component here states a fact about a real machine, so accuracy in the copy matters
more than polish.

## Setup: no provider, one stylesheet

There is **no provider, theme object or context of any kind**. Import a component
and render it. The only requirement is that `styles.css` is loaded — without it
components render as unstyled text, because all colour, spacing and type come from
CSS custom properties defined there.

`styles.css` also sets `body`'s font, colour and background. Do not re-declare
those on your own wrapper; inherit them.

**Theme**: dark is the default. Light applies automatically under
`prefers-color-scheme: light`, and either can be forced with an attribute on the
root element: `<html data-ferrum-theme="light">` or `data-ferrum-theme="dark"`.
Never hard-code a colour — a literal breaks one of the two themes every time.

## The styling idiom: custom properties, not classes

This kit has **no utility-class vocabulary**. Components own their own class names
(all `fk-` prefixed) and you never write them. For your own layout glue around the
components, use plain CSS with these tokens — this is the complete set:

| Purpose | Tokens |
|---|---|
| Surfaces | `--ferrum-bg` (page), `--ferrum-panel` (raised), `--ferrum-line` (borders) |
| Text | `--ferrum-text`, `--ferrum-muted` |
| Semantic | `--ferrum-accent`, `--ferrum-ok`, `--ferrum-danger` |
| Washes (whole-block tints) | `--ferrum-wash-accent`, `--ferrum-wash-ok`, `--ferrum-wash-danger` |
| Shape & rhythm | `--ferrum-radius`, `--ferrum-radius-sm`, `--ferrum-gap` |
| Type | `--ferrum-sans`, `--ferrum-mono` |

Every colour token clears WCAG AA against both surfaces of its own theme. There is
no web font: `--ferrum-mono` is load-bearing, not decorative — serials, by-id paths
and log output are compared character by character and must stay monospaced.

Two rules the kit enforces about meaning, which designs should not work around:

- **`danger` is a property of a thing** (not running, no authentication), never of
  a selection. "About to be erased" belongs to `DiskCard`'s `selected` state and
  `EraseGate`, which own that red.
- **A default is shown, never pre-filled.** `SchemaField` renders a schema default
  as placeholder text. Writing it into a value freezes it forever.

## Where the truth is

- `styles.css` and its one `@import` (`_ds_bundle.css`) — the full closure a design
  receives. Read it before styling anything.
- `components/general/<Name>/<Name>.prompt.md` — per-component props and intent.
- `components/general/<Name>/<Name>.d.ts` — the exact API.

## An idiomatic composition

```jsx
<AppShell
  hostname="ferrum.example.com"
  nav={[{ href: "#/apps", label: "Apps" }, { href: "#/generations", label: "Generations" }]}
  current="#/apps"
  status={<StatusLine state="ok" message="Up to date — generation 48, applied 2 hours ago." />}
>
  <div style={{ display: "grid", gap: "var(--ferrum-gap)" }}>
    <AppTile app={{ id: "sonarr", displayName: "Sonarr", enabled: true,
                    url: "sonarr.example.com", health: "active", auth: "sso" }} />
  </div>
</AppShell>
```

`AppShell` is the dashboard frame (header, nav, status slot, content). Installer
screens do not use it — they compose `PhaseRail`, `StateRibbon`, `DiskCard`,
`SafeList` and `EraseGate` directly.
