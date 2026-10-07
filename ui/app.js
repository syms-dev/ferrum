// The ferrum UI: six hash-routed views over the daemon's read-only APIs and
// its three mutating ones.
//
// No framework, no build step, no external request of any kind. The box this
// runs on may have no internet -- which is a real state during provisioning,
// and exactly when an operator most needs the UI to work.

import * as api from "./api.js";
import { renderForm, appSchema, advancedSchema } from "./forms.js";

const $ = (sel) => document.querySelector(sel);
const view = () => $("#view");

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, "");
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

const state = {
  username: null,
  catalog: null,
  settings: null,
  stream: null, // the live EventSource, so a view teardown can close it
  ticker: null, // the interval re-ageing an on-screen reading, same reason
  ticks: [], // every re-ageing callback that interval drives -- see startTicker
};

function setStatus(message, kind = "") {
  const bar = $("#status");
  bar.textContent = message || "";
  bar.className = kind;
}

/// A unix-epoch-seconds string, rendered in the OPERATOR's own locale.
///
/// This is the UI's job, not the daemon's, and it is precisely why the wire
/// value carries no timezone: the daemon cannot know where the person reading
/// it is sitting, and a server-rendered timestamp would be wrong for everyone
/// but the server.
function localTime(epochString) {
  const seconds = Number(epochString);
  if (!Number.isFinite(seconds)) return String(epochString);
  return new Date(seconds * 1000).toLocaleString();
}

function closeStream() {
  state.stream?.close();
  state.stream = null;
}

/// Runs `tick` once a minute until the view is torn down.
///
/// Exists for one job: keeping a "checked N minutes ago" line honest while a
/// page sits open. A reading painted once and never re-aged is the frozen
/// gauge in slow motion -- it was true when it was painted and says nothing
/// about having stopped being true.
///
/// One INTERVAL at a time, cleared by `route()` before any view is painted, so
/// a view cannot leak a timer that goes on writing into a detached node -- but
/// it drives every callback registered against it, rather than only the last
/// one. That distinction is the whole reason this function changed: the app
/// detail screen now carries two independently-fetched readings (health and
/// VPN), and the previous version replaced the interval on each call, so the
/// second panel to register silently froze the first one's age line at the
/// value it was painted with. A line that has STOPPED ageing is worse than no
/// line, because it still looks like a live one.
///
/// @param {() => void} tick - Called every minute, and never on the first
///   call: the caller paints the initial value itself, so the line is never
///   blank for a minute.
/// @returns {void}
function startTicker(tick) {
  state.ticks.push(tick);
  if (state.ticker === null) {
    state.ticker = setInterval(() => {
      for (const each of state.ticks) each();
    }, 60_000);
  }
}

function closeTicker() {
  if (state.ticker !== null) clearInterval(state.ticker);
  state.ticker = null;
  state.ticks = [];
}

// --- login ---------------------------------------------------------------

function loginView() {
  const username = el("input", { type: "text", id: "u", value: "admin", autocomplete: "username" });
  const password = el("input", { type: "password", id: "p", autocomplete: "current-password" });
  const error = el("p", { class: "error" });

  const form = el("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      error.textContent = "";
      try {
        await api.login(username.value, password.value);
        await boot();
      } catch (err) {
        error.textContent =
          err.status === 401
            ? "That username and password did not match."
            : err.status === 429
              ? "Too many attempts. Wait a moment and try again."
              : err.message;
      }
    },
  }, [
    el("h1", { text: "ferrum" }),
    el("div", { class: "field" }, [el("label", { for: "u", text: "Username" }), username]),
    el("div", { class: "field" }, [el("label", { for: "p", text: "Password" }), password]),
    el("button", { type: "submit", text: "Log in" }),
    error,
  ]);

  view().replaceChildren(el("section", { class: "login" }, [form]));
}

// --- apps ----------------------------------------------------------------

function appsView() {
  const apps = state.catalog?.apps || {};
  const schema = state.catalog?.schema || {};
  const ids = Object.keys(apps).sort();

  const list = el("div", { class: "cards" });
  // One health cell per card, filled in by the single request below rather
  // than by a fetch per card. Held by id so the answer can find its cell
  // whatever order the probes finished in.
  const healthCells = new Map();
  for (const id of ids) {
    const meta = apps[id];
    const enabled = state.settings?.apps?.[id]?.enable === true;
    // "Checking..." rather than a blank or a neutral dot. An empty cell on a
    // list of app names reads as "nothing wrong", which is the one thing it
    // must not say before anybody has asked.
    const health = el("p", { class: "pill", text: "Checking…" });
    healthCells.set(id, health);
    list.appendChild(
      el("article", { class: "card" }, [
        el("h3", { text: meta.displayName || id }),
        el("p", { class: "hint", text: meta.summary || "" }),
        el("p", { class: enabled ? "pill on" : "pill", text: enabled ? "Enabled" : "Disabled" }),
        health,
        // A real link, not a button that calls a function. The detail view has
        // its own route, so this one is middle-clickable, bookmarkable, and
        // survives a reload -- which a hand-dispatched render never did.
        el("a", { class: "button-link", href: `#/apps/${id}`, text: `Open ${meta.displayName || id}` }),
      ]),
    );
  }

  // One line for the whole list, aged in place while the page sits open. Each
  // card's word is only as good as this timestamp, so it is stated once,
  // prominently, rather than implied per card.
  const age = el("p", { class: "checked-at" });

  view().replaceChildren(
    el("section", {}, [
      el("h2", { text: "Apps" }),
      el("p", { class: "hint", text: "Every app is rendered from the same schema. Adding one to the catalog needs no UI change." }),
      age,
      list,
    ]),
  );

  fillAppHealth(healthCells, age);
}

// --- app detail ----------------------------------------------------------

/// The one screen that knows what an app IS, rather than what its settings
/// are.
///
/// Built to screen 4 of docs/design/mockups/2026-10-07-ferrum-ui-mockups.html,
/// which the reconciliation beside it recorded as having zero occurrences of
/// anything resembling it in the shipped UI. What the mockup adds over the
/// settings form it replaces is CONTEXT: who this app is already wired to,
/// whether its tunnel is up, where to open it. The form underneath is the
/// same schema renderer, untouched -- "adding an app needs no UI change" is
/// the property this screen is built on rather than around.

/// The hostname an app is published at.
///
/// `modules/proxy/lib.nix`'s `vhostNameFor` owns this rule --
/// `"${app.subdomain}.${ferrum.proxy.baseDomain}"` -- and this is the one
/// place the browser restates it, because the catalog is host-independent and
/// cannot carry a hostname that depends on this host's own base domain.
///
/// Returns null rather than a plausible-looking wrong answer in every case
/// where the app is NOT published: no proxy, no base domain, or an app the
/// catalog marks headless (which gets no vhost and no DNS record at all, so a
/// link would promise a page that can never answer).
///
/// @param {string} id - The catalog app id.
/// @param {object} meta - That app's catalog metadata.
/// @returns {string|null} The host, or null when this app has no front door.
function appHostname(id, meta) {
  if (meta.headless) return null;
  const baseDomain = state.settings?.proxy?.baseDomain;
  if (state.settings?.proxy?.enable === false || !baseDomain) return null;
  const subdomain = state.settings?.apps?.[id]?.subdomain ?? meta.defaultSubdomain;
  if (!subdomain) return null;
  return `${subdomain}.${baseDomain}`;
}

/// The Integrations panel: who ferrum has already wired this app to.
///
/// **Read, never re-derived.** The edges and their registration kinds arrive
/// in the catalog as `integrationEdges`, computed once by
/// modules/lib/integrations.nix -- the same module modules/core/reconciler.nix
/// imports `pairKind` from. Two places deriving "Prowlarr registers Sonarr as
/// an application" from the same meta.nix is the defect class that produced
/// the nginx/reconciler address split, and this panel is deliberately not the
/// second place.
///
/// The one thing applied here is the reconciler's own liveness filter: it
/// registers an edge only when BOTH ends are enabled, so an edge to a
/// disabled app is listed separately as something that is not wired yet,
/// rather than claimed as done.
///
/// @param {string} id - The catalog app id.
/// @returns {HTMLElement} The panel.
function integrationsPanel(id) {
  const edges = state.catalog.apps[id]?.integrationEdges ?? [];
  const nameOf = (other) => state.catalog.apps[other]?.displayName || other;
  const isEnabled = (app) => state.settings?.apps?.[app]?.enable === true;
  const bothEnabled = (edge) => isEnabled(edge.consumer) && isEnabled(edge.provider);

  const phrase = (edge) => {
    const weAreTheConsumer = edge.consumer === id;
    if (edge.kind === "application") {
      return weAreTheConsumer
        ? `registers ${nameOf(edge.provider)} as an application, pushing indexers to it`
        : `is registered as an application in ${nameOf(edge.consumer)}, which pushes indexers here`;
    }
    return weAreTheConsumer
      ? `pulls downloads from ${nameOf(edge.provider)}`
      : `is registered as a download client in ${nameOf(edge.consumer)}`;
  };

  const live = edges.filter(bothEnabled);
  const dormant = edges.filter((edge) => !bothEnabled(edge));

  const body = [];
  if (live.length) {
    body.push(el("p", { text: "ferrum-reconcile re-asserts these on every apply, through the apps' own APIs:" }));
    body.push(el("ul", {}, live.map((edge) => el("li", { text: `This app ${phrase(edge)}.` }))));
  } else if (edges.length) {
    body.push(el("p", { text: "Nothing is wired yet \u2014 every app this one connects to is disabled." }));
  } else {
    body.push(el("p", { text: "This app has no integrations in the catalog. Nothing registers it, and it registers nothing." }));
  }
  if (dormant.length) {
    body.push(el("p", {
      class: "hint",
      text:
        "Declared in the catalog but not wired, because the other end is not enabled: " +
        dormant
          .map((edge) => nameOf(edge.consumer === id ? edge.provider : edge.consumer))
          .join(", ") +
        ". Enable it and the next apply connects them.",
    }));
  }

  return el("section", { class: "callout" }, [el("h3", { text: "Integrations" }), ...body]);
}

/// One entry per line, one distinct sentence per state, and every sentence
/// names a DIFFERENT thing to do next. That is the test a state had to pass
/// to exist: `unknown` folded into `tunnel-down` would send an operator to
/// debug WireGuard over a daemon that simply could not reach systemd, and
/// `not-applied` folded into it would send them to a journal for a unit that
/// does not exist on this host yet.
///
/// Cross-checked against crates/ferrumd/src/vpn.rs's own `VpnState` variants
/// by checks.app-detail-view-is-wired, so a state the daemon can send with no
/// branch here fails the build rather than rendering as a blank panel.
// Kept on ONE line on purpose -- the check reads the quoted names out of it.
const VPN_STATES = ["not-configured", "not-applied", "starting", "tunnel-configured", "tunnel-down", "unknown"];

/// The two keys `GET /api/vpn` always answers with. Same cross-check.
const VPN_ENVELOPE_KEYS = ["checkedAt", "apps"];

const VPN_STATE_TEXT = {
  "not-configured": stateText("No VPN is set up for this app", "Nothing is declared, so there is no tunnel and no kill switch: this app reaches the network the same way every other app does. Paste a WireGuard config below to change that."),
  "not-applied": stateText("A VPN config is saved, but this host has not been rebuilt yet", "The config is encrypted on disk and systemd knows no tunnel unit, which is what a saved-but-unapplied VPN looks like. Apply, and the tunnel is created."),
  "starting": stateText("The tunnel is coming up", "systemd is still bringing the namespace up or taking it down. Check again in a moment."),
  "tunnel-configured": stateText("The tunnel is configured and the kill switch is in place", "The setup ran all the way through: the network namespace exists and the WireGuard interface inside it was configured from your config. See the limit below \u2014 this is not a statement that traffic is flowing."),
  "tunnel-down": stateText("The tunnel is down, so downloads are blocked", "The kill switch keeps it that way on purpose \u2014 it never falls back to your real IP. The app is bound to the tunnel's own unit, so it is stopped rather than left running outside it. Read that unit's journal for the reason."),
  "unknown": stateText("ferrum could not find out", "The system bus did not answer, so nothing was measured. This is not the same as the tunnel being down, and it is not the same as it being up."),
};

/// The qBittorrent VPN panel -- screen 5 of the mockups.
///
/// Nothing here names an app. The panel is rendered for whichever app's
/// catalog metadata declares a `vpn` block (`meta.vpn`), which is what keeps
/// "adding an app is adding a directory" true for this screen too, and what
/// stops the systemd unit name living in a second place where it could
/// silently stop matching the unit service.nix defines.
///
/// @param {string} id - The catalog app id.
/// @param {object} vpnMeta - That app's catalog `vpn` block.
/// @returns {HTMLElement} The panel, which fetches its own reading.
function vpnPanel(id, vpnMeta) {
  const status = el("div", { class: "state" });
  const age = el("p", { class: "checked-at" });
  const facts = el("dl", { class: "facts" });
  const paste = el("textarea", {
    id: "wg-config",
    rows: 6,
    spellcheck: "false",
    placeholder: "[Interface]\nPrivateKey = ...\nAddress = ...\n\n[Peer]\nPublicKey = ...\nEndpoint = ...",
  });
  const note = el("p", { class: "hint", "aria-live": "polite" });
  const recheck = el("button", { type: "button", class: "ghost", text: "Check again" });
  const save = el("button", { type: "button", text: "Save VPN config" });

  // The reading's own timestamp, held so the ticker can re-age it without
  // re-fetching. A page left open must not go on claiming a measurement is
  // fresh -- the text says how old it is, and keeps saying so as it ages.
  let checkedAt = null;

  function paintAge() {
    age.textContent = checkedAt
      ? `Checked ${localTime(checkedAt)} \u2014 ${relativeAge(checkedAt)}.`
      : "Not checked yet.";
  }

  function paint(reading) {
    const stateName = String(reading?.state ?? "");
    const text = VPN_STATE_TEXT[stateName];
    status.replaceChildren();
    if (!text) {
      status.appendChild(el("p", {
        class: "error",
        text: `The daemon reported VPN state "${orUnknown(stateName)}", which this page does not know how to render. It knows: ${VPN_STATES.join(", ")}.`,
      }));
      return;
    }
    status.appendChild(el("strong", { text: text.label }));
    status.appendChild(el("p", { class: "hint", text: text.prose }));

    const rows = [
      ["Kill switch", reading.killSwitch
        ? "on \u2014 this app reaches the network only through the tunnel, with no fallback path if it drops"
        : "OFF \u2014 if the tunnel drops, this app falls back to this host's own address. Turn it on under this app's own options above."],
      ["Measured from", reading.unit
        ? `the systemd unit ${reading.unit}, which reported "${orUnknown(reading.activeState)}"`
        : "nothing \u2014 there is no tunnel configured to measure"],
    ];
    facts.replaceChildren(...rows.flatMap(([term, detail]) => [
      el("dt", { text: term }),
      el("dd", { text: detail }),
    ]));
  }

  async function refresh() {
    try {
      const document_ = await api.vpn();
      const missing = VPN_ENVELOPE_KEYS.filter((key) => !(key in document_));
      if (missing.length) {
        note.textContent = `The daemon's VPN answer is missing ${missing.join(", ")}, so this panel cannot be trusted.`;
        return;
      }
      checkedAt = document_.checkedAt;
      paintAge();
      paint(document_.apps?.[id]);
    } catch (err) {
      note.textContent = `Could not read the VPN status: ${err.message}`;
    }
  }

  recheck.addEventListener("click", refresh);

  save.addEventListener("click", async () => {
    const value = paste.value.trim();
    if (!value) {
      note.textContent = "Paste the WireGuard config first.";
      return;
    }
    save.disabled = true;
    save.textContent = "Saving\u2026";
    try {
      // A secret can only be written once settings.json DECLARES it --
      // secrets_api.rs refuses an undeclared name, deliberately, so the write
      // surface stays settings-driven. Declaring it is therefore part of
      // saving a config, not a separate chore for the operator.
      //
      // The declaration is merged into the document as it is ON DISK, not
      // into whatever this session has staged elsewhere: saving a VPN config
      // must not quietly commit an unrelated pending edit from another
      // screen.
      if (!state.settings?.secrets?.[vpnMeta.secret]) {
        const onDisk = await api.settings();
        onDisk.secrets = { ...(onDisk.secrets || {}), [vpnMeta.secret]: {} };
        await api.putSettings(onDisk);
        state.settings = {
          ...state.settings,
          secrets: { ...(state.settings.secrets || {}), [vpnMeta.secret]: {} },
        };
      }
      await api.putSecret(vpnMeta.secret, value);
      paste.value = "";
      note.textContent =
        "Encrypted and written. Apply to bring the tunnel up \u2014 nothing has been rebuilt yet.";
      await refresh();
    } catch (err) {
      note.textContent = `Could not save it: ${err.message}`;
    } finally {
      save.disabled = false;
      save.textContent = "Save VPN config";
    }
  });

  // Re-age the reading in place while the page sits open. The reading is not
  // re-fetched: silently refreshing it would make the operator's screen
  // disagree with what they last asked for. Only the AGE moves, which is the
  // honest half -- and it is what turns a static line into one that visibly
  // goes stale.
  startTicker(paintAge);
  paintAge();
  refresh();

  return el("section", { class: "callout" }, [
    el("h3", { text: "VPN kill switch" }),
    status,
    age,
    facts,
    el("p", {
      class: "hint",
      text:
        "What this can and cannot tell you: ferrum reads whether the tunnel was SET UP, not " +
        "whether it is carrying traffic. WireGuard is connectionless \u2014 an interface is up " +
        "from the moment it is configured, peer or no peer \u2014 and ferrumd is unprivileged, " +
        "so it cannot look inside the namespace to check for a recent handshake.",
    }),
    el("div", { class: "field" }, [
      el("label", { for: "wg-config", text: "WireGuard config" }),
      paste,
      el("p", {
        class: "hint",
        text:
          "Paste the whole file your provider issued, [Interface] and [Peer] together. " +
          "Encrypted immediately on save, to this host's own key. ferrumd can write this but " +
          "can never read it back \u2014 there is no endpoint that returns a secret, by design, " +
          "so this page cannot show you what is already stored.",
      }),
    ]),
    el("div", { class: "row" }, [save, recheck]),
    note,
  ]);
}

/// One app, in full: what it is, what it is connected to, and what you can
/// change about it.
///
/// @param {string} id - The catalog app id, from the `#/apps/<id>` route.
/// @returns {void}
function appDetailView(id) {
  closeStream();
  const meta = state.catalog?.apps?.[id];
  if (!meta) {
    view().replaceChildren(
      el("section", {}, [
        el("p", {}, [el("a", { href: "#/apps", text: "\u2190 Apps" })]),
        el("h2", { text: "No such app" }),
        el("p", {
          text:
            `This host's catalog has no app called "${id}". It may have been renamed, or this ` +
            "link may be from a different version of ferrum.",
        }),
      ]),
    );
    return;
  }

  const current = state.settings?.apps?.[id] ?? {};
  const stateRoot = state.settings?.storage?.stateDir ?? "/var/lib/ferrum/state";
  const enabled = current.enable === true;

  // Two groups, deliberately, and both still rendered by the ONE schema
  // renderer. The first is what an operator decides; the second is everything
  // the catalog already answered correctly. Enabling an app should not be a
  // configuration exercise -- that is the whole point of having a catalog.
  const primary = renderForm(appSchema(state.catalog.schema, id, meta), current);
  const advanced = renderForm(advancedSchema(meta, stateRoot, id), current);

  const host = appHostname(id, meta);
  const actions = el("div", { class: "row" }, [
    host
      ? // Scheme-relative on purpose. It inherits the scheme the dashboard is
        // already being served over, which is the right answer on a host
        // reached either way -- and spelling a scheme out here would put an
        // absolute URL in this file, which is the exact shape the standing
        // "no external request of any kind" invariant is checked for.
        el("a", { class: "button-link", href: `//${host}`, target: "_blank", rel: "noreferrer", text: `Open ${meta.displayName || id} \u2197` })
      : null,
    // The catalog's own docsUrl. A link the operator clicks, never a fetch --
    // this page still requests nothing but its own origin. `noreferrer` so
    // following it does not hand the destination this host's name.
    meta.docsUrl
      ? el("a", { href: meta.docsUrl, target: "_blank", rel: "noreferrer", text: "Docs \u2197" })
      : null,
  ]);

  const vpnMeta = meta.vpn;

  view().replaceChildren(
    el("section", {}, [
      el("p", { class: "crumb" }, [el("a", { href: "#/apps", text: "\u2190 Apps" }), ` / ${meta.displayName || id}`]),
      el("h2", { text: meta.displayName || id }),
      // What is actually KNOWN about this app, and nothing more. This line
      // used to carry a comment explaining why the mockup's green "Healthy"
      // dot was NOT drawn: ferrum had no per-app health check between applies,
      // so a dot would have been the frozen gauge this release exists to stop
      // shipping. The measurement exists now (`appHealthPanel` below, over
      // GET /api/app-health), so the status is reported -- in words, with the
      // time it was taken, and with the limits of what it proves stated on the
      // panel itself rather than implied by a colour.
      el("p", {}, [
        el("span", { class: enabled ? "pill on" : "pill", text: enabled ? "Enabled" : "Disabled" }),
        " ",
        meta.summary || "",
      ]),
      host ? el("p", { class: "hint", text: `Published at ${host}.` }) : null,
      actions,

      appHealthPanel(id),

      primary.node,

      el("details", { class: "advanced" }, [
        el("summary", { text: "Advanced \u2014 the catalog already set these" }),
        el("p", {
          class: "hint",
          text:
            "Nothing here needs changing to run the app. A value you leave alone is not " +
            "written to settings.json at all, so it keeps tracking ferrum's own default " +
            "instead of being frozen at today's value.",
        }),
        advanced.node,
      ]),

      vpnMeta ? vpnPanel(id, vpnMeta) : null,
      integrationsPanel(id),

      el("div", { class: "row" }, [
        el("button", {
          type: "button",
          class: "ghost",
          text: "Discard",
          // Re-renders from the staged document, which is where the controls
          // were populated from, so every edit made since this screen was
          // painted is dropped and nothing already staged is lost.
          onclick: () => appDetailView(id),
        }),
        el("button", {
          type: "button",
          text: "Review changes",
          onclick: () => {
            // Both groups merge into one app object. Each read() already omits
            // anything still at its default, so an untouched form stages
            // nothing and settings.json does not grow.
            const merged = { ...advanced.read(), ...primary.read() };
            state.settings = {
              ...state.settings,
              apps: { ...(state.settings.apps || {}), [id]: merged },
            };
            setStatus("Changes staged. Review and apply them on the Apply tab.", "ok");
            location.hash = "#/apply";
          },
        }),
      ]),
    ]),
  );
}

// --- app health ----------------------------------------------------------

/// What `GET /api/app-health` can establish, rendered as WORDS.
///
/// The mockup's screens 3 and 4 put a green "Healthy" dot here, and until this
/// section existed the detail view deliberately refused to draw one: nothing
/// measured anything, so the dot would have been the frozen gauge ROAD-TO-PUBLIC
/// item 23 exists to stop shipping. The dot is earned now, and these are the
/// terms it is earned on.
///
/// One entry per line, one distinct sentence per state, and every sentence
/// names a DIFFERENT thing to do next -- the same test a state had to pass to
/// exist in the daemon's own vocabulary. The three that matter most:
///
///   * `unauthenticated` is NOT a fault. The app answered 401 or 403, which
///     means it accepted the connection, read the request and applied its own
///     auth policy. ferrum holds no credential for it on purpose, because the
///     alternative is putting a key in a URL.
///   * `timed-out` is NOT `refused`. One is a wedged app, the other a stopped
///     one, and starting the unit only fixes the second.
///   * `address-unknown` is NOT `unreachable`. Nothing was dialled at all.
///
/// Cross-checked against crates/ferrumd/src/app_health.rs's own `HealthState`
/// variants by checks.app-health-view-is-wired, so a state the daemon can send
/// with no branch here fails the build rather than rendering as a blank cell.
// Kept on ONE line on purpose -- the check reads the quoted names out of it.
const HEALTH_STATES = ["not-enabled", "not-measurable", "address-unknown", "healthy", "unauthenticated", "unhealthy", "refused", "unreachable", "timed-out"];

/// The two keys `GET /api/app-health` always answers with. Same cross-check.
const HEALTH_ENVELOPE_KEYS = ["checkedAt", "apps"];

const HEALTH_STATE_TEXT = {
  "not-enabled": stateText("Not enabled", "This app is not switched on for this host, so there is nothing running to ask. Nothing was measured."),
  "not-measurable": stateText("Not checked — nothing to ask", "This app publishes no HTTP endpoint of its own, so ferrum has nothing to dial. That is a permanent property of the app, not a fault, and it is not a statement that the app is unwell."),
  "address-unknown": stateText("ferrum does not know where this app listens", "The app is enabled, but this host did not tell the daemon which address it binds. Nothing was dialled — ferrum declines to guess, because guessing loopback is exactly how an app that runs inside a VPN namespace gets reported as down. Rebuild this host; if it persists, it is a ferrum bug."),
  "healthy": stateText("Answering", "The app answered on its own health endpoint with exactly the status its catalog entry declares. See the limit below — this says it is up and serving, not that everything inside it is well."),
  "unauthenticated": stateText("Answering — and declining to say more", "The app replied that this caller may not ask, which means it is UP: it accepted the connection, read the request and applied its own auth policy. ferrum deliberately holds no key for this check, so this is the expected answer rather than a problem to fix. Nothing to do."),
  "unhealthy": stateText("Answering with the wrong thing", "Something is listening and speaking HTTP at this address, and what it said is not what this app's catalog entry expects. The app may be starting, mid-upgrade, or broken — its own journal is the next place to look."),
  "refused": stateText("Nothing is listening", "The connection was refused outright, so the port is closed. That usually means the app's service is not running. Check the unit, then its journal."),
  "unreachable": stateText("Could not be reached", "The address could not be dialled, or whatever answered was not speaking HTTP. This is different from the port being closed: something about the route or the network namespace is wrong rather than simply absent. The address ferrum dialled is shown below."),
  "timed-out": stateText("Did not answer in time", "The connection was accepted and then nothing came back inside the deadline. That is NOT the same as the app being down — a wedged app holds its socket open and says nothing, and starting it again is not the fix. Check its load, then its journal."),
};

/// The short word for a state, for the apps list, where there is no room for
/// a sentence.
///
/// @param {object|undefined} reading - That app's entry in the report.
/// @returns {string} The state's label, or the raw wire value when this page
///   has no branch for it -- never a blank, which reads as "fine".
function healthLabel(reading) {
  const name = String(reading?.state ?? "");
  return HEALTH_STATE_TEXT[name]?.label ?? `Unrecognised state "${orUnknown(name)}"`;
}

/// Whether a state is one an operator should look at.
///
/// Used ONLY to pick a border colour. The words carry the meaning on their
/// own -- colour is never the only indicator here, which is the rule
/// .claude/rules/responsive-and-accessibility.md states and the reason every
/// pill below is labelled as well as tinted.
///
/// @param {object|undefined} reading - That app's entry in the report.
/// @returns {string} A `pill` class list.
function healthPillClass(reading) {
  const name = String(reading?.state ?? "");
  if (name === "healthy" || name === "unauthenticated") return "pill on";
  if (name === "not-enabled" || name === "not-measurable") return "pill";
  return "pill bad";
}

/// What the probe actually did, as rows an operator can act on.
///
/// `measuredFrom` is the load-bearing one: it is how a reader sees that
/// qBittorrent was dialled at `10.200.1.2:8090` inside its VPN namespace
/// rather than at a loopback address where nothing listens.
///
/// The declared PATH is deliberately not here, and not anywhere else on this
/// page: the daemon never sends it, so a key in a catalog query string cannot
/// reach a browser. See crates/ferrumd/src/app_health.rs.
///
/// @param {object} reading - That app's entry in the report.
/// @returns {Array<[string, string]>} Term/detail pairs.
function healthFacts(reading) {
  return [
    ["Measured from", reading.measuredFrom
      ? `${reading.measuredFrom} — the address this host says the app binds`
      : "nothing — no connection was made"],
    ["It answered", reading.status === null || reading.status === undefined
      ? "nothing"
      : `HTTP ${reading.status}, where this app's catalog entry expects ${orUnknown(reading.expectStatus)}`],
  ];
}

/// The health block on the app detail header -- screen 4 of the mockups.
///
/// Fetches its own reading, says when it was taken, keeps saying how old that
/// is while the page sits open, and offers a re-check. Nothing here names an
/// app: every app gets the same block, because the catalog decides what is
/// measurable.
///
/// @param {string} id - The catalog app id.
/// @returns {HTMLElement} The block, which fetches its own reading.
function appHealthPanel(id) {
  const status = el("div", { class: "state" });
  const age = el("p", { class: "checked-at" });
  const facts = el("dl", { class: "facts" });
  const note = el("p", { class: "hint", "aria-live": "polite" });
  const recheck = el("button", { type: "button", class: "ghost", text: "Check again" });

  // The reading's own timestamp, held so the ticker can re-age it without
  // re-fetching. Silently re-fetching would make the screen disagree with what
  // the operator last asked for; only the AGE moves.
  let checkedAt = null;

  function paintAge() {
    age.textContent = checkedAt
      ? `Checked ${localTime(checkedAt)} — ${relativeAge(checkedAt)}.`
      : "Not checked yet.";
  }

  function paint(reading) {
    const name = String(reading?.state ?? "");
    const text = HEALTH_STATE_TEXT[name];
    status.replaceChildren();
    facts.replaceChildren();
    if (!text) {
      status.appendChild(el("p", {
        class: "error",
        text: `The daemon reported health state "${orUnknown(name)}", which this page does not know how to render. It knows: ${HEALTH_STATES.join(", ")}.`,
      }));
      return;
    }
    status.appendChild(el("strong", { text: text.label }));
    status.appendChild(el("p", { class: "hint", text: text.prose }));
    facts.replaceChildren(...healthFacts(reading).flatMap(([term, detail]) => [
      el("dt", { text: term }),
      el("dd", { text: detail }),
    ]));
  }

  async function refresh() {
    recheck.disabled = true;
    try {
      const document_ = await api.appHealth();
      const missing = HEALTH_ENVELOPE_KEYS.filter((key) => !(key in document_));
      if (missing.length) {
        note.textContent = `The daemon's health answer is missing ${missing.join(", ")}, so this panel cannot be trusted.`;
        return;
      }
      note.textContent = "";
      // Stamped only once a reading really arrived. Setting it before the
      // fetch would age a measurement that never happened.
      checkedAt = document_.checkedAt;
      paintAge();
      paint(document_.apps?.[id]);
    } catch (err) {
      note.textContent = `Could not read this app's health: ${err.message}`;
    } finally {
      recheck.disabled = false;
    }
  }

  recheck.addEventListener("click", refresh);
  startTicker(paintAge);
  paintAge();
  refresh();

  return el("section", { class: "callout" }, [
    el("h3", { text: "Health" }),
    status,
    age,
    facts,
    el("p", {
      class: "hint",
      text:
        "What this can and cannot tell you: ferrum asks this app's own health endpoint whether " +
        "it is answering, and reports the status code it got back. An app can answer perfectly " +
        "and still have a corrupt database or an unmounted library, so this is a " +
        "liveness signal, not a verdict on the app. " +
        "ferrum also sends no password or API key with the question, " +
        "so an app that refuses to answer is reported as up, which is what it is.",
    }),
    el("div", { class: "row" }, [recheck]),
    note,
  ]);
}

/// Fills in every card's health cell on the apps list, from ONE request.
///
/// One request for the whole screen rather than one per card: the daemon
/// probes every app concurrently and answers once, so a list of seven apps
/// costs seven sockets opened at the same time rather than seven round trips
/// in sequence.
///
/// @param {Map<string, HTMLElement>} cells - Card id -> the element to fill.
/// @param {HTMLElement} age - The one "checked ..." line for the whole list.
/// @returns {Promise<void>}
async function fillAppHealth(cells, age) {
  let checkedAt = null;
  const paintAge = () => {
    age.textContent = checkedAt
      ? `Health checked ${localTime(checkedAt)} — ${relativeAge(checkedAt)}.`
      : "Health not checked yet.";
  };
  startTicker(paintAge);
  paintAge();

  try {
    const document_ = await api.appHealth();
    const missing = HEALTH_ENVELOPE_KEYS.filter((key) => !(key in document_));
    if (missing.length) {
      age.textContent = `The daemon's health answer is missing ${missing.join(", ")}, so these rows cannot be trusted.`;
      return;
    }
    checkedAt = document_.checkedAt;
    paintAge();
    for (const [id, cell] of cells) {
      const reading = document_.apps?.[id];
      cell.className = healthPillClass(reading);
      cell.textContent = healthLabel(reading);
    }
  } catch (err) {
    age.textContent = `Could not read app health: ${err.message}`;
  }
}

// --- apply ---------------------------------------------------------------

async function applyView() {
  closeStream();
  const saved = await api.settings();
  const edited = state.settings ?? saved;
  const changed = JSON.stringify(saved) !== JSON.stringify(edited);

  const log = el("pre", { class: "log" });
  const diff = el("pre", {
    class: "diff",
    text: changed
      ? `--- on disk\n+++ staged\n${JSON.stringify(saved, null, 2)}\n\n=>\n\n${JSON.stringify(edited, null, 2)}`
      : "No staged changes.",
  });
  const error = el("p", { class: "error" });
  // Where a refused apply explains itself. Empty on every ordinary apply:
  // the gate below fires only when this host's on-disk pin disagrees with
  // the pin the running generation was built from, which is the state a
  // rollback leaves behind and nothing else does.
  const gate = el("section", { role: "status", "aria-live": "polite" });

  /// Paint the pin gate's refusal, with the one control that passes it.
  ///
  /// @param {string} rev - The on-disk revision, full 40-hex, exactly as the
  ///   job reported it. Handed straight back as the acknowledgement, so the
  ///   operator can only ever accept the revision they were shown.
  /// @param {string} message - The job's own sentence. Not recomposed here:
  ///   only ferrum-apply can see which of the two cases this is (a moved
  ///   revision, or a moved tree under an unchanged one).
  /// @returns {void}
  function renderGate(rev, message) {
    gate.replaceChildren(
      el("h3", { text: "This is not only a settings change" }),
      el("p", { text: message }),
      el("p", {}, [el("code", { class: "rev", text: rev })]),
      el("p", {
        class: "hint",
        text:
          "This usually means you rolled back and the pin did not come with you — rolling back " +
          "reverts the system, never /etc/ferrum/flake.lock. The gate is here to make the " +
          "decision visible, not to prevent it: if you do want that revision, take it.",
      }),
      el("div", { class: "row" }, [
        el("button", {
          type: "button",
          class: "danger",
          text: `Apply anyway, moving ferrum to ${rev.slice(0, 7)}`,
          onclick: () => startApply(rev),
        }),
      ]),
    );
  }

  /// Paint the way-in gate's refusal, with the one control that passes it.
  ///
  /// @param {string} token - The lockout token, exactly as the job reported
  ///   it. Handed straight back as the acknowledgement, so the operator can
  ///   only ever accept the lockout they were shown — an acknowledgement
  ///   given for "SSH is off" cannot pass a later, different lockout.
  /// @param {string} message - The job's own sentence, naming both closed
  ///   routes and what would reopen each. Not recomposed here: only
  ///   ferrum-apply can see which routes it found shut.
  /// @returns {void}
  function renderWayInGate(token, message) {
    gate.replaceChildren(
      el("h3", { text: "This would leave no way back into this machine" }),
      el("p", { text: message }),
      el("p", {}, [el("code", { class: "rev", text: token })]),
      el("p", {
        class: "hint",
        text:
          "Nothing has been built and nothing has changed — this host is still running the " +
          "generation it was. The gate is here to make the decision visible, not to prevent " +
          "it: if you have another way in that ferrum cannot see, take it.",
      }),
      el("div", { class: "row" }, [
        el("button", {
          type: "button",
          class: "danger",
          text: "Apply anyway, with no way back in",
          onclick: () => startApply(null, token),
        }),
      ]),
    );
  }

  function attach(id) {
    log.textContent = "";
    state.stream = api.streamJob(id, {
      onEvent: (e) => {
        log.textContent += `${e.event}: ${e.detail}\n`;
        log.scrollTop = log.scrollHeight;
        // The job writes this one event as `<rev>: <prose>` -- the same
        // shape `progress::complete` writes and `splitCompletion` already
        // parses -- so the revision arrives verbatim rather than being
        // scraped out of a sentence this page would then be depending on.
        if (e.event === "pin-gate") {
          const { result: rev, message } = splitCompletion(e.detail);
          renderGate(rev, message);
        }
        // Same `<token>: <prose>` shape, same reason: the token the retry
        // must carry arrives verbatim rather than being scraped out of a
        // sentence this page would then depend on.
        if (e.event === "way-in-gate") {
          const { result: token, message } = splitCompletion(e.detail);
          renderWayInGate(token, message);
        }
      },
      onDone: () => setStatus("Job finished.", "ok"),
    });
  }

  /// Start an apply, optionally acknowledging one of the two gates.
  ///
  /// @param {string|null} acceptPinChange - The full revision the operator
  ///   accepted, or null for an ordinary apply. Sent only when present, so
  ///   the common case posts exactly the body it always has.
  /// @param {string|null} acceptNoWayIn - The lockout token the operator
  ///   accepted, or null. Sent only when present, for the same reason.
  /// @returns {Promise<void>}
  async function startApply(acceptPinChange = null, acceptNoWayIn = null) {
    error.textContent = "";
    gate.replaceChildren();
    try {
      const { id } = await api.startJob("apply", {
        ...(acceptPinChange ? { acceptPinChange } : {}),
        ...(acceptNoWayIn ? { acceptNoWayIn } : {}),
      });
      setStatus(`Apply started (${id}).`);
      attach(id);
    } catch (err) {
      if (err.status === 409) {
        const running = (await api.jobs(5)).jobs.find((j) => j.status === "running");
        error.textContent = running
          ? `A ${running.kind || "job"} started at ${localTime(running.started_at)} is still running (${running.id}). Wait for it to finish.`
          : "A job is already running.";
      } else {
        error.textContent = err.message;
      }
    }
  }

  const save = el("button", {
    type: "button",
    text: "Save settings",
    onclick: async () => {
      error.textContent = "";
      try {
        await api.putSettings(edited);
        setStatus("Settings saved. Nothing has been applied yet.", "ok");
      } catch (err) {
        // The daemon's own validation messages, verbatim. A stale schema --
        // the UI knowing a field the built schema no longer has -- surfaces
        // here, and a browser tab cannot prevent that situation, only report
        // it clearly.
        error.textContent = err.message;
      }
    },
  });

  const apply = el("button", {
    type: "button",
    class: "danger",
    text: "Apply now (rebuild the system)",
    onclick: () => startApply(),
  });

  view().replaceChildren(
    el("section", {}, [
      el("h2", { text: "Apply" }),
      el("p", {
        class: "hint",
        text: "Saving settings never rebuilds the system. Applying is a separate, deliberate step.",
      }),
      diff,
      el("div", { class: "row" }, [save, apply]),
      error,
      gate,
      log,
    ]),
  );

  // Reattach to a job still running from a previous page load.
  const recent = await api.jobs(10);
  const running = recent.jobs.find((j) => j.status === "running");
  if (running) {
    setStatus(`Reattached to a ${running.kind || "job"} already running.`);
    attach(running.id);
  }
}

// --- secrets -------------------------------------------------------------

/// Write-only, always. There is no GET for a secret and there must never be
/// one, so this can report only THAT a name has a value set -- never what it
/// is. The names come from the settings document's own `secrets` map, which
/// is where ferrum.secrets actually lives; the catalog publishes no per-app
/// secret list (checked against a real /api/catalog response).
function secretsView() {
  closeStream();
  const declared = Object.keys(state.settings?.secrets || {}).sort();
  const list = el("div", {});

  const field = (name) => {
    const input = el("input", { type: "password", autocomplete: "new-password" });
    const note = el("span", { class: "hint" });
    return el("div", { class: "field" }, [
      el("label", { text: name }),
      el("div", { class: "row" }, [
        input,
        el("button", {
          type: "button",
          text: "Set value",
          onclick: async () => {
            if (!input.value) {
              note.textContent = "Enter a value first.";
              return;
            }
            try {
              await api.putSecret(name, input.value);
              input.value = "";
              note.textContent = "A value is set. It cannot be read back.";
            } catch (err) {
              note.textContent = `Could not set it: ${err.message}`;
            }
          },
        }),
      ]),
      note,
      el("p", {
        class: "hint",
        text: state.settings.secrets[name]?.description || "",
      }),
    ]);
  };

  for (const name of declared) list.appendChild(field(name));

  view().replaceChildren(
    el("section", {}, [
      el("h2", { text: "Secrets" }),
      el("p", {
        class: "hint",
        text:
          "Each value is encrypted to this host's own SSH key and written to disk. " +
          "Nothing here can be read back \u2014 there is no endpoint that returns a secret, " +
          "by design, so this page cannot tell you whether a value is already set. " +
          "Setting one simply replaces whatever is there.",
      }),
      el("p", {
        class: "hint",
        text:
          "To check from the host: ls /etc/ferrum/secrets/ \u2014 a <name>.sops file means " +
          "that secret has a value.",
      }),
      declared.length
        ? list
        : el("p", {
            text:
              "No secret names are declared in settings.json yet. Add them under " +
              "\"secrets\" there, then re-apply, and they will appear here to fill in.",
          }),
    ]),
  );
}

// --- generations + the rollback dialog -----------------------------------

/// The confirmation an operator reads before reverting a machine.
///
/// Written as prose, not a field dump, and deliberately specific about what
/// does NOT come back. The original design doc names getting this wrong as
/// "how a technically correct product earns a reputation for losing data":
/// rollback restores app state from a snapshot, so anything written since
/// that snapshot is gone, and anything living outside the state subvolume is
/// untouched and therefore now mismatched against the reverted databases.
function confirmRollback(gen) {
  const dialog = el("dialog", { class: "confirm" });
  const taken = gen.snapshot?.taken_at ? localTime(gen.snapshot.taken_at) : "unknown";

  dialog.appendChild(
    el("form", { method: "dialog" }, [
      el("h3", { text: `Roll back to generation ${gen.generation}?` }),
      el("p", {
        text:
          `This reboots the machine into generation ${gen.generation} and restores ` +
          `every app's data from the snapshot taken at ${taken}.`,
      }),
      el("h4", { text: "What comes back" }),
      el("p", {
        text:
          "The whole system: every package and service version as it was. And every " +
          "app's state directory — its database, its settings, its library index. " +
          `Anything an app wrote after ${taken} is discarded.`,
      }),
      // Said by name rather than left to be inferred from "the whole
      // system" above. One apply is one generation regardless of what went
      // into it, so a settings change staged into the same apply as an
      // update is reverted by the same rollback — and an operator who
      // thinks they are only undoing the update will not go looking for the
      // setting they also lost.
      el("p", {
        text:
          "Including whatever else was applied at the same time. If a settings change — a port, " +
          "an app enabled, a root folder — was staged into the same apply as the thing you are " +
          "undoing, it goes back too. One apply is one generation, whatever changed inside it, " +
          "and a rollback cannot take back one half of it.",
      }),
      el("h4", { text: "What does NOT come back" }),
      el("p", {
        text:
          "Your media files are untouched — they live outside the snapshot. So are " +
          "downloads in flight or queued, which keep running against a library index " +
          "that no longer knows about them. TLS certificates stay as they are. So do " +
          "Authelia users, including any password changed since — that new password " +
          "still works after the rollback.",
      }),
      // R8's fourth criterion, in the same register as the rest of this
      // dialog. The pin is the one thing a rollback leaves ahead of the
      // system it just reverted, and the operator finds out either here or
      // the next time they press Apply.
      el("p", {
        text:
          "And ferrum's own pin does not move. /etc/ferrum/flake.lock still names whatever " +
          "revision it names now, so the next rebuild would start from that one — not from the " +
          "revision you are going back to. Nothing rebuilds behind your back: the Apply screen " +
          "will tell you, and name the revision, before it moves this host. If you want the pin " +
          "back as well, `git -C /etc/ferrum checkout flake.lock` on the host does it.",
      }),
      el("p", {
        class: "hint",
        text:
          "In short: the system and its databases go back in time; your files, logins and " +
          "the pin do not. Where those two disagree, an app may need to rescan.",
      }),
      el("div", { class: "row" }, [
        el("button", { value: "cancel", text: "Cancel" }),
        el("button", { value: "confirm", class: "danger", text: `Roll back and reboot` }),
      ]),
    ]),
  );

  document.body.appendChild(dialog);
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      const ok = dialog.returnValue === "confirm";
      dialog.remove();
      resolve(ok);
    });
    dialog.showModal();
  });
}

async function generationsView() {
  closeStream();
  const data = await api.generations();
  const rows = el("tbody");

  for (const gen of data.generations) {
    // rollbackable: false shows the daemon's own reason and NO control. That
    // includes the currently-running generation, so no rollback affordance is
    // ever rendered for it.
    const action = gen.rollbackable
      ? el("button", {
          type: "button",
          class: "danger",
          text: "Roll back",
          onclick: async () => {
            if (!(await confirmRollback(gen))) return;
            try {
              const { id } = await api.startJob("rollback", { to: gen.generation });
              setStatus(`Rollback started (${id}). The machine will reboot.`);
            } catch (err) {
              setStatus(err.message, "error");
            }
          },
        })
      : el("span", { class: "hint", text: gen.reason || "Not rollbackable." });

    rows.appendChild(
      el("tr", { class: gen.current ? "current" : "" }, [
        el("td", { text: String(gen.generation) }),
        el("td", { text: localTime(gen.date) }),
        el("td", {
          text: gen.current
            ? "running now"
            : gen.snapshot?.update_pre_image
              ? "kept: the way back from an update"
              : "",
        }),
        el("td", {}, [action]),
      ]),
    );
  }

  // Held-back snapshots, and the one control that releases them.
  //
  // An update's way back is the snapshot taken immediately before its pin
  // moved, and `ferrum.storage.keepGenerations` would retire that after ten
  // more applies — so gc holds it. A retention rule nobody can see is its
  // own defect, which is why this says so on the screen where snapshots
  // live rather than only in a gc job's log.
  const held = data.generations.filter((g) => g.snapshot?.update_pre_image);
  const status = el("p", { class: "hint", role: "status", "aria-live": "polite" });
  const confirm = held.length
    ? el("section", { class: "callout warn" }, [
        el("h3", {
          text:
            held.length === 1
              ? "One snapshot is being kept for an update you have not confirmed"
              : `${held.length} snapshots are being kept for updates you have not confirmed`,
        }),
        el("p", {
          text:
            "These are the states this host was in immediately before an update moved its " +
            "ferrum pin. Ordinary retention would have retired them after " +
            "ferrum.storage.keepGenerations more applies; they are held so an update that turns " +
            "out bad is still reversible weeks later.",
        }),
        el("p", {
          text:
            "They cost disk, and they go on costing it until you say the update is good. " +
            "Confirming does not delete anything — it returns them to ordinary retention, so " +
            "they stay rollbackable for exactly as long as any other change of the same age.",
        }),
        el("div", { class: "row" }, [
          el("button", {
            type: "button",
            text: "Confirm these updates are good",
            onclick: async () => {
              status.textContent = "";
              try {
                const { id } = await api.startJob("confirm_update");
                setStatus(`Confirming (${id}).`);
                status.textContent =
                  "Releasing the held snapshots. Reload this page to see the result.";
              } catch (err) {
                setStatus(err.message, "error");
              }
            },
          }),
        ]),
        status,
      ])
    : null;

  view().replaceChildren(
    el("section", {}, [
      el("h2", { text: "Generations" }),
      confirm,
      el("table", {}, [
        el("thead", {}, [
          el("tr", {}, [
            el("th", { text: "#" }),
            el("th", { text: "Built" }),
            el("th", { text: "" }),
            el("th", { text: "" }),
          ]),
        ]),
        rows,
      ]),
    ]),
  );
}

// --- updates -------------------------------------------------------------

/// The four values `candidate.state` can carry on the check_update report.
///
/// Kept on one line because the `updates-view-is-wired` flake check reads
/// this file as text, cross-checks these names against CANDIDATE_STATE_TEXT's
/// keys, AND cross-checks them against ferrum-apply's own `CandidateState`
/// enum. A state the daemon can send with no branch here fails the build
/// instead of rendering as an empty cell -- which is the failure this view
/// exists to prevent, since "we could not check" and "you are up to date"
/// look identical when a branch is missing.
///
/// There is no `not-checked` here, unlike APP_STATES below. Every code path
/// that produces a candidate report has already resolved one of these five;
/// "this host has never checked at all" is not a candidate state, it is the
/// endpoint's own `never-checked` envelope status, rendered separately.
///
/// `order-unknown` is the newest of them and the one that carries the most
/// weight. Ordering rests entirely on the `lastModified` each side reports
/// for itself, and no ancestry is ever established, so there are real cases
/// -- an unparseable probe, or a locked timestamp sitting in this host's
/// future -- where ferrum knows the candidate DIFFERS and cannot honestly say
/// which way. Collapsing that into `not-newer` is what turns one skewed clock
/// into a permanent, silent "nothing to do".
// Kept on one line: updates-view-is-wired parses this as a single-line array
// literal to cross-check it against the Rust CandidateState enum, and reading
// no names out of it would make its branch-coverage assertion vacuous. It
// fails loudly rather than passing empty, which is how this comment came to
// be here.
const CANDIDATE_STATES = ["up-to-date", "pinned-exactly", "not-newer", "update-available", "check-failed", "order-unknown"];

/// The five values an entry in `apps[]`'s `state` can carry. Same file, same
/// flake check, same cross-check against `AppState`.
///
/// `not-checked` DOES exist on this side and is reachable: an enabled app
/// whose current version is known while the candidate side never resolved.
/// It is explicitly not a claim that the app is up to date.
const APP_STATES = ["not-checked", "up-to-date", "update-available", "excluded", "evaluation-failed"];

/// The five values `pinProvenance.state` can carry (R8).
///
/// Same file, same flake check, same cross-check against ferrum-apply's
/// `PinProvenanceState`. This is the answer to a question nothing else on
/// the report asks: `candidate.currentRev` is the pin on DISK, which is
/// where the next build starts — this says where the system you are looking
/// at actually came from, and the two are not the same claim on a host that
/// has been rolled back.
///
/// Three unknowns rather than one, deliberately. "The lock does not pin
/// ferrum in a shape ferrum reads" and "this generation predates the field
/// that would have recorded its pin" send an operator to different places,
/// and the second is the ordinary state of every generation on a host that
/// predates this feature.
const PIN_STATES = ["matches", "differs", "on-disk-unknown", "running-unknown", "both-unknown"];

/// The three keys `GET /api/updates` always answers with, and the two values
/// its `status` can take.
///
/// Both lines are cross-checked by `updates-view-is-wired` against what
/// ferrumd's `report_body`/`never_checked_body` actually construct. This is
/// the join the whole screen turns on: taking "never checked" from `status`
/// instead of inferring it from an empty document only works for as long as
/// that literal is what the daemon sends, and nothing but this check would
/// notice it being renamed.
const UPDATES_ENVELOPE_KEYS = ["status", "jobId", "report"];
const UPDATES_ENVELOPE_STATUSES = ["report", "never-checked"];

/// What is wrong with an `/api/updates` envelope, if anything.
///
/// The UI is a long-lived tab and the daemon can be rebuilt under it (1.5b's
/// global constraint), so an envelope this page cannot read is an ordinary
/// event, not an impossible one. Saying which key is missing beats rendering
/// an empty screen and leaving the operator to guess.
///
/// @param {object|null} envelope - The parsed body of `GET /api/updates`.
/// @returns {string|null} An operator-facing problem, or null when the
///   envelope is one this page knows how to read.
function envelopeProblem(envelope) {
  if (envelope === null || typeof envelope !== "object") {
    return "The daemon's reply to /api/updates was not an object. This page cannot read it.";
  }
  const missing = UPDATES_ENVELOPE_KEYS.filter((key) => !(key in envelope));
  if (missing.length) {
    return `The daemon's reply to /api/updates is missing ${missing.join(", ")}. This page is probably older than the daemon serving it — reload it.`;
  }
  if (!UPDATES_ENVELOPE_STATUSES.includes(envelope.status)) {
    return `The daemon answered with status "${orUnknown(envelope.status)}", which this page does not understand. It knows: ${UPDATES_ENVELOPE_STATUSES.join(", ")}.`;
  }
  return null;
}

/// A state's short label and the sentence that explains it.
///
/// @param {string} label - The words shown in the status cell.
/// @param {string} prose - One sentence saying what that state means for this host.
/// @returns {{label: string, prose: string}} The pair both state tables hold.
function stateText(label, prose) {
  return { label, prose };
}

// One entry per line, one distinct sentence per state, on purpose. "Never
// checked" and "up to date" are different facts about a host, and an
// unreachable check that reads as a clean result is precisely the confusion
// R1's edge cases name.
const CANDIDATE_STATE_TEXT = {
  "up-to-date": stateText("Up to date", "The tracked reference resolves to the revision this host already pins. There is nothing to apply."),
  "pinned-exactly": stateText(
    "Cannot check",
    "This host pins its ferrum input at an exact commit, which resolves to itself, so no newer release can be discovered however often the check runs. Your apps may well have updates waiting. Point the pin at a release branch or tag to start tracking them.",
  ),
  "not-newer": stateText("Candidate is not newer — not an update", "The tracked reference resolves to a revision that is older than the pinned one by the commit dates the two carry. ferrum will not offer it, the same way preview-migration refuses to call a lower schema version a migration."),
  "update-available": stateText("Update available", "A revision later than the pinned one exists, by the commit dates the two carry. Nothing has been fetched, built, or applied — a check only reads."),
  "check-failed": stateText("Could not check for updates", "The check did not complete, so this host's update state is unknown. That is not the same as being up to date."),
  "order-unknown": stateText("A different revision — ferrum cannot tell whether it is newer", "The tracked reference resolves to a revision this host does not pin, and ferrum could not establish which of the two came later. This is NOT a statement that you are up to date: there may well be an update here, and ferrum is declining to guess rather than answering. Both revisions are shown below; the judgement is yours."),
};

// "Would change" rather than "Update available" for a single app, deliberately.
// One nixpkgs pin supplies every app's package, so per-app wording that reads
// like an actionable per-app update would claim an independence ferrum does
// not have (R1's last criterion, R7).
const APP_STATE_TEXT = {
  "not-checked": stateText("Not checked", "No candidate has been resolved, so there is nothing to compare this app against."),
  "up-to-date": stateText("Up to date", "The candidate package set carries the version this app already runs."),
  "update-available": stateText("Would change", "The candidate package set carries a different version for this app. It moves with every other app, not on its own."),
  "excluded": stateText("Not shown — disabled", "This app is disabled, so nothing is running to compare against. It picks up the candidate's version if you enable it after updating."),
  "evaluation-failed": stateText("Could not evaluate", "Evaluating this app against the candidate failed. The row is kept, with the evaluator's own words, rather than dropped."),
};

// A first-class state, never an error. The two ways an operator reaches
// "differs" are both deliberate acts: rolling back (which reverts the
// system and not the lock) and a `git checkout` in /etc/ferrum that puts a
// machine-written flake.lock back.
const PIN_STATE_TEXT = {
  "matches": stateText("The running system was built from the pin on disk", "What you are running and what the next rebuild would start from are the same revision. This is the ordinary state."),
  "differs": stateText("Your on-disk pin is not the one the running system was built from", "The next rebuild would move this host to a different ferrum revision, whether or not you changed anything else. Usually this means you rolled back: a rollback reverts the system, never /etc/ferrum/flake.lock. Nothing happens behind your back — the Apply screen names the revision and asks before it moves you. To go the other way, `git -C /etc/ferrum checkout flake.lock` on the host puts the pin back."),
  "on-disk-unknown": stateText("Could not read the pin on disk", "/etc/ferrum/flake.lock could not be read, or does not pin ferrum in a shape ferrum recognises. Nothing is being claimed about where the running system came from."),
  "running-unknown": stateText("Pin unknown for the running generation", "Nothing records which revision this generation was built from. Generations applied before ferrum began recording it — and any applied outside ferrum-apply — read this way. It is an artifact of age, not a disagreement, and it is never treated as one: an apply is not gated on it."),
  "both-unknown": stateText("Pin unknown on both sides", "Neither the lock on disk nor the running generation's provenance could be established, so there is nothing to compare."),
};

/// A value the report may legitimately not know yet, rendered as words.
///
/// @param {string|number|null|undefined} value - A version, a revision, or nothing.
/// @returns {string} The value, or "unknown" -- never an empty cell, which
///   reads as "nothing changes" rather than "nobody looked".
function orUnknown(value) {
  return value === null || value === undefined || value === "" ? "unknown" : String(value);
}

/// How long ago an epoch-seconds instant was, in coarse operator words.
///
/// Every branch below is reached only with a count of two or more -- the
/// thresholds are 90 seconds and 36 hours, not 60 and 24 -- so there is no
/// singular form to write. That is deliberate rather than forgotten.
///
/// @param {number} epochSeconds - The report's `checkedAt`.
/// @returns {string} A phrase to follow "Checked": "just now", "7 minutes
///   ago", "3 days ago", or a plain statement that the timestamp is ahead of
///   this host's own clock.
function relativeAge(epochSeconds) {
  const seconds = Math.round(Date.now() / 1000 - Number(epochSeconds));
  if (!Number.isFinite(seconds)) return "at a time this page cannot read";
  // A clock that stepped backwards is the exact condition that makes the
  // daemon serve a stale report, so naming it beats clamping it to "just
  // now" and hiding the one visible clue that it happened.
  if (seconds < -60) return "at a time ahead of this host's own clock";
  if (seconds < 90) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 90) return `${minutes} minutes ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 36) return `${hours} hours ago`;
  return `${Math.round(hours / 24)} days ago`;
}

/// The status cell for one state, as words rather than a colour.
///
/// @param {{label: string, prose: string}|undefined} text - The state's entry
///   in its table, or undefined for a state this page has never heard of.
/// @param {string} raw - The wire value, shown when there is no entry for it.
/// @param {string|null} detail - The daemon's own words (an evaluator error,
///   or the reason an app is excluded), shown verbatim when present.
/// @param {string[]} vocabulary - The states this page has wording for, named
///   in the unknown branch so an operator can see the disagreement rather
///   than just the symptom.
/// @returns {HTMLElement} A cell body carrying the label, the explanation and
///   any verbatim detail.
function stateCell(text, raw, detail, vocabulary) {
  const known = text !== undefined;
  return el("div", { class: "state" }, [
    el("strong", { text: known ? text.label : `Unrecognised state: ${orUnknown(raw)}` }),
    el("p", {
      class: known ? "hint" : "error",
      text: known
        ? text.prose
        : `This page has no wording for that state and understands only: ${vocabulary.join(", ")}. It is probably older than the daemon serving it. Treat the state as unknown, not as up to date.`,
    }),
    detail ? el("pre", { class: "log detail", text: detail }) : null,
  ]);
}

/// One row of the per-app table.
///
/// Deliberately renders no control of any kind. A per-app button would imply
/// an app can be moved independently of the rest, which a single shared
/// nixpkgs pin makes false (R1's last acceptance criterion). The
/// `updates-view-is-wired` flake check reads this function's body and fails
/// if a control ever appears inside it.
///
/// @param {object} app - One entry of the report's `apps` array.
/// @param {object} catalogApps - `/api/catalog`'s apps map, for display names.
/// @returns {HTMLElement} A `<tr>` for the per-app table.
function appRow(app, catalogApps) {
  const meta = catalogApps[app.id] || {};
  return el("tr", {}, [
    el("th", { scope: "row" }, [
      el("span", { text: meta.displayName || app.id }),
      el("p", { class: "hint", text: app.enabled ? "Enabled" : "Disabled" }),
    ]),
    el("td", { text: orUnknown(app.currentVersion) }),
    el("td", { text: orUnknown(app.candidateVersion) }),
    el("td", {}, [
      stateCell(APP_STATE_TEXT[app.state], app.state, app.error || app.reason || null, APP_STATES),
    ]),
  ]);
}

/// Render the "no check has ever run here" answer.
///
/// A separate branch rather than a candidate state, because the daemon
/// answers it separately: `status: "never-checked"` carries no report at all,
/// and `CandidateState` has no `not-checked` value to borrow. Saying it in
/// prose keeps it visibly distinct from "up to date", which is the one
/// confusion R1's edge cases single out.
///
/// @param {HTMLElement} target - The element whose children are replaced.
/// @returns {void}
function renderNeverChecked(target) {
  target.replaceChildren(
    el("h3", { text: "This host has never checked for updates" }),
    el("p", {
      text:
        "No check has run here, so there is nothing to report. This is not a claim that you are up to date — nobody has looked yet.",
    }),
    el("p", { class: "hint", text: "Use “Check for updates” above. It reads only." }),
  );
}

/// Render a whole check_update report into the view's report region.
///
/// @param {HTMLElement} target - The element whose children are replaced.
/// @param {object} report - The producer's document, taken from the
///   endpoint's envelope. ferrumd models none of its fields and serves it
///   verbatim, so this is the only place its shape is read.
/// @param {object} catalogApps - `/api/catalog`'s apps map.
/// @param {string|null} jobId - The run this report came from, or null when
///   it came from a bare CLI run. Shown as provenance; never used as a job id.
/// @returns {void}
function renderUpdateReport(target, report, catalogApps, jobId) {
  const candidate = report.candidate || {};
  const ferrum = report.ferrum || {};
  const migration = report.schemaMigration || {};
  // Defaulted to the daemon's own "neither side known" value rather than to
  // `{}`: a report from a ferrum that predates this block has, truthfully,
  // established nothing about the pin — and an absent `state` would render
  // as "Unrecognised state: unknown", which blames the daemon for a field
  // it never claimed to send.
  const provenance = report.pinProvenance || { state: "both-unknown" };
  const apps = Array.isArray(report.apps) ? report.apps : [];
  const warnings = Array.isArray(report.warnings) ? report.warnings : [];

  const rows = el("tbody");
  for (const app of apps) rows.appendChild(appRow(app, catalogApps));

  // Warnings moved to the top of the report and given a callout of their own,
  // rather than sitting last as a plain list. The case that forced it: one
  // future-dated `lastModified` in the lock makes every genuinely later
  // release compare as older, so the screen says "not newer" forever and
  // nothing else on it ever looks wrong. The warning is the only thing on the
  // page that names a cause an operator can act on, and a footnote below the
  // apps table is not where it gets read.
  //
  // Deliberately NOT string-matched for the future-dated case: sniffing the
  // producer's wording for one warning would silently demote every warning it
  // failed to recognise, and the producer's text is not this file's to depend
  // on. Every warning is treated as conspicuous instead.
  const warningsBlock = warnings.length
    ? el("section", { class: "callout warn" }, [
        el("h3", { text: warnings.length === 1 ? "A warning about this check" : "Warnings about this check" }),
        el("ul", {}, warnings.map((w) => el("li", { text: String(w) }))),
      ])
    : null;

  // A report carrying no apps at all is a fact worth stating. An empty table
  // body would read as "nothing changes", which is a different claim.
  const appsBlock = apps.length
    ? el("div", { class: "table-scroll" }, [
        el("table", {}, [
          el("caption", { class: "hint", text: "Every catalog app this report covers, including the ones nothing can be said about." }),
          el("thead", {}, [
            el("tr", {}, [
              el("th", { scope: "col", text: "App" }),
              el("th", { scope: "col", text: "Current" }),
              el("th", { scope: "col", text: "Candidate" }),
              el("th", { scope: "col", text: "What the check found" }),
            ]),
          ]),
          rows,
        ]),
      ])
    : el("p", { text: "This report lists no apps. That is not the same as no app changing — it means the check produced no per-app result at all." });

  target.replaceChildren(
    // Prominent, not a muted footnote, and carrying its own age.
    //
    // The daemon picks "the newest report" by file mtime, so a host clock
    // that steps backwards between two checks -- NTP correcting a fast clock
    // -- makes a freshly written report look older and the previous one gets
    // served. ferrumd will not fix that by parsing the document, and should
    // not: treating the report as opaque is what keeps it from becoming a
    // second place the shape is written down. So the mitigation is here, and
    // the age is the part that does the work: an absolute timestamp still
    // leaves the operator doing arithmetic to notice that "the newest
    // report" predates the check they just ran.
    //
    // No trailing full stop: localTime renders in the operator's own locale,
    // and several of those (en-CA, en-GB 12-hour) end the string with "a.m."
    // -- a sentence period after one reads as a typo.
    el("p", {
      class: "checked-at",
      text: report.checkedAt
        ? `Checked ${relativeAge(report.checkedAt)} — ${localTime(report.checkedAt)}`
        : "This report carries no check time",
    }),

    el("p", {
      class: "hint",
      // Provenance, not a handle. A report written by a bare CLI run carries
      // no job id at all, and the envelope says so with null rather than a
      // placeholder -- so there is nothing here to feed back to /api/jobs.
      text: jobId
        ? `From check job ${jobId}`
        : "From a check run on the host itself, not from a job started here",
    }),

    report.schemaVersion !== 1
      ? el("p", {
          class: "error",
          text: `This report declares schema version ${orUnknown(report.schemaVersion)}, and this page understands only version 1. Some of it may be shown wrongly or not at all.`,
        })
      : null,

    warningsBlock,

    el("h3", { text: "The candidate" }),
    stateCell(CANDIDATE_STATE_TEXT[candidate.state], candidate.state, candidate.error || null, CANDIDATE_STATES),

    // Said once, under every ordering verdict, rather than qualified into
    // each state's own sentence. "Newer" here means nothing but: the commit
    // date the candidate reports for itself is later than the one the lock
    // records. Git commit dates are chosen by whoever makes the commit and
    // ferrum establishes no ancestry between the two revisions, so this is
    // self-reported metadata, not proof. It belongs in the same voice as the
    // trust section at the foot of this screen.
    el("p", {
      class: "hint",
      text: "Newer and older here mean only that one commit date is later than the other. Those dates are set by whoever made the commit, and ferrum does not establish that either revision descends from the other.",
    }),

    el("dl", { class: "facts" }, [
      el("dt", { text: "Tracked input" }),
      el("dd", { text: `${orUnknown(candidate.inputName)} — ${orUnknown(candidate.inputUrl)}` }),
      el("dt", { text: "Tracked reference" }),
      el("dd", { text: orUnknown(candidate.reference) }),
      // Named as the pin, not as the running revision. This value is read
      // out of /etc/ferrum/flake.lock, which is the pin the NEXT build would
      // start from. What the RUNNING system was built from is a separate
      // claim, and it now has a separate section below rather than being
      // quietly asserted here -- asserting the equality on this line is what
      // the earliest wording got wrong, on the one field the operator is
      // asked to read and refuse in place of a signature check.
      el("dt", { text: "Revision pinned in /etc/ferrum/flake.lock" }),
      el("dd", {}, [el("code", { class: "rev", text: orUnknown(candidate.currentRev) })]),
      el("dt", { text: "Candidate revision" }),
      el("dd", {}, [el("code", { class: "rev", text: orUnknown(candidate.rev || ferrum.candidateRev) })]),
    ]),

    el("h3", { text: "Where the running system came from" }),
    stateCell(PIN_STATE_TEXT[provenance.state], provenance.state, null, PIN_STATES),
    // Only on `differs`, where they are two facts the operator has to read.
    // On every other state the producer sends null, and a facts list of
    // "unknown / unknown" under a sentence that already said so would be
    // noise.
    provenance.state === "differs"
      ? el("dl", { class: "facts" }, [
          el("dt", { text: "The running system was built from" }),
          el("dd", {}, [el("code", { class: "rev", text: orUnknown(provenance.runningRev) })]),
          el("dt", { text: "The next build would start from" }),
          el("dd", {}, [el("code", { class: "rev", text: orUnknown(provenance.onDiskRev) })]),
          // Present only when the revision is NOT what moved -- a reference
          // re-pointed at a new tree under one revision, where showing that
          // revision twice would read as a bug rather than as the finding.
          ...(provenance.onDiskNarHash
            ? [
                el("dt", { text: "…and the tree behind that one revision" }),
                el("dd", {
                  text: `${orUnknown(provenance.runningNarHash)} → ${orUnknown(provenance.onDiskNarHash)}`,
                }),
              ]
            : []),
        ])
      : null,

    el("h3", { text: "ferrum itself" }),
    el("p", {
      text: `ferrum ${orUnknown(ferrum.currentVersion)} → ${orUnknown(ferrum.candidateVersion)}.`,
    }),
    el("p", {
      class: "hint",
      text: "ferrum's own release version moves with the same pin as the apps below. It is not a separate check and cannot be taken separately.",
    }),

    el("h3", { text: "Apps" }),
    report.appsError
      ? el("p", { class: "error", text: `The per-app evaluation failed as a whole: ${report.appsError}` })
      : null,
    appsBlock,

    el("h3", { text: "Settings schema" }),
    el("p", {
      text: migration.pending
        ? `A settings-schema migration is pending: version ${orUnknown(migration.currentVersion)} → ${orUnknown(migration.targetVersion)}.`
        : `No settings-schema migration is pending. On-disk version ${orUnknown(migration.currentVersion)}, this ferrum's version ${orUnknown(migration.targetVersion)}.`,
    }),
    migration.note ? el("p", { class: "hint", text: migration.note }) : null,
    migration.error ? el("pre", { class: "log detail", text: migration.error }) : null,
    el("p", {
      class: "hint",
      text:
        "ferrum cannot tell you whether you have seen this migration before: the step that would record having shown it is not built. A pending migration therefore reappears on every check, and seeing it twice is not evidence that anything went wrong.",
    }),

  );
}

/// Ask before committing to an update, naming the exact revision.
///
/// The same "review, then commit" shape the Apply view and `confirmRollback`
/// already use — this screen does not invent a second one. What it adds over
/// those two is the revision itself: DA-1 makes seeing the exact commit, and
/// being able to refuse it, the control that stands in place of signature
/// verification, so a dialog that said "apply the update?" without naming it
/// would remove the only thing being verified.
///
/// @param {object} candidate - The report's `candidate` object.
/// @returns {Promise<boolean>} True when the operator confirmed.
function confirmUpdate(candidate) {
  const dialog = el("dialog", { class: "confirm" });
  const rev = candidate.rev || "an unknown revision";

  dialog.appendChild(
    el("form", { method: "dialog" }, [
      el("h3", { text: "Update this host?" }),
      el("p", { text: "ferrum will move the pin in /etc/ferrum/flake.lock to this exact revision:" }),
      el("p", {}, [el("code", { class: "rev", text: rev })]),
      el("h4", { text: "What this does" }),
      el("p", {
        text:
          "It rewrites one line of bookkeeping — flake.lock — and then rebuilds and switches " +
          "the system, exactly as “Apply now” does. Your apps stop while it switches. The " +
          "result is an ordinary generation you can roll back from, with its own state " +
          "snapshot, like any other change.",
      }),
      el("h4", { text: "What it does not do" }),
      el("p", {
        text:
          "It never writes /etc/ferrum/flake.nix — the file that decides which repository and " +
          "which reference this host trusts stays byte-for-byte as you wrote it. It cannot " +
          "update one app without the others. And it does not commit anything to your git " +
          "tree: flake.lock will be left modified for you to review and commit.",
      }),
      el("p", {
        class: "hint",
        text:
          "ferrum verifies no signature on this revision, and evaluates it as root. Reading " +
          "the revision above and refusing it if it is not what you expect is the whole of " +
          "that control.",
      }),
      el("div", { class: "row" }, [
        el("button", { value: "cancel", text: "Cancel" }),
        el("button", { value: "confirm", class: "danger", text: "Update and rebuild" }),
      ]),
    ]),
  );

  document.body.appendChild(dialog);
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      const ok = dialog.returnValue === "confirm";
      dialog.remove();
      resolve(ok);
    });
    dialog.showModal();
  });
}

/// Split a `"<token>: <sentence>"` job detail into its two halves.
///
/// `progress::complete` writes `"<result>: <detail>"` into one `detail`
/// field, so the result the job reached and the sentence explaining it
/// arrive as one string. Parsed on the FIRST separator only: an update's own
/// message contains colons of its own, and splitting on all of them would
/// truncate the sentence the operator is meant to read.
///
/// The Apply view's `pin-gate` event deliberately writes the same shape,
/// with the revision in the token position, so the one value that must
/// arrive verbatim is read rather than scraped out of prose.
///
/// @param {string} detail - The `complete` event's detail.
/// @returns {{result: string, message: string}} The job's result word and
///   its message; the whole string as the message when there is no separator.
function splitCompletion(detail) {
  const text = String(detail ?? "");
  const at = text.indexOf(": ");
  if (at < 0) return { result: text.trim(), message: "" };
  return { result: text.slice(0, at).trim(), message: text.slice(at + 2).trim() };
}

/// The Updates view: what a read-only check found, and the one deliberate
/// step that acts on it.
///
/// @returns {Promise<void>} Resolves once the shell is painted and either a
///   stored report has been rendered or an in-flight job reattached to.
async function updatesView() {
  closeStream();

  const error = el("p", { class: "error" });
  const pending = el("p", { class: "hint", role: "status", "aria-live": "polite" });
  const report = el("div", {});
  // Painted directly BELOW the report, never above it: R4 requires the
  // preview to be what the operator read immediately before committing, and
  // a control above the thing it commits to is a control you can press
  // without having read it.
  const commit = el("section", {});
  const outcome = el("p", { role: "status", "aria-live": "polite" });
  const log = el("pre", { class: "log", hidden: true });

  // Whether a check this view started or reattached to is still in flight.
  //
  // This flag is the ONLY bound on concurrent checks anywhere in the system,
  // which is why it is a closure variable rather than a read of the button's
  // own disabled state: the daemon exempts check_update from its single-job
  // interlock on purpose (a rollback must never be blocked by a read-only
  // check), POST /api/jobs is not rate limited, and the systemd template puts
  // no limit on concurrent instances. Each check is roughly 2N+2 whole
  // module-system nix evaluations as root on an N-app host, and nix eval is
  // memory-heavy -- so an impatient double-click is a real self-DoS against
  // the very apps this page is reporting on.
  //
  // A UI latch is not a substitute for a daemon-side bound. It is the part of
  // the mitigation that belongs here.
  let checking = false;

  /// Whether an update this view started or reattached to is still running.
  ///
  /// Separate from `checking` because the two jobs are not interchangeable:
  /// the daemon's single-job interlock already bounds concurrent updates
  /// (an update takes it, a check does not), so this latch is an affordance
  /// rather than the only bound — the opposite of `checking`, which IS the
  /// only bound there is.
  let updating = false;

  /// Moves the check control in or out of its in-flight state.
  ///
  /// @param {boolean} inFlight - Whether a check is running right now.
  /// @returns {void}
  function setChecking(inFlight) {
    checking = inFlight;
    check.disabled = inFlight;
    check.setAttribute("aria-busy", String(inFlight));
    // The label carries the state, so it survives without colour and is read
    // out by anything that reaches the button. The dimming in style.css is
    // the secondary cue, never the only one. The live `pending` region below
    // announces the same fact to a screen reader that is not on the button.
    check.textContent = inFlight ? "Checking for updates…" : "Check for updates";
  }

  function attach(id) {
    // A previous stream is closed rather than dropped. `attach` is reachable
    // twice for one job -- this view paints before its two awaits, so a click
    // can land first and the reattach finder below then finds that same job
    // still running -- and overwriting state.stream without closing it left
    // two EventSources tailing one job: every log line twice, and one
    // connection leaked for as long as the tab lives.
    closeStream();
    setChecking(true);
    log.hidden = false;
    log.textContent = "";
    // Written for slow, not for instant. The real cost of a candidate check
    // is unmeasured -- it overrides an input the store has never seen and
    // evaluates the whole module system against it -- and a screen that
    // implied otherwise would be lying about the one thing nobody has timed.
    pending.textContent = "Checking for updates. This can take a while: ferrum resolves the candidate and evaluates the whole configuration against it.";
    state.stream = api.streamJob(id, {
      onEvent: (e) => {
        log.textContent += `${e.event}: ${e.detail}\n`;
        log.scrollTop = log.scrollHeight;
      },
      onDone: async () => {
        pending.textContent = "";
        try {
          const envelope = await api.updatesForJob(id);
          const problem = envelopeProblem(envelope);
          if (problem) {
            error.textContent = problem;
          } else {
            renderUpdateReport(report, envelope.report, state.catalog?.apps || {}, envelope.jobId);
            renderCommit(envelope.report.candidate || null);
            setStatus("Check finished.", "ok");
          }
        } catch (err) {
          // A 404 here means THIS run wrote no report -- it failed before it
          // could, or it is somehow still going. The daemon's own message
          // says exactly that, and it is deliberately not the never-checked
          // answer, so it stays in the error line rather than replacing the
          // report region with "nobody has looked yet".
          error.textContent = err.message;
        } finally {
          // Whatever the report fetch did, the job itself is over. Re-enabling
          // only on the success branch would leave a host whose check failed
          // with a control that never comes back -- a worse fault than the one
          // this latch exists to prevent.
          setChecking(false);
        }
      },
      onError: () => {
        // EventSource reconnects by itself, so an error is not terminal and
        // re-enabling on every one would hand out a second root job to an
        // operator whose check is merely blinking. The exception is a stream
        // the browser has closed for good -- a 404 or a non-event-stream
        // reply -- where `complete` is never coming and the latch would
        // otherwise be stuck for the life of the view.
        if (state.stream?.readyState !== EventSource.CLOSED) return;
        closeStream();
        pending.textContent = "";
        error.textContent =
          "Lost the connection to this check's progress log. The check may still be running on the host — reload this page to pick it up again.";
        setChecking(false);
      },
    });
  }

  /// Follow a running update job and report what it did.
  ///
  /// @param {string} id - The job id.
  /// @returns {void}
  function attachUpdate(id) {
    closeStream();
    updating = true;
    log.hidden = false;
    log.textContent = "";
    outcome.textContent = "";
    pending.textContent =
      "Updating. The system is rebuilding and will switch when the build finishes; your apps " +
      "stop during the switch.";
    state.stream = api.streamJob(id, {
      onEvent: (e) => {
        log.textContent += `${e.event}: ${e.detail}\n`;
        log.scrollTop = log.scrollHeight;
      },
      onDone: (e) => {
        pending.textContent = "";
        updating = false;
        const { result, message } = splitCompletion(e.detail);
        // The job's own words, not a sentence this file composes from the
        // result word. "no change — nothing to apply" is a distinct outcome
        // from "updated to <rev> as generation N", and only the job knows
        // which happened — it is the side that can see whether a generation
        // was created. A UI that said "Updated." for both would be stating
        // something nobody checked.
        outcome.textContent = message || result;
        // Only classes style.css actually defines. A degraded update gets
        // the same callout a warning on this screen already gets; a failure
        // gets the same `.error` every other failure here gets. Colour is
        // never the only signal: the sentence itself says what happened,
        // and the live region announces it.
        outcome.className =
          result === "succeeded" ? "" : result === "degraded" ? "callout warn" : "error";
        setStatus(`Update ${result}.`, result === "succeeded" ? "ok" : "error");
        // The report on screen described the host as it was before this ran,
        // so it is now stale whatever the outcome. Said rather than silently
        // left there to be read as current.
        renderCommit(null, "This report predates the update you just ran. Check again to see where this host stands now.");
      },
      onError: () => {
        if (state.stream?.readyState !== EventSource.CLOSED) return;
        closeStream();
        pending.textContent = "";
        updating = false;
        error.textContent =
          "Lost the connection to this update's progress log. The update may still be running on the host — reload this page to pick it up again.";
      },
    });
  }

  /// Paint the commit control, or the reason there is none.
  ///
  /// @param {object|null} candidate - The report's `candidate` object, or
  ///   null when there is no usable report.
  /// @param {string|null} [note] - A replacement explanation, used after an
  ///   update has made the report on screen stale.
  /// @returns {void}
  function renderCommit(candidate, note = null) {
    if (note) {
      commit.replaceChildren(el("p", { class: "hint", text: note }));
      return;
    }
    if (!candidate) {
      commit.replaceChildren();
      return;
    }
    // Keyed on the one state that means "there is something newer, and
    // ferrum established that it is newer". Every other state — including
    // order-unknown, where ferrum found a different revision and could not
    // say which way — renders no control at all, because the daemon would
    // refuse the job anyway and an affordance that always fails is worse
    // than none.
    if (candidate.state !== "update-available") {
      commit.replaceChildren(
        el("p", {
          class: "hint",
          text:
            candidate.state === "up-to-date"
              ? "Nothing to apply: this host already runs the revision the tracked reference points at."
              : "No update can be applied from this report. Nothing above establishes a newer revision to move to, and ferrum will not move to one it cannot order.",
        }),
      );
      return;
    }

    const update = el("button", {
      type: "button",
      class: "danger",
      text: "Update and rebuild",
      onclick: async () => {
        if (updating) return;
        error.textContent = "";
        if (!(await confirmUpdate(candidate))) return;
        updating = true;
        update.disabled = true;
        pending.textContent = "Starting the update…";
        try {
          const { id } = await api.startJob("update");
          setStatus(`Update started (${id}).`);
          attachUpdate(id);
        } catch (err) {
          // An update takes the daemon's single-job interlock, exactly as
          // an apply does, so 409 is a real and ordinary answer here —
          // unlike on the check above, which is exempt from it.
          if (err.status === 409) {
            const running = (await api.jobs(5)).jobs.find((j) => j.status === "running");
            error.textContent = running
              ? `A ${running.kind || "job"} started at ${localTime(running.started_at)} is still running (${running.id}). Wait for it to finish.`
              : "A job is already running.";
          } else {
            error.textContent = err.message;
          }
          pending.textContent = "";
          updating = false;
          update.disabled = false;
        }
      },
    });

    commit.replaceChildren(
      el("h3", { text: "Apply this update" }),
      el("p", {
        text:
          "Everything above is what this will change. Checking never applies anything; this is " +
          "the separate, deliberate step — the same split Save and Apply already use for " +
          "settings.",
      }),
      el("div", { class: "row" }, [update]),
      el("p", {
        class: "hint",
        text:
          "If the rebuilt system turns out identical to the one already running, ferrum will " +
          "say “no change — nothing to apply” and create no generation. That is a real outcome, " +
          "not a failure.",
      }),
    );
  }

  const check = el("button", {
    type: "button",
    text: "Check for updates",
    onclick: async () => {
      // The guard, not the disabled attribute, is what makes a second click
      // harmless: `disabled` is the affordance an operator sees, this is the
      // thing that holds even if a click arrives some other way.
      if (checking) return;
      error.textContent = "";
      // Latched here, synchronously, BEFORE the await -- the handler stays
      // live across it, so anything set afterwards would leave the window a
      // double-click already fits through.
      setChecking(true);
      // Announced, not merely shown: disabling the button takes focus off it,
      // so the live region above is what tells a screen-reader user that the
      // click landed. `attach` replaces this with the longer wait message.
      pending.textContent = "Starting an update check…";
      // No 409 branch, unlike the Apply view. A read-only check deliberately
      // does not claim the daemon's single-job interlock: the one path that
      // has to keep working on a host an update just broke is the rollback a
      // shared interlock would block.
      try {
        const { id } = await api.startJob("check_update");
        setStatus(`Update check started (${id}).`);
        attach(id);
      } catch (err) {
        error.textContent = err.message;
        pending.textContent = "";
        // Deliberately not a `finally`: on the success path the latch is
        // handed to `attach`, which holds it until the stream ends.
        setChecking(false);
      }
    },
  });

  // Painted before anything is awaited, so an operator arriving here never
  // sees the previous view's DOM sitting under an "Updates" heading while a
  // slow check runs.
  view().replaceChildren(
    el("section", { class: "updates" }, [
      el("h2", { text: "Updates" }),
      el("p", {
        text:
          "Checking reads only. It resolves what the tracked reference points at and works out what your configuration would become — it writes nothing, builds nothing and switches nothing. Applying is a separate, deliberate step below the report, the same split Save and Apply already use for settings.",
      }),
      el("p", {
        class: "hint",
        text:
          "ferrum cannot update one app without the others. A single nixpkgs pin supplies every app's package, so every version below moves together or not at all. There is no per-app update control here because there is no per-app update to offer.",
      }),
      // R7's second criterion. The honest answer to "can I hold Sonarr
      // back?" is no — and then the one lever that does exist, named,
      // rather than leaving an operator to go looking for a control this
      // phase did not build. It REMOVES an app from tracking the shared pin
      // rather than letting it move ahead of it, which is a different thing
      // and is said as such.
      el("p", {
        class: "hint",
        text:
          "If you need one app held at a specific version, the lever is the custom/ override on the host — `services.<app>.package = ...` in your own Nix. That takes the app out of the shared pin rather than letting it move independently of it, and ferrum will then report it as unaffected by any update, because it is.",
      }),
      // R7's third criterion. Enabling an app is an ordinary settings
      // change; it reaches the host through Apply, not through this screen.
      el("p", {
        class: "hint",
        text:
          "Enabling an app you have never run is not an update. It arrives with the next ordinary Apply, at whatever version the pin you already have supplies — so a newly enabled app shows a version here without that version being something this screen can move.",
      }),
      el("div", { class: "row" }, [check]),
      pending,
      error,
      outcome,
      log,
      report,
      commit,
      el("section", {}, [
        el("h3", { text: "What you are trusting" }),
        el("p", {
          text:
            "A candidate is evaluated as root, with the build sandbox's purity disabled, exactly as an ordinary apply is. ferrum verifies no signature on it: pointing this host at a ferrum release is itself the trust decision.",
        }),
        el("p", {
          text:
            "Seeing the exact candidate revision above, before anything is applied, is the control that stands in place of that signature. Read it, and refuse it if it is not what you expect.",
        }),
        el("p", {
          class: "hint",
          text:
            "An operator who wants no delegated trust can keep pinning an exact commit by hand in /etc/ferrum/flake.nix. This feature never takes that away.",
        }),
      ]),
    ]),
  );

  pending.textContent = "Loading the most recent check…";
  try {
    const envelope = await api.updates();
    const problem = envelopeProblem(envelope);
    // Taken from `status`, never inferred from an absent or empty report:
    // the daemon answers the question explicitly, and guessing it from the
    // document's shape is how "never checked" starts reading as "up to date".
    if (problem) {
      error.textContent = problem;
    } else if (envelope.status === "never-checked") {
      renderNeverChecked(report);
      renderCommit(null);
    } else {
      renderUpdateReport(report, envelope.report, state.catalog?.apps || {}, envelope.jobId);
      renderCommit(envelope.report.candidate || null);
    }
  } catch (err) {
    error.textContent = err.message;
  }
  pending.textContent = "";

  // Nothing to reattach to when this view is already following a check: a
  // click that landed while the two awaits above were outstanding has already
  // attached to the very job this finder would go looking for.
  if (checking || updating) return;

  // Reattach to a check or an update still running from a previous page
  // load. Filtered on kind as well as status, unlike the Apply view's finder
  // above: an unfiltered one here would tail a rollback or a gc job into
  // this screen's log and then ask /api/updates for a report that job never
  // produced. The two kinds are found separately and attached by different
  // handlers, because what happens when the stream ends differs -- a check
  // has a report to fetch, an update has an outcome sentence to show and a
  // now-stale report on screen to disown.
  try {
    const recent = await api.jobs(10);
    const update = recent.jobs.find((j) => j.status === "running" && j.kind === "update");
    if (update) {
      setStatus("Reattached to an update already running.");
      attachUpdate(update.id);
      return;
    }
    const running = recent.jobs.find((j) => j.status === "running" && j.kind === "check_update");
    if (running) {
      setStatus("Reattached to an update check already running.");
      attach(running.id);
    }
  } catch (err) {
    error.textContent = err.message;
  }
}

// --- parity --------------------------------------------------------------

/// The eight values a parity report's `state` can carry.
///
/// Kept on one line because the `parity-view-is-wired` flake check reads this
/// file as text, cross-checks these names against PARITY_STATE_TEXT's keys,
/// AND cross-checks them against ferrum-apply's own `ParityState` enum. A
/// state the daemon can send with no branch here fails the build instead of
/// rendering as an empty tile -- which is the exact failure this view exists
/// to prevent, since "nobody looked" and "you are protected" look identical
/// when a branch is missing.
///
/// `not-configured` is a state of the HOST, reported inside a report. It is
/// not the same fact as the envelope's `never-checked`, which means no report
/// exists yet, and the two are rendered separately below.
const PARITY_STATES = ["not-configured", "syncing", "never-synced", "last-sync-failed", "parity-disk-missing", "in-sync", "stale", "unknown"];

/// The three keys `GET /api/parity` always answers with, and the two values
/// its `status` can take. Cross-checked by the same flake check against what
/// ferrumd's parity.rs actually constructs.
const PARITY_ENVELOPE_KEYS = ["status", "jobId", "report"];
const PARITY_ENVELOPE_STATUSES = ["report", "never-checked"];

// One entry per line, one distinct sentence per state. Every one of these is
// a different thing to do next, and a tile that said "protected" for any of
// the unhealthy ones would be the frozen gauge this whole feature exists to
// avoid shipping.
const PARITY_STATE_TEXT = {
  "not-configured": stateText("Parity is not set up on this host", "No disk is dedicated to parity, so losing a data disk loses everything that was on it. The other disks are unaffected -- mergerfs does not stripe -- but what was on the failed one is gone."),
  "syncing": stateText("A parity sync is running", "Parity is being brought up to date right now. What has changed is not reported during a sync: the array is being rewritten underneath the question."),
  "never-synced": stateText("Parity is set up but has never completed a sync", "Nothing is protected yet. The first sync reads every file on every data disk and is the slowest one; it runs on the schedule, or you can start it here."),
  "last-sync-failed": stateText("The last parity sync did not succeed", "Parity is as old as the last sync that DID succeed, and may be older than the timestamp below suggests. This is not the same as being out of date -- something went wrong and is likely still wrong."),
  "parity-disk-missing": stateText("A parity disk is missing", "The parity disk is not mounted, so parity cannot rebuild anything no matter how recent its last sync was. Check that the disk is attached and that its mount came up."),
  "in-sync": stateText("Protected -- parity is current", "Every file on the data disks is covered by parity as of the last sync, and nothing has changed since."),
  "stale": stateText("Files have changed since the last parity sync", "Those files are not protected yet: if a data disk failed right now, they would be lost. Everything synced before them is still covered."),
  "unknown": stateText("ferrum could not determine the parity state", "The check did not complete, so this host's parity state is unknown. That is not the same as being protected."),
};

/// Which states mean parity is genuinely doing its job.
///
/// Used only to decide whether the limitation sentence reads as a qualifier
/// on good news or as context on bad news. It is shown either way (R6).
const PARITY_OK_STATES = ["in-sync"];

/// What is wrong with a `/api/parity` envelope, if anything.
///
/// @param {object|null} envelope - The parsed body of `GET /api/parity`.
/// @returns {string|null} An operator-facing problem, or null when the
///   envelope is one this page knows how to read.
function parityEnvelopeProblem(envelope) {
  if (envelope === null || typeof envelope !== "object") {
    return "The daemon's reply to /api/parity was not an object. This page cannot read it.";
  }
  const missing = PARITY_ENVELOPE_KEYS.filter((key) => !(key in envelope));
  if (missing.length) {
    return `The daemon's reply to /api/parity is missing ${missing.join(", ")}. This page is probably older than the daemon serving it -- reload it.`;
  }
  if (!PARITY_ENVELOPE_STATUSES.includes(envelope.status)) {
    return `The daemon answered with status "${orUnknown(envelope.status)}", which this page does not understand. It knows: ${PARITY_ENVELOPE_STATUSES.join(", ")}.`;
  }
  return null;
}

/// Paints one parity report into `host`.
///
/// Renders the state, then the timestamp it was computed from, then the
/// figure -- in that order and never the figure alone. A changed-file count
/// with no "as of when" beside it is a number an operator cannot act on.
///
/// @param {HTMLElement} host - The container to replace the contents of.
/// @param {object} report - The producer's document, verbatim.
/// @returns {void}
function renderParityReport(host, report) {
  host.replaceChildren();
  const reportState = String(report?.state ?? "");
  const text = PARITY_STATE_TEXT[reportState];
  if (!text) {
    host.appendChild(el("p", {
      class: "error",
      text: `The daemon reported parity state "${orUnknown(reportState)}", which this page does not know how to render. It knows: ${PARITY_STATES.join(", ")}.`,
    }));
    return;
  }

  host.appendChild(el("h3", { text: text.label }));
  host.appendChild(el("p", { text: text.prose }));

  const rows = [];
  if (report.lastSync) {
    rows.push(["Last sync", `${localTime(report.lastSync.finishedAt)} (${relativeAge(report.lastSync.finishedAt)})`]);
    rows.push(["Result reported by systemd", orUnknown(report.lastSync.result)]);
  } else {
    rows.push(["Last sync", "never -- no completed sync has been recorded on this host"]);
  }

  if (report.unprotected) {
    const u = report.unprotected;
    const changed = Number(u.added) + Number(u.removed) + Number(u.updated);
    rows.push([
      "Changed since that sync",
      `${changed} file(s) -- ${orUnknown(u.added)} added, ${orUnknown(u.updated)} modified, ${orUnknown(u.removed)} removed`,
    ]);
  } else {
    rows.push(["Changed since that sync", `not available -- ${orUnknown(report.unprotectedUnavailable)}`]);
  }
  // Always shown, in every state. A line that appeared only sometimes would
  // read, when absent, as "there IS a size figure here".
  rows.push(["Size of the unprotected data", orUnknown(report.unprotectedBytesUnavailable)]);

  for (const d of report.parityDisks || []) {
    rows.push([`Parity file ${d.path}`, d.present ? "its disk is mounted" : "ITS DISK IS NOT MOUNTED"]);
  }
  rows.push(["This report was produced", `${localTime(report.generatedAt)} (${relativeAge(report.generatedAt)})`]);

  host.appendChild(
    el("table", {}, [
      el("tbody", {}, rows.map(([k, v]) => el("tr", {}, [el("th", { text: k }), el("td", { text: v })]))),
    ]),
  );

  // R6. Carried on EVERY surface that reports a healthy state, and taken from
  // the report rather than written here, so the one sentence the product
  // commits to lives in one place. Shown in the other states too -- somebody
  // reading "a parity disk is missing" is exactly somebody deciding how
  // worried to be.
  host.appendChild(
    el("p", {
      class: PARITY_OK_STATES.includes(reportState) ? "callout" : "callout warn",
      text: orUnknown(report.limitation),
    }),
  );
}

/// The Parity view: what parity protects, as of when, and what it does not.
///
/// Four states, all rendered and none blank: loading (a live region says the
/// report is being read), empty (`never-checked`), error (the envelope
/// problem or the request's own message), and success (a report).
///
/// @returns {Promise<void>}
async function parityView() {
  closeStream();

  const error = el("p", { class: "error" });
  const pending = el("p", { class: "hint", role: "status", "aria-live": "polite" });
  const report = el("div", {});
  const log = el("pre", { class: "log", hidden: true });

  // Whether a check or a sync this view started is still in flight.
  let busy = false;

  const check = el("button", { type: "button", text: "Check parity now" });
  const sync = el("button", { type: "button", text: "Sync parity now" });

  /// Moves both controls in or out of their in-flight state.
  ///
  /// The LABEL carries the state, so it survives without colour and is read
  /// out by anything that reaches the button; the dimming is the secondary
  /// cue, never the only one.
  ///
  /// @param {boolean} inFlight - Whether a job is running right now.
  /// @param {string} what - "check" or "sync", for the label.
  /// @returns {void}
  function setBusy(inFlight, what) {
    busy = inFlight;
    check.disabled = inFlight;
    sync.disabled = inFlight;
    check.setAttribute("aria-busy", String(inFlight));
    sync.setAttribute("aria-busy", String(inFlight));
    check.textContent = inFlight && what === "check" ? "Checking parity…" : "Check parity now";
    sync.textContent = inFlight && what === "sync" ? "Syncing parity…" : "Sync parity now";
  }

  /// Re-reads `GET /api/parity` and paints whatever it says.
  ///
  /// @returns {Promise<void>}
  async function refresh() {
    error.textContent = "";
    const envelope = await api.parity();
    const problem = parityEnvelopeProblem(envelope);
    if (problem) {
      error.textContent = problem;
      return;
    }
    if (envelope.status === "never-checked") {
      report.replaceChildren(
        el("h3", { text: "Parity has not been checked on this host yet" }),
        el("p", {
          text:
            "This says nothing about whether parity is set up -- only that nobody has asked. " +
            "Run a check to find out.",
        }),
      );
      return;
    }
    renderParityReport(report, envelope.report);
  }

  /// Streams one dispatched job, then refreshes the report.
  ///
  /// A sync writes no report of its own, so a finished sync chains straight
  /// into a check rather than leaving the screen showing the figures from
  /// before it ran -- which would be the stalest moment to show them.
  ///
  /// @param {string} id - The job uuid.
  /// @param {string} what - "check" or "sync".
  /// @returns {void}
  function attach(id, what) {
    closeStream();
    setBusy(true, what);
    log.hidden = false;
    log.textContent = "";
    pending.textContent =
      what === "sync"
        ? "Syncing parity. A first sync reads every file on every data disk, so this can take hours."
        : "Checking parity. This reads the array index and compares it against the disks.";
    state.stream = api.streamJob(id, {
      onEvent: (e) => {
        log.textContent += `${e.event}: ${e.detail}\n`;
        log.scrollTop = log.scrollHeight;
      },
      onDone: async () => {
        pending.textContent = "";
        try {
          if (what === "sync") {
            const job = await api.startJob("parity_status");
            attach(job.id, "check");
            return;
          }
          await refresh();
          setStatus("Parity check finished.", "ok");
        } catch (err) {
          error.textContent = err.message;
          // The chain-into-a-check failed, so nothing else will clear the
          // latch. Without this a host whose refresh errored keeps controls
          // that never come back -- a worse fault than the one being reported.
          if (what === "sync") setBusy(false, what);
        } finally {
          if (what !== "sync") setBusy(false, what);
        }
      },
      onError: () => {
        // EventSource reconnects by itself, so an error here is not terminal
        // and must not clear the in-flight latch.
      },
    });
  }

  check.addEventListener("click", async () => {
    if (busy) return;
    try {
      const job = await api.startJob("parity_status");
      attach(job.id, "check");
    } catch (err) {
      error.textContent = err.message;
      setBusy(false, "check");
    }
  });

  sync.addEventListener("click", async () => {
    if (busy) return;
    try {
      const job = await api.startJob("parity_sync");
      attach(job.id, "sync");
    } catch (err) {
      error.textContent = err.message;
      setBusy(false, "sync");
    }
  });

  view().replaceChildren(
    el("h2", { text: "Parity" }),
    el("p", {
      class: "hint",
      text:
        "Parity lets ferrum rebuild a data disk that fails. It is not a copy of your library " +
        "kept anywhere else, and it protects nothing against deletion, corruption that was " +
        "synced before anyone noticed, ransomware, fire or theft.",
    }),
    el("div", { class: "row" }, [check, sync]),
    pending,
    error,
    report,
    log,
  );

  // Painted BEFORE the await, so the view is never a blank screen while the
  // first request is in flight.
  report.replaceChildren(
    el("p", {
      class: "hint",
      role: "status",
      "aria-live": "polite",
      text: "Reading the last parity report…",
    }),
  );
  try {
    await refresh();
  } catch (err) {
    report.replaceChildren();
    error.textContent = err.message;
  }
}

// --- routing -------------------------------------------------------------

const routes = {
  "#/apps": appsView,
  "#/apply": applyView,
  "#/secrets": secretsView,
  "#/generations": generationsView,
  "#/updates": updatesView,
  "#/parity": parityView,
};

/// The one parameterised route: `#/apps/<id>`.
///
/// Kept as a pattern rather than an entry per app in `routes` above, because
/// the catalog decides which apps exist and a hand-maintained route table
/// would be the one place in this UI that had to change when an app was
/// added. The character class is the catalog's own app-id shape -- the same
/// one modules/lib/settings-schema.json constrains `apps`' keys to -- so a
/// hash carrying anything else falls through to the apps list rather than
/// being looked up.
const APP_DETAIL_ROUTE = /^#\/apps\/([a-z0-9]([a-z0-9-]*[a-z0-9])?)$/;

async function route() {
  // Before anything is painted, not after: a view that started a ticker must
  // not leave it writing into the nodes the next view is about to replace.
  closeTicker();
  const detail = APP_DETAIL_ROUTE.exec(location.hash);
  const handler = detail ? () => appDetailView(detail[1]) : routes[location.hash] || appsView;
  setStatus("");
  try {
    await handler();
  } catch (err) {
    if (err.status !== 401) setStatus(err.message, "error");
  }
}

/// Gets a ferrumd session without a password, if the edge already knows who we
/// are -- R5.
///
/// Tried once, at boot, and only after /api/session has already said 401. Every
/// failure path here is ordinary and ends the same way: return false, and the
/// caller shows the password form. A host with no single sign-on answers 404; a
/// browser not signed in to Authelia gets 401; an Authelia identity with no
/// ferrum account gets 403; Authelia being down gets 503. None of them is an
/// error worth interrupting the operator with, because the password form is
/// right there and still works.
async function trySingleSignOn() {
  try {
    await api.sso();
    return true;
  } catch {
    return false;
  }
}

async function boot() {
  try {
    let me;
    try {
      // signalExpiry: false -- a 401 here is the expected answer before the
      // SSO attempt below, and dropping to the login view first would paint
      // the password form for a frame on a host that does not need it.
      me = await api.session({ signalExpiry: false });
    } catch (err) {
      if (err.status !== 401) throw err;
      if (!(await trySingleSignOn())) {
        loginView();
        return;
      }
      me = await api.session();
    }
    state.username = me.username;
    [state.catalog, state.settings] = await Promise.all([api.catalog(), api.settings()]);
  } catch (err) {
    if (err.status === 401) return; // the handler already showed the login view
    setStatus(err.message, "error");
    return;
  }

  $("#nav").hidden = false;
  $("#who").textContent = state.username;
  if (!location.hash) location.hash = "#/apps";
  await route();
}

api.setUnauthenticatedHandler(() => {
  closeStream();
  closeTicker();
  $("#nav").hidden = true;
  loginView();
});

window.addEventListener("hashchange", route);
$("#logout").addEventListener("click", async () => {
  await api.logout();
  closeStream();
  closeTicker();
  $("#nav").hidden = true;
  loginView();
});

boot();
