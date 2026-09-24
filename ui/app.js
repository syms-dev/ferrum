// The ferrum UI: five hash-routed views over the daemon's read-only APIs and
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
  for (const id of ids) {
    const meta = apps[id];
    const enabled = state.settings?.apps?.[id]?.enable === true;
    list.appendChild(
      el("article", { class: "card" }, [
        el("h3", { text: meta.displayName || id }),
        el("p", { class: "hint", text: meta.summary || "" }),
        el("p", { class: enabled ? "pill on" : "pill", text: enabled ? "Enabled" : "Disabled" }),
        el("button", {
          type: "button",
          text: "Configure",
          onclick: () => appForm(id),
        }),
      ]),
    );
  }

  view().replaceChildren(
    el("section", {}, [
      el("h2", { text: "Apps" }),
      el("p", { class: "hint", text: "Every app is rendered from the same schema. Adding one to the catalog needs no UI change." }),
      list,
    ]),
  );
}

function appForm(id) {
  const meta = state.catalog.apps[id];
  const current = state.settings?.apps?.[id] ?? {};
  const stateRoot = state.settings?.storage?.stateDir ?? "/var/lib/ferrum/state";

  // Two groups, deliberately. The first is what an operator decides; the
  // second is everything the catalog already answered correctly. Enabling an
  // app should not be a configuration exercise -- that is the whole point of
  // having a catalog, and the comparison being made against Saltbox.
  const primary = renderForm(appSchema(state.catalog.schema, id, meta), current);
  const advanced = renderForm(advancedSchema(meta, stateRoot, id), current);

  const details = el("details", { class: "advanced" }, [
    el("summary", { text: "Advanced \u2014 the catalog already set these" }),
    el("p", {
      class: "hint",
      text:
        "Nothing here needs changing to run the app. A value you leave alone is not " +
        "written to settings.json at all, so it keeps tracking ferrum's own default " +
        "instead of being frozen at today's value.",
    }),
    advanced.node,
  ]);

  view().replaceChildren(
    el("section", {}, [
      el("button", { type: "button", class: "ghost", text: "\u2190 All apps", onclick: appsView }),
      el("h2", { text: meta.displayName || id }),
      el("p", { class: "hint", text: meta.summary || "" }),
      primary.node,
      details,
      el("button", {
        type: "button",
        text: "Stage changes",
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
  );
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

  function attach(id) {
    log.textContent = "";
    state.stream = api.streamJob(id, {
      onEvent: (e) => {
        log.textContent += `${e.event}: ${e.detail}\n`;
        log.scrollTop = log.scrollHeight;
      },
      onDone: () => setStatus("Job finished.", "ok"),
    });
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
    onclick: async () => {
      error.textContent = "";
      try {
        const { id } = await api.startJob("apply");
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
    },
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
      el("h4", { text: "What does NOT come back" }),
      el("p", {
        text:
          "Your media files are untouched — they live outside the snapshot. So are " +
          "downloads in flight or queued, which keep running against a library index " +
          "that no longer knows about them. TLS certificates stay as they are. So do " +
          "Authelia users, including any password changed since — that new password " +
          "still works after the rollback.",
      }),
      el("p", {
        class: "hint",
        text:
          "In short: the system and its databases go back in time; your files and " +
          "logins do not. Where those two disagree, an app may need to rescan.",
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
        el("td", { text: gen.current ? "running now" : "" }),
        el("td", {}, [action]),
      ]),
    );
  }

  view().replaceChildren(
    el("section", {}, [
      el("h2", { text: "Generations" }),
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
/// that produces a candidate report has already resolved one of these four;
/// "this host has never checked at all" is not a candidate state, it is the
/// endpoint's own `never-checked` envelope status, rendered separately.
const CANDIDATE_STATES = ["up-to-date", "not-newer", "update-available", "check-failed"];

/// The five values an entry in `apps[]`'s `state` can carry. Same file, same
/// flake check, same cross-check against `AppState`.
///
/// `not-checked` DOES exist on this side and is reachable: an enabled app
/// whose current version is known while the candidate side never resolved.
/// It is explicitly not a claim that the app is up to date.
const APP_STATES = ["not-checked", "up-to-date", "update-available", "excluded", "evaluation-failed"];

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
  "up-to-date": stateText("Up to date", "The tracked reference resolves to the revision this host is already running. There is nothing to apply."),
  "not-newer": stateText("Candidate is not newer — not an update", "The tracked reference resolves to a revision that is not newer than the one this host runs. ferrum will not offer it, the same way preview-migration refuses to call a lower schema version a migration."),
  "update-available": stateText("Update available", "A newer revision exists. Nothing has been fetched, built, or applied — a check only reads."),
  "check-failed": stateText("Could not check for updates", "The check did not complete, so this host's update state is unknown. That is not the same as being up to date."),
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
  const apps = Array.isArray(report.apps) ? report.apps : [];
  const warnings = Array.isArray(report.warnings) ? report.warnings : [];

  const rows = el("tbody");
  for (const app of apps) rows.appendChild(appRow(app, catalogApps));

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

    el("h3", { text: "The candidate" }),
    stateCell(CANDIDATE_STATE_TEXT[candidate.state], candidate.state, candidate.error || null, CANDIDATE_STATES),

    el("dl", { class: "facts" }, [
      el("dt", { text: "Tracked input" }),
      el("dd", { text: `${orUnknown(candidate.inputName)} — ${orUnknown(candidate.inputUrl)}` }),
      el("dt", { text: "Tracked reference" }),
      el("dd", { text: orUnknown(candidate.reference) }),
      // Named as the pin, not as the running revision. This value is read
      // out of /etc/ferrum/flake.lock, which is the pin the NEXT build would
      // start from; the pin the running generation was actually built from is
      // recorded nowhere -- not in the journal, not anywhere else -- so the
      // two can differ and ferrum has no way to tell. Declining to report the
      // difference is honest; asserting the equality in a label was not, and
      // it landed on the one field the operator is asked to read and refuse
      // in place of a signature check.
      el("dt", { text: "Revision pinned in /etc/ferrum/flake.lock" }),
      el("dd", {}, [el("code", { class: "rev", text: orUnknown(candidate.currentRev) })]),
      el("dt", { text: "Candidate revision" }),
      el("dd", {}, [el("code", { class: "rev", text: orUnknown(candidate.rev || ferrum.candidateRev) })]),
    ]),
    el("p", {
      class: "hint",
      text: "That is the pin on disk. ferrum cannot confirm the generation now running was built from it — nothing records the pin a generation was built with.",
    }),

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

    warnings.length
      ? el("section", {}, [
          el("h3", { text: "Warnings" }),
          el("ul", {}, warnings.map((w) => el("li", { text: String(w) }))),
        ])
      : null,
  );
}

/// The Updates view: what a read-only check found, and nothing that acts on it.
///
/// @returns {Promise<void>} Resolves once the shell is painted and either a
///   stored report has been rendered or an in-flight check reattached to.
async function updatesView() {
  closeStream();

  const error = el("p", { class: "error" });
  const pending = el("p", { class: "hint", role: "status", "aria-live": "polite" });
  const report = el("div", {});
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
          "Checking reads only. It resolves what the tracked reference points at and works out what your configuration would become — it writes nothing, builds nothing and switches nothing. Nothing on this screen applies an update.",
      }),
      el("p", {
        class: "hint",
        text:
          "ferrum cannot update one app without the others. A single nixpkgs pin supplies every app's package, so every version below moves together or not at all. There is no per-app update control here because there is no per-app update to offer.",
      }),
      el("div", { class: "row" }, [check]),
      pending,
      error,
      log,
      report,
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
    } else {
      renderUpdateReport(report, envelope.report, state.catalog?.apps || {}, envelope.jobId);
    }
  } catch (err) {
    error.textContent = err.message;
  }
  pending.textContent = "";

  // Nothing to reattach to when this view is already following a check: a
  // click that landed while the two awaits above were outstanding has already
  // attached to the very job this finder would go looking for.
  if (checking) return;

  // Reattach to a check still running from a previous page load. Filtered on
  // kind as well as status, unlike the Apply view's finder above: an
  // unfiltered one here would tail a rollback or a gc job into this screen's
  // log and then ask /api/updates for a report that job never produced.
  try {
    const recent = await api.jobs(10);
    const running = recent.jobs.find((j) => j.status === "running" && j.kind === "check_update");
    if (running) {
      setStatus("Reattached to an update check already running.");
      attach(running.id);
    }
  } catch (err) {
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
};

async function route() {
  const handler = routes[location.hash] || appsView;
  setStatus("");
  try {
    await handler();
  } catch (err) {
    if (err.status !== 401) setStatus(err.message, "error");
  }
}

async function boot() {
  try {
    const me = await api.session();
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
  $("#nav").hidden = true;
  loginView();
});

window.addEventListener("hashchange", route);
$("#logout").addEventListener("click", async () => {
  await api.logout();
  closeStream();
  $("#nav").hidden = true;
  loginView();
});

boot();
