// The ferrum UI: four hash-routed views over the daemon's read-only APIs and
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

// --- routing -------------------------------------------------------------

const routes = {
  "#/apps": appsView,
  "#/apply": applyView,
  "#/secrets": secretsView,
  "#/generations": generationsView,
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
