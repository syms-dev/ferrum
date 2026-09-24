// Renders a JSON Schema node as form controls, and reads the edited values
// back out as a document.
//
// There is ONE form definition for every app. That is not a shortcut -- the
// app submodule is uniform by design, and hand-writing a second per-app form
// path would quietly abandon the central claim that adding a directory under
// modules/apps/ makes an app appear with zero UI changes. If you find
// yourself special-casing an app id in this file, the design has been lost.

/// The single most important rule in this file.
///
/// A schema type this renderer does not know is shown as a visibly disabled
/// field with an explanation, and its existing value is carried through to
/// the submitted document UNTOUCHED. It is never silently dropped.
///
/// Dropping it would mean an operator opens a form, saves it, and discovers
/// later that an option they never touched has been erased from
/// settings.json -- a data-loss bug caused by the UI being older than the
/// schema it is rendering, which is a normal state on a host that has been
/// updated. Task 8's eval check exists to keep this honest.
const UNSUPPORTED = Symbol("unsupported");

/// The type shapes this renderer has a real control for.
///
/// A SINGLE honest declaration, exported so `checks.ui-renders-every-schema-type`
/// can read it without parsing JavaScript. The check walks the real
/// settings-schema.json, collects every distinct shape it actually contains,
/// and fails the build if one is missing from this list.
///
/// That check is the mechanical guard on "adding an app needs no ui/ change".
/// Without it the claim decays the first time someone adds an option shape the
/// renderer has never seen, and nothing fails until an operator opens a form,
/// saves it, and loses a field. Keep this list honest: adding an entry here
/// without adding the matching branch in `control()` turns the guard into a
/// rubber stamp.
// Kept on ONE line on purpose: checks.nix finds this line and reads the
// quoted names out of it, which is far more robust than teaching Nix's
// regex engine to parse a multi-line JavaScript array.
export const SUPPORTED_TYPES = ["boolean", "integer", "number", "string", "string-enum", "array-of-string", "object"];

let uid = 0;
const nextId = () => `f${++uid}`;

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (v === true) node.setAttribute(k, "");
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function labelled(labelText, control, description) {
  const id = control.id || (control.id = nextId());
  return el("div", { class: "field" }, [
    el("label", { for: id, text: labelText }),
    control,
    description ? el("p", { class: "hint", text: description }) : null,
  ]);
}

/// Builds a control for one schema node.
///
/// Returns `{ node, read }` where `read()` yields this node's current value.
/// Every branch returns a `read`, including the unsupported one -- that is
/// what makes "preserved untouched" true rather than aspirational.
function control(schema, value, key) {
  const description = schema.description;
  const title = schema.title || key;

  // Show the EFFECTIVE value: what the document says, or -- when it says
  // nothing -- the default the host is actually running with.
  //
  // Populating only from the document was a lie with teeth. Plex's real
  // mediaAccess default is "read", but with no document value the select fell
  // to its first option and displayed "none" while the running host had
  // "read". The number inputs rendered blank rather than 32400. An operator
  // reading the form saw values the machine was not using -- and worse, the
  // default-omission logic in renderObject would then compare the displayed
  // "none" against the default "read", conclude the operator had changed it,
  // and write mediaAccess:"none" into settings.json, breaking Plex's access
  // to the library on save. Showing the truth is what makes that logic safe.
  const effective = value !== undefined ? value : schema.default;

  // A readOnly property is rendered disabled and its value passed straight
  // through on read, exactly like an unsupported type -- so it displays the
  // truth without inviting an edit that would break something.
  if (schema.readOnly) {
    const shown = effective === undefined ? "" :
      (typeof effective === "object" ? JSON.stringify(effective) : String(effective));
    const input = el("input", { type: "text", id: nextId(), value: shown, disabled: true });
    return {
      node: el("div", { class: "field" }, [
        el("label", { for: input.id, text: title }),
        input,
        description ? el("p", { class: "hint", text: description }) : null,
      ]),
      read: () => value,
    };
  }

  // boolean -> checkbox
  if (schema.type === "boolean") {
    const input = el("input", { type: "checkbox", id: nextId() });
    input.checked = effective === true;
    return { node: labelled(title, input, description), read: () => input.checked };
  }

  // integer / number -> number input
  if (schema.type === "integer" || schema.type === "number") {
    const input = el("input", { type: "number", id: nextId() });
    if (schema.type === "integer") input.step = "1";
    if (effective != null) input.value = effective;
    return {
      node: labelled(title, input, description),
      read: () => (input.value === "" ? undefined : Number(input.value)),
    };
  }

  if (schema.type === "string") {
    // string with enum -> select
    if (Array.isArray(schema.enum)) {
      const select = el("select", { id: nextId() });
      for (const option of schema.enum) {
        const o = el("option", { value: option, text: option });
        if (option === effective) o.selected = true;
        select.appendChild(o);
      }
      return { node: labelled(title, select, description), read: () => select.value };
    }
    // plain string -> text
    //
    // An EMPTY box reads as `undefined`, not "". Several of these options are
    // `nullOr str` in app-submodule.nix (resources.memoryMax, resources.cpuQuota),
    // and writing "" put `MemoryMax=` into a real systemd unit on a real host
    // instead of leaving the limit unset -- `serviceConfig`'s own
    // `filterAttrs (_: v: v != null)` drops null but happily passes through an
    // empty string. Omitting it is also what keeps the document minimal.
    const input = el("input", { type: "text", id: nextId() });
    if (effective != null) input.value = effective;
    return {
      node: labelled(title, input, description),
      read: () => (input.value === "" ? undefined : input.value),
    };
  }

  // array of string -> repeated rows with add/remove
  if (schema.type === "array" && schema.items && schema.items.type === "string") {
    const rows = el("div", { class: "rows" });
    const inputs = [];

    const addRow = (initial = "") => {
      const input = el("input", { type: "text", value: initial });
      const remove = el("button", { type: "button", class: "ghost", text: "Remove" });
      const row = el("div", { class: "row" }, [input, remove]);
      remove.addEventListener("click", () => {
        row.remove();
        inputs.splice(inputs.indexOf(input), 1);
      });
      inputs.push(input);
      rows.appendChild(row);
    };

    for (const item of Array.isArray(effective) ? effective : []) addRow(item);
    const add = el("button", { type: "button", class: "ghost", text: "Add" });
    add.addEventListener("click", () => addRow());

    return {
      node: el("fieldset", {}, [
        el("legend", { text: title }),
        description ? el("p", { class: "hint", text: description }) : null,
        rows,
        add,
      ]),
      read: () => inputs.map((i) => i.value).filter((v) => v !== ""),
    };
  }

  // object -> nested fieldset, recursing
  if (schema.type === "object" && schema.properties) {
    const inner = renderObject(schema, effective || {});
    return {
      node: el("fieldset", {}, [
        el("legend", { text: title }),
        description ? el("p", { class: "hint", text: description }) : null,
        inner.node,
      ]),
      read: inner.read,
    };
  }

  // Anything else. Disabled, visibly explained, and its value passed straight
  // through by `read` -- see UNSUPPORTED above for why this matters more than
  // any other branch in this file.
  const shown = effective === undefined ? "" : JSON.stringify(effective);
  const input = el("input", { type: "text", id: nextId(), value: shown, disabled: true });
  const note = el("p", {
    class: "hint unsupported",
    text:
      `This ferrum UI does not know how to edit a "${schema.type ?? "untyped"}" ` +
      `option, so it is shown read-only. Its current value is kept exactly as ` +
      `it is when you save; nothing here is erased. Edit it in settings.json, ` +
      `or update ferrum.`,
  });
  return {
    node: el("div", { class: "field" }, [el("label", { for: input.id, text: title }), input, note]),
    read: () => value,
    kind: UNSUPPORTED,
  };
}

/// Renders every property of an object schema.
function renderObject(schema, value) {
  const container = el("div", { class: "group" });
  const readers = {};

  for (const [key, propSchema] of Object.entries(schema.properties || {})) {
    const built = control(propSchema, value?.[key], key);
    container.appendChild(built.node);
    readers[key] = built.read;
  }

  // Keys present in the document but absent from the schema are ALSO carried
  // through untouched, for the same reason an unsupported type is: a UI older
  // than the document it is editing must not delete what it does not
  // recognise.
  const unknownKeys = Object.keys(value || {}).filter((k) => !(k in (schema.properties || {})));

  return {
    node: container,
    read: () => {
      const out = {};
      for (const k of unknownKeys) out[k] = value[k];
      for (const [k, read] of Object.entries(readers)) {
        const v = read();
        if (v === undefined) continue;

        // Write a value ONLY when it differs from the default, so the saved
        // document stays as small as the operator's actual intent.
        //
        // This is not tidiness, it is correctness. settings.json on a real
        // host reads {"apps":{"plex":{"enable":true}}} -- one field, with
        // everything else coming from app-submodule.nix and each app's meta.
        // An earlier version of this function wrote back every control it
        // rendered, which silently froze today's defaults into the document:
        // if ferrum later changed a default port, or added a path to an app's
        // authBypassPaths, this host would never receive it, because the UI
        // had pinned the old value. Nobody would connect the two.
        //
        // An explicit value the operator DID set is still written, even when
        // it happens to equal the default, if it was already in the document
        // -- removing it would be editing their file behind their back.
        const def = schema.properties[k]?.default;
        const wasExplicit = value && Object.prototype.hasOwnProperty.call(value, k);
        const isDefault = def !== undefined && JSON.stringify(v) === JSON.stringify(def);
        const isEmptyObject = v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0;

        if (!wasExplicit && (isDefault || isEmptyObject)) continue;
        out[k] = v;
      }
      return out;
    },
  };
}

/// Public entry point: render `schema` over `value`.
export function renderForm(schema, value) {
  return renderObject(schema, value ?? {});
}

/// The schema for ONE app's settings.
///
/// WHY THIS IS HAND-WRITTEN, and what would replace it.
///
/// `GET /api/catalog`'s `schema` does not describe app options at all. Its
/// own text says so: `apps` is `{"type":"object"}` with the description
/// "Deep per-app validation is deferred -- a future task tightens this
/// against the real catalog-driven submodule shape." Task 7 assumed that
/// schema would drive this form; it cannot, because there is nothing in it
/// to drive from. Discovered by opening the UI in a browser and finding an
/// empty form.
///
/// So the UNIFORM half below mirrors modules/lib/app-submodule.nix by hand,
/// and the app-SPECIFIC half comes from that app's own `meta.settingsSchema`,
/// which the catalog really does publish.
///
/// This does NOT abandon the design's central claim. Adding a directory under
/// modules/apps/ still makes an app appear with zero changes here: every app
/// shares the uniform half, and its own knobs arrive dynamically. What it
/// does cost is that adding a new OPTION to app-submodule.nix needs a
/// matching edit in this function -- which is why the real fix is to generate
/// the `apps` sub-schema in Nix from the submodule and serve it, at which
/// point this whole function collapses back to reading `schema`.
/// Tracked as Task 7.5; do not let this shape quietly become permanent.
///
/// Nothing here matches on an app id, and nothing may: that is the line
/// between "mirrors the uniform submodule" and "hand-written per-app form".
export function appSchema(fullSchema, appId, meta = {}) {
  const published = fullSchema?.properties?.apps?.properties?.[appId];
  if (published?.properties) return published; // the generated schema landed

  // `default` on every property is load-bearing, not documentation: renderObject
  // omits a value that still equals its default, which is what keeps
  // settings.json down to the operator's actual intent instead of eleven
  // frozen fields per app. Defaults come from the catalog where the catalog
  // publishes them, so they track the app rather than being restated here.
  return {
    type: "object",
    // Two things an operator actually decides, plus the app's own knobs.
    //
    // `exposure` is deliberately NOT here. Every app is published on the
    // operator's domain -- that is what this product is, the same shape as
    // Saltbox, and "reachable only from the machine itself" is not a target
    // state anyone wants. The module default is now "public" whenever a proxy
    // exists (modules/lib/app-submodule.nix), so there is nothing to choose.
    // Removing the option from the module tree entirely is the honest finish
    // and needs a settings-schema migration; until then an existing explicit
    // `exposure` in a document is preserved untouched by renderObject's
    // unknown-key handling rather than being silently rewritten.
    properties: {
      enable: {
        type: "boolean",
        default: false,
        title: "Enabled",
        description: "Run this app on this host.",
      },
      subdomain: {
        type: "string",
        default: meta.defaultSubdomain,
        title: "Subdomain",
        description:
          "Reached at this label under your base domain. The one knob here people " +
          "genuinely want to change.",
      },
      settings: {
        ...(meta.settingsSchema ?? { type: "object", properties: {} }),
        title: `${meta.displayName || appId} options`,
      },
    },
  };
}

/// The knobs that already have a correct answer.
///
/// Separated so the form can collapse them. Every one of these is either
/// derived from the catalog (port, subdomain, auth policy, media access,
/// bypass paths), derived from the storage layout (stateDir), or off by
/// default (resource limits). An operator should be able to enable an app
/// without reading any of it -- which is the comparison being made against
/// Saltbox, where you enable a role and it works.
export function advancedSchema(meta = {}, stateRoot = "/var/lib/ferrum/state", appId = "") {
  return {
    type: "object",
    properties: {
      // readOnly: shown so an operator can SEE what the host is using, but
      // not editable. These are answers the catalog already gave correctly,
      // and changing them is a foot-gun rather than a feature: a port only
      // matters behind the proxy, and stateDir moved outside the ferrum state
      // root silently removes the app from snapshot and rollback -- the one
      // guarantee this whole project exists to provide.
      port: {
        type: "integer",
        default: meta.defaultPort,
        readOnly: true,
        title: "Port",
        description: "Loopback port behind the proxy. Set by the catalog.",
      },
      mediaAccess: {
        type: "string",
        enum: ["none", "read", "readwrite"],
        default: meta.defaultMediaAccess ?? "none",
        title: "Media access",
      },
      stateDir: {
        type: "string",
        default: `${stateRoot}/${appId}`,
        readOnly: true,
        title: "State directory",
        description:
          "Derived from your storage layout. Moving it outside the ferrum state root " +
          "would drop this app out of snapshot and rollback.",
      },
      auth: {
        type: "object",
        title: "Single sign-on",
        properties: {
          policy: {
            type: "string",
            enum: ["bypass", "one_factor", "two_factor"],
            default: meta.defaultAuthPolicy ?? "two_factor",
            title: "Policy",
          },
          bypassPaths: {
            type: "array",
            items: { type: "string" },
            default: meta.authBypassPaths ?? [],
            readOnly: true,
            title: "Bypass paths",
            description:
              "Paths that skip sign-on, for native clients that cannot follow a login " +
              "redirect. The catalog already sets the ones each app needs.",
          },
        },
      },
      resources: {
        type: "object",
        title: "Resource limits",
        properties: {
          memoryMax: { type: "string", title: "Memory limit", description: "e.g. 2G. Empty means no limit." },
          cpuQuota: { type: "string", title: "CPU quota", description: "e.g. 150%. Empty means no limit." },
        },
      },
      backup: {
        type: "object",
        title: "Backup",
        properties: { enable: { type: "boolean", default: true, title: "Include in backups" } },
      },
    },
  };
}

export { UNSUPPORTED };
