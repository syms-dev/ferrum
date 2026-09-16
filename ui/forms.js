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

  // boolean -> checkbox
  if (schema.type === "boolean") {
    const input = el("input", { type: "checkbox", id: nextId() });
    input.checked = value === true;
    return { node: labelled(title, input, description), read: () => input.checked };
  }

  // integer / number -> number input
  if (schema.type === "integer" || schema.type === "number") {
    const input = el("input", { type: "number", id: nextId() });
    if (schema.type === "integer") input.step = "1";
    if (value != null) input.value = value;
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
        if (option === value) o.selected = true;
        select.appendChild(o);
      }
      return { node: labelled(title, select, description), read: () => select.value };
    }
    // plain string -> text
    const input = el("input", { type: "text", id: nextId() });
    if (value != null) input.value = value;
    return { node: labelled(title, input, description), read: () => input.value };
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

    for (const item of Array.isArray(value) ? value : []) addRow(item);
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
    const inner = renderObject(schema, value || {});
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
  const shown = value === undefined ? "" : JSON.stringify(value);
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
        if (v !== undefined) out[k] = v;
      }
      return out;
    },
  };
}

/// Public entry point: render `schema` over `value`.
export function renderForm(schema, value) {
  return renderObject(schema, value ?? {});
}

/// Resolves the sub-schema describing one app's settings, from the document
/// shape the daemon actually serves.
///
/// Returned separately rather than hard-coded into app.js so the path into
/// the schema lives beside the renderer that consumes it.
export function appSchema(fullSchema, appId) {
  const apps = fullSchema?.properties?.apps;
  // A uniform submodule: either every app shares one definition, or each is
  // named. Both shapes are handled; neither is special-cased per app.
  return (
    apps?.properties?.[appId] ??
    apps?.additionalProperties ??
    apps?.patternProperties?.[Object.keys(apps?.patternProperties || {})[0]] ??
    { type: "object", properties: {} }
  );
}

export { UNSUPPORTED };
