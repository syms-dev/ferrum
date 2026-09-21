import "./SchemaField.css";

/**
 * The JSON-schema subset ferrum's settings can express.
 *
 * Deliberately closed. Every option under `ferrum.*` must stay
 * JSON-expressible — that is what lets the UI render the whole namespace
 * without a per-app screen — and a type outside this list is a schema the
 * UI cannot honestly edit. It says so rather than guessing.
 */
export type SchemaType =
  | "boolean"
  | "integer"
  | "number"
  | "string"
  | "string-enum"
  | "array-of-string"
  | "object";

export interface FieldSchema {
  type: SchemaType;
  title?: string;
  description?: string;
  enum?: string[];
  /**
   * The value this field has when nobody sets it.
   *
   * Shown, never pre-filled. A UI that writes the default into the
   * document freezes today's value forever: the operator's settings.json
   * would pin a number that was only ever meant to track the module's own
   * default, and a later ferrum that improves it would be silently
   * overridden on every host that ever opened this form.
   */
  default?: unknown;
}

export interface SchemaFieldProps {
  name: string;
  schema: FieldSchema;
  value?: unknown;
  onChange?: (value: unknown) => void;
  /** Rendered instead of a control when the type is one ferrum cannot edit. */
  unsupported?: boolean;
}

/**
 * One editable setting, rendered from its schema.
 *
 * This is what makes "adding an app needs no UI change" true: the form is
 * generated from the catalog's own schema, so a new option appears here
 * the moment the module declares it.
 */
export function SchemaField({ name, schema, value, onChange, unsupported }: SchemaFieldProps) {
  const label = schema.title ?? name;
  const id = `fk-field-${name}`;
  const described = schema.description ? `${id}-d` : undefined;

  if (unsupported) {
    return (
      <div className="fk-field" data-unsupported="true">
        <span className="fk-field-label">{label}</span>
        <p className="fk-field-note">
          This ferrum UI does not know how to edit a &quot;{schema.type}&quot; value. Edit it in{" "}
          <code>settings.json</code> on the host, or in <code>custom/</code> if it belongs there.
        </p>
      </div>
    );
  }

  const shown = value === undefined ? "" : String(value);
  const placeholder =
    schema.default !== undefined ? `default: ${String(schema.default)}` : undefined;

  return (
    <div className="fk-field">
      <label className="fk-field-label" htmlFor={id}>
        {label}
      </label>

      {schema.type === "boolean" ? (
        <input
          id={id}
          type="checkbox"
          checked={Boolean(value)}
          aria-describedby={described}
          onChange={(e) => onChange?.(e.target.checked)}
        />
      ) : schema.type === "string-enum" && schema.enum ? (
        <select
          id={id}
          value={shown}
          aria-describedby={described}
          onChange={(e) => onChange?.(e.target.value)}
        >
          {schema.enum.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      ) : (
        <input
          id={id}
          type={schema.type === "integer" || schema.type === "number" ? "number" : "text"}
          step={schema.type === "integer" ? 1 : undefined}
          value={shown}
          placeholder={placeholder}
          aria-describedby={described}
          onChange={(e) =>
            onChange?.(
              schema.type === "integer" || schema.type === "number"
                ? e.target.value === ""
                  ? undefined
                  : Number(e.target.value)
                : e.target.value,
            )
          }
        />
      )}

      {schema.description && (
        <p className="fk-field-note" id={described}>
          {schema.description}
        </p>
      )}
    </div>
  );
}
