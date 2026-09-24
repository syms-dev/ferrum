import { useState } from "react";
import "./SecretField.css";

export interface SecretFieldProps {
  name: string;
  description?: string;
  /** Whether a value already exists on the host. Its CONTENT is never read back. */
  present: boolean;
  onSubmit?: (value: string) => void;
}

/**
 * A secret, which is write-only by construction.
 *
 * The existing value is never fetched, never rendered, and never masked —
 * masking implies the UI has it. ferrum stores secrets encrypted to the
 * host's own key and the daemon cannot decrypt them either, so "set" and
 * "not set" is genuinely all there is to show.
 *
 * Replacing is explicit rather than implied by typing: a form that
 * silently overwrites on save makes an accidental keystroke into a
 * rotated credential, and the two failures are not symmetric — a secret
 * you meant to change and did not is noticed, one you changed by accident
 * is noticed much later.
 */
export function SecretField({ name, description, present, onSubmit }: SecretFieldProps) {
  const [value, setValue] = useState("");
  const [replacing, setReplacing] = useState(!present);
  const id = `fk-secret-${name}`;

  return (
    <div className="fk-secret">
      <div className="fk-secret-head">
        <label className="fk-secret-name" htmlFor={id}>
          {name}
        </label>
        <span className="fk-secret-state" data-present={present}>
          {present ? "set" : "not set"}
        </span>
      </div>
      {description && <p className="fk-secret-note">{description}</p>}

      {replacing ? (
        <>
          <input
            id={id}
            type="password"
            value={value}
            autoComplete="off"
            placeholder="paste the value"
            onChange={(e) => setValue(e.target.value)}
          />
          <button
            type="button"
            className="fk-secret-save"
            disabled={value.length === 0}
            onClick={() => {
              onSubmit?.(value);
              setValue("");
              if (present) setReplacing(false);
            }}
          >
            {present ? "Replace" : "Save"} {name}
          </button>
        </>
      ) : (
        <button type="button" className="fk-secret-replace" onClick={() => setReplacing(true)}>
          Replace it
        </button>
      )}
    </div>
  );
}
