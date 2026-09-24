import { useState } from "react";
import "./Copyable.css";

export interface CopyableProps {
  /** The exact text that lands on the clipboard. */
  value: string;
  /** What to show, when it differs from what gets copied. */
  label?: string;
  /** For screen readers: "Copy the serial", "Copy the log". */
  describe?: string;
  /** `block` fills its line; `inline` sits in a sentence. */
  variant?: "inline" | "block";
}

/**
 * A value with a button that puts it on the clipboard.
 *
 * Everything ferrum shows you that you then have to type somewhere else —
 * a serial, a by-id path, a whole failing log — gets one of these.
 * Retyping a 16-character serial from a screen is a good way to make a
 * typo and blame the software.
 *
 * The clipboard needs a secure context and a user gesture, and it throws
 * rather than failing quietly when it doesn't have one. So the write is
 * guarded and the button reports what actually happened: if the copy
 * failed, saying "Copied" would be a lie the operator only discovers
 * after pasting the wrong thing.
 */
export function Copyable({ value, label, describe, variant = "block" }: CopyableProps) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
    setTimeout(() => setState("idle"), 2000);
  }

  return (
    <span className="fk-copy" data-variant={variant}>
      <code className="fk-copy-value">{label ?? value}</code>
      <button
        type="button"
        className="fk-copy-btn"
        onClick={copy}
        data-state={state}
        aria-label={describe ?? `Copy ${value}`}
      >
        {state === "copied" ? "Copied" : state === "failed" ? "Select it instead" : "Copy"}
      </button>
    </span>
  );
}
