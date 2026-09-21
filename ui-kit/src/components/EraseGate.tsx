import { useId, useState } from "react";
import "./EraseGate.css";

export interface EraseGateProps {
  /** Kernel name of the disk about to be erased. */
  diskName: string;
  /** Its serial — what must be typed, byte for byte. */
  serial: string;
  /**
   * Every other disk's serial, mapped to its name. Used for the one live
   * check this gate performs.
   */
  otherSerials?: Record<string, string>;
  onConfirm?: () => void;
}

/**
 * The confirmation that stands between a typo and an erased disk.
 *
 * Typing the serial, not a checkbox: the serial is the one thing that
 * cannot be got right by reflex, and the terminal version of this gate is
 * what caught a wrong-disk selection during testing.
 *
 * Three deliberate choices, each of which is a refusal to do the obvious
 * thing:
 *
 *  - **Paste is allowed.** Blocking it is unenforceable and only pushes
 *    people to transcribe from a screenshot, which is worse.
 *  - **There is no "matches ✓" tick.** A live success indicator rewards
 *    fiddling until it turns green, which is the opposite of the care
 *    this gate exists to demand.
 *  - **There IS one live check:** a serial belonging to a *different*
 *    disk warns immediately and names that disk. That is the only failure
 *    this gate exists to catch, so it is the only thing worth interrupting
 *    for.
 *
 * Enter moves focus to the button rather than submitting. It is the one
 * deliberate break with browser convention here, because Enter-after-
 * typing is precisely the reflex being defeated.
 */
export function EraseGate({ diskName, serial, otherSerials = {}, onConfirm }: EraseGateProps) {
  const [typed, setTyped] = useState("");
  const inputId = useId();
  const warnId = useId();

  const wrongDisk = otherSerials[typed.trim()];
  const matches = typed === serial;

  return (
    <section className="fk-gate" aria-labelledby={`${inputId}-h`}>
      <h3 id={`${inputId}-h`}>Type the serial of the disk to erase</h3>
      <p>Not a checkbox. The serial is the one thing that cannot be got right by reflex.</p>

      <label className="fk-gate-label" htmlFor={inputId}>
        Serial of <span className="fk-gate-mono">{diskName}</span> —{" "}
        <span className="fk-gate-mono">{serial}</span>
      </label>
      <input
        id={inputId}
        className="fk-gate-input"
        value={typed}
        autoComplete="off"
        spellCheck={false}
        placeholder="type it exactly"
        aria-describedby={wrongDisk ? warnId : undefined}
        aria-invalid={wrongDisk ? true : undefined}
        onChange={(e) => setTyped(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            (e.currentTarget.form ?? e.currentTarget.closest(".fk-gate"))
              ?.querySelector<HTMLButtonElement>(".fk-gate-go")
              ?.focus();
          }
        }}
      />

      {wrongDisk && wrongDisk !== diskName && (
        <p className="fk-gate-warn" id={warnId} role="alert">
          That is the serial of {wrongDisk}, not {diskName}. {wrongDisk} is not the disk you
          selected.
        </p>
      )}

      <button type="button" className="fk-gate-go" disabled={!matches} onClick={onConfirm}>
        Erase {diskName} and install
      </button>
      <p className="fk-gate-hint">
        Pressing Enter moves focus to the button — it does not submit.
      </p>
    </section>
  );
}
