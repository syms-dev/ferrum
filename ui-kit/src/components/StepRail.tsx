import "./StepRail.css";

export interface Step {
  /** Short, in the operator's terms: "Pick a disk", not "diskSelected". */
  label: string;
  /** One line on what this step is for, shown only for the current step. */
  detail?: string;
}

export interface StepRailProps {
  steps: Step[];
  /** Zero-based. */
  current: number;
  /** Steps before this one can be returned to; after the erase, none can. */
  canGoBack?: boolean;
  onBack?: (index: number) => void;
}

/**
 * Numbered steps, for the half of the installer that is a wizard.
 *
 * The installer is two different things and they need different
 * furniture. Before the disk is erased it is a sequence of questions the
 * operator can back out of, and that half wants "Step 2 of 5" and room
 * to breathe. After the disk is erased it is an irreversible process
 * where the only question is whether it is still alive — that half is
 * `PhaseRail` and `LivenessPanel`, which show ferrum's real phase
 * machine because a resume resumes to it.
 *
 * Showing the phase machine during the questions is what makes an
 * installer feel complicated: `hardwareConfigured` is true and useful and
 * means nothing to somebody deciding which disk to wipe.
 *
 * `canGoBack` goes false the moment the erase is confirmed, and the rail
 * stops offering a way back rather than offering one that fails.
 */
export function StepRail({ steps, current, canGoBack = true, onBack }: StepRailProps) {
  return (
    <nav className="fk-steps" aria-label={`Step ${current + 1} of ${steps.length}`}>
      <p className="fk-steps-count">
        Step {current + 1} of {steps.length}
      </p>
      <ol>
        {steps.map((s, i) => {
          const state = i < current ? "done" : i === current ? "now" : "todo";
          const returnable = state === "done" && canGoBack;
          return (
            <li key={s.label} data-state={state}>
              <span className="fk-steps-num" aria-hidden="true">
                {state === "done" ? "✓" : i + 1}
              </span>
              <span className="fk-steps-body">
                {returnable ? (
                  <button type="button" onClick={() => onBack?.(i)}>
                    {s.label}
                  </button>
                ) : (
                  <span className="fk-steps-label">{s.label}</span>
                )}
                {state === "now" && s.detail && (
                  <span className="fk-steps-detail">{s.detail}</span>
                )}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
