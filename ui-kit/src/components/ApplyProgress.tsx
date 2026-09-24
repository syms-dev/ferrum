import { LogStream } from "./LogStream";
import "./ApplyProgress.css";

export interface ApplyStep {
  id: string;
  label: string;
  state: "pending" | "running" | "done" | "failed";
  /** Why it failed, in the operator's terms. */
  detail?: string;
}

export interface ApplyProgressProps {
  steps: ApplyStep[];
  lines: string[];
  follow?: boolean;
  onFollowChange?: (follow: boolean) => void;
}

/**
 * A running apply: the steps, and the output underneath them.
 *
 * Both halves are shown at once rather than the log being hidden behind a
 * disclosure. The steps answer "how far along is it"; only the log
 * answers "why did it stop", and an apply that fails is exactly when the
 * operator needs the second answer without hunting for it.
 */
export function ApplyProgress({ steps, lines, follow, onFollowChange }: ApplyProgressProps) {
  return (
    <div className="fk-apply">
      <ol className="fk-apply-steps">
        {steps.map((s) => (
          <li key={s.id} data-state={s.state}>
            <span className="fk-apply-mark" aria-hidden="true" />
            <span className="fk-apply-label">{s.label}</span>
            {s.detail && <span className="fk-apply-detail">{s.detail}</span>}
          </li>
        ))}
      </ol>
      <LogStream lines={lines} follow={follow} onFollowChange={onFollowChange} label="Apply output" />
    </div>
  );
}
