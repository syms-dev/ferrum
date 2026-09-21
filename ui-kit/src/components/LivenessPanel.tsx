import "./LivenessPanel.css";

export type Liveness = "talking" | "quiet" | "overdue";

export interface LivenessPanelProps {
  state: Liveness;
  /** What the step is doing, e.g. "Building the system closure on the target". */
  title: string;
  /** Seconds since the step last produced output. */
  sinceOutput?: number;
  /** Seconds since an independent probe last confirmed the target is alive. */
  sinceProbe?: number;
  /**
   * Attempts made by a retrying step, and how long it has been retrying.
   *
   * This is the payload that matters when a step is stuck. Elapsed time
   * alone cannot separate "slow" from "looping" — a count can. The real
   * incident was `nixos-anywhere` retrying `ssh-copy-id` every three
   * seconds for three hours while the screen showed one static line.
   */
  attempts?: number;
  /** How long this step usually takes, in human words. */
  plausible?: string;
  /** What is most likely wrong, shown only when overdue. */
  likelyCause?: string;
}

function ago(s?: number): string {
  if (s === undefined) return "";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s ago`;
}

/**
 * Whether the thing you are waiting on is alive, which is a different
 * question from how far along it is.
 *
 * A NixOS closure build on the target is legitimately silent for minutes
 * at a time, so silence cannot mean failure — but an unbounded retry loop
 * is also silent, and that one never ends. Nothing on screen distinguished
 * them, and the cost was three hours, twice in CI and once on real
 * hardware.
 *
 * The `quiet` state STOPS the pulse rather than changing colour. A
 * stopped animation is noticed peripherally in a way a colour shift on a
 * screen nobody is staring at is not, and it maps to the truth: the dot
 * moves when output moves.
 */
export function LivenessPanel({
  state,
  title,
  sinceOutput,
  sinceProbe,
  attempts,
  plausible,
  likelyCause,
}: LivenessPanelProps) {
  return (
    <div className="fk-live" data-state={state} role="status">
      <span className="fk-live-dot" aria-hidden="true" />
      <div className="fk-live-body">
        <b>{title}</b>
        {state === "talking" && (
          <small>
            Output {ago(sinceOutput)}.{plausible ? ` This step normally takes ${plausible}.` : ""}
          </small>
        )}
        {state === "quiet" && (
          <small>
            No output for {ago(sinceOutput).replace(" ago", "")}. Still alive — the target answered
            a probe {ago(sinceProbe)}.{plausible ? ` Long silences are normal here; this step normally takes ${plausible}.` : ""}
          </small>
        )}
        {state === "overdue" && (
          <small>
            {attempts !== undefined && (
              <span className="fk-live-attempts">{attempts} attempts, none succeeded. </span>
            )}
            {plausible ? `This step normally completes in ${plausible}. ` : ""}
            {likelyCause}
          </small>
        )}
      </div>
    </div>
  );
}
