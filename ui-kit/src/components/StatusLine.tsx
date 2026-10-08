import "./StatusLine.css";

export interface StatusLineProps {
  /**
   * `busy` means a job is running on the host — an apply, a rollback, a
   * reconcile. `drifted` is the one worth its own state: the system's
   * actual configuration no longer matches its declared one, which is the
   * failure mode ferrum exists to rule out and must never be reported as
   * merely "ok with a note".
   */
  state: "ok" | "busy" | "drifted" | "failed";
  message: string;
  /** Present while `busy`, 0–1, when the job reports one. */
  progress?: number;
}

/** One line saying what the host is doing, or why it is not fine. */
export function StatusLine({ state, message, progress }: StatusLineProps) {
  return (
    <div className="fk-status" data-state={state} role="status" aria-live="polite">
      <span className="fk-status-dot" aria-hidden="true" />
      <span className="fk-status-msg">{message}</span>
      {state === "busy" && progress !== undefined && (
        <span className="fk-status-bar" aria-hidden="true">
          <span style={{ width: `${Math.round(Math.min(Math.max(progress, 0), 1) * 100)}%` }} />
        </span>
      )}
    </div>
  );
}
