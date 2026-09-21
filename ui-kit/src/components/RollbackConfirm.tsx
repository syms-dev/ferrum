import "./RollbackConfirm.css";

export interface RollbackConfirmProps {
  /** The generation being rolled back to. */
  target: number;
  current: number;
  /** What comes back with it, in the operator's terms. */
  effects?: string[];
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * The confirmation before a rollback.
 *
 * It is deliberately NOT an erase-style gate. Rolling back is the safe
 * direction — the whole point of ferrum's atomic generations — and making
 * it feel as dangerous as wiping a disk would teach operators to avoid
 * the one recovery mechanism the product is built around. It confirms,
 * states what changes, and gets out of the way.
 */
export function RollbackConfirm({
  target,
  current,
  effects = [],
  busy = false,
  onConfirm,
  onCancel,
}: RollbackConfirmProps) {
  return (
    <div className="fk-rollback" role="dialog" aria-modal="true" aria-label={`Roll back to generation ${target}`}>
      <h3>Roll back to generation #{target}?</h3>
      <p>
        The system is on #{current}. Rolling back switches the whole configuration and the
        application state it was captured with, together. #{current} is not deleted — you can move
        forward again afterwards.
      </p>
      {effects.length > 0 && (
        <ul className="fk-rollback-effects">
          {effects.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      )}
      <div className="fk-rollback-actions">
        <button type="button" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button type="button" className="fk-rollback-go" onClick={onConfirm} disabled={busy}>
          {busy ? "Rolling back…" : `Roll back to #${target}`}
        </button>
      </div>
    </div>
  );
}
