import { Badge } from "./Badge";
import { Copyable } from "./Copyable";
import "./DriftPanel.css";

export interface DriftItem {
  /** The file, unit or path that no longer matches. */
  subject: string;
  /** How it diverged, in two or three words: "Edited by hand", "Stopped by hand". */
  kind: string;
  /** What changed and what re-applying will do about it. */
  detail: string;
}

export interface DriftPanelProps {
  generation: number;
  items: DriftItem[];
  firstSeen?: string;
  onReapply?: () => void;
  onRollback?: () => void;
}

/**
 * The most important thing the dashboard ever says.
 *
 * Configuration drift is the failure ferrum exists to rule out, and it is
 * invisible by nature: the box is up, the services are running, and the
 * configuration it is running is not the one you declared. So this is not
 * a warning banner with a count — it names each thing, says what changed,
 * and says what re-applying will do to it.
 *
 * It offers rollback beside re-apply because those are genuinely different
 * intentions. Re-apply asserts the declared configuration; rollback says
 * the declared configuration is itself the problem.
 */
export function DriftPanel({
  generation,
  items,
  firstSeen,
  onReapply,
  onRollback,
}: DriftPanelProps) {
  return (
    <section className="fk-drift" aria-label="Configuration drift">
      <div className="fk-drift-head">
        <h2>Something changed this box outside of ferrum</h2>
        {firstSeen && <span className="fk-drift-when">first seen {firstSeen}</span>}
      </div>

      <p className="fk-drift-lede">
        {items.length === 1 ? "One thing" : `${items.length} things`} on disk no longer
        {items.length === 1 ? " matches" : " match"} generation {generation}. ferrum did not make
        {items.length === 1 ? " this change" : " these changes"} and will not keep
        {items.length === 1 ? " it" : " them"}. Re-applying puts the box back to the
        configuration it is supposed to be running; nothing below is repaired until you do.
      </p>

      <ol className="fk-drift-items">
        {items.map((it) => (
          <li key={it.subject}>
            <div className="fk-drift-subject">
              <Copyable value={it.subject} variant="inline" describe={`Copy ${it.subject}`} />
              <Badge tone="danger">{it.kind}</Badge>
            </div>
            <span className="fk-drift-detail">{it.detail}</span>
          </li>
        ))}
      </ol>

      <div className="fk-drift-actions">
        <button type="button" className="fk-drift-go" onClick={onReapply}>
          Re-apply generation {generation}
        </button>
        <button type="button" onClick={onRollback}>
          Roll back instead
        </button>
      </div>
    </section>
  );
}
