import "./GenerationList.css";

export interface Generation {
  number: number;
  /** ISO timestamp. Rendered in the reader's own timezone. */
  built: string;
  current: boolean;
  /** What changed, when ferrum recorded it. */
  summary?: string;
}

export interface GenerationListProps {
  generations: Generation[];
  onRollback?: (n: number) => void;
}

/**
 * The system's history, and the way back.
 *
 * This is ferrum's actual differentiator: the closure and the application
 * state roll back TOGETHER, atomically. Nothing else in this space does
 * that, and it is invisible until something breaks — so the dashboard's
 * job is to make it obvious that the way back exists BEFORE it is needed,
 * not to bury it behind an advanced menu.
 */
export function GenerationList({ generations, onRollback }: GenerationListProps) {
  return (
    <ol className="fk-gens">
      {generations.map((g) => (
        <li key={g.number} className="fk-gen" data-current={g.current}>
          <div className="fk-gen-main">
            <span className="fk-gen-num">#{g.number}</span>
            {g.current && <span className="fk-gen-now">running now</span>}
            <span className="fk-gen-when">{new Date(g.built).toLocaleString()}</span>
          </div>
          {g.summary && <p className="fk-gen-summary">{g.summary}</p>}
          {!g.current && (
            <button type="button" onClick={() => onRollback?.(g.number)}>
              Roll back to #{g.number}
            </button>
          )}
        </li>
      ))}
    </ol>
  );
}
