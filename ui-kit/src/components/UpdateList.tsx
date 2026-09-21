import "./UpdateList.css";

export interface AvailableUpdate {
  app: string;
  from: string;
  to: string;
  /** What it means for THIS box, not the upstream changelog. */
  consequence: string;
}

export interface UpdateListProps {
  updates: AvailableUpdate[];
  /** The tracked release ref, e.g. "nixos-25.05". */
  channel?: string;
  checkedAgo?: string;
  /** The generation these would be built into. */
  nextGeneration?: number;
  currentGeneration?: number;
  onBuild?: () => void;
}

/**
 * What has an update waiting, and what applying it costs.
 *
 * A version number alone is not a decision. Each row states the
 * consequence for this box — a restart that drops in-flight streams, a
 * database schema the rollback carries back — because that is what the
 * operator is actually weighing, and it is the thing an upstream
 * changelog never tells them.
 *
 * The reassurance at the bottom is load-bearing rather than decorative:
 * updating is only safe to offer this casually BECAUSE the previous
 * generation stays on disk, and saying so is what makes the button
 * clickable without anxiety.
 */
export function UpdateList({
  updates,
  channel,
  checkedAgo,
  nextGeneration,
  currentGeneration,
  onBuild,
}: UpdateListProps) {
  if (updates.length === 0) {
    return (
      <section className="fk-upd" aria-label="Updates">
        <div className="fk-upd-head">
          <h2>Everything is on its latest version</h2>
          {channel && (
            <span className="fk-upd-when">
              channel {channel}
              {checkedAgo && ` · checked ${checkedAgo}`}
            </span>
          )}
        </div>
      </section>
    );
  }

  return (
    <section className="fk-upd" aria-label="Updates">
      <div className="fk-upd-head">
        <h2>
          {updates.length} {updates.length === 1 ? "app has" : "apps have"} an update waiting
        </h2>
        {channel && (
          <span className="fk-upd-when">
            channel {channel}
            {checkedAgo && ` · checked ${checkedAgo}`}
          </span>
        )}
      </div>

      <table className="fk-upd-table">
        <tbody>
          {updates.map((u) => (
            <tr key={u.app}>
              <th scope="row">{u.app}</th>
              <td className="fk-upd-ver">
                {u.from} → {u.to}
              </td>
              <td className="fk-upd-why">{u.consequence}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="fk-upd-foot">
        <button type="button" onClick={onBuild}>
          {nextGeneration ? `Build these into generation ${nextGeneration}` : "Build these"}
        </button>
        {currentGeneration && (
          <span>
            Generation {currentGeneration} stays on disk. If {nextGeneration ?? "the new one"} is
            worse, roll back to it.
          </span>
        )}
      </div>
    </section>
  );
}
