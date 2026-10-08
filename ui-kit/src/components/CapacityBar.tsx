import "./CapacityBar.css";

export interface CapacityBarProps {
  /** Bytes used. */
  used: number;
  /** Total capacity in bytes. */
  total: number;
  /**
   * Severity of the bar itself. `danger` is for a disk about to be
   * erased, not for a full one — fullness is a fact, erasure is a
   * decision, and colouring them the same conflates the two.
   */
  tone?: "neutral" | "danger";
  /** Hides the "x used · y free · n% full" line, for dense contexts. */
  hideLabel?: boolean;
}

function human(bytes: number): string {
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let n = bytes;
  while (n >= 1000 && i < u.length - 1) {
    n /= 1000;
    i += 1;
  }
  // Decimal units, not binary: this sits beside `lsblk` output and a
  // vendor's label, both of which are decimal. Showing 7.3 TB where the
  // box says 8 TB is confusing enough without also disagreeing with df.
  return `${n < 10 && i > 1 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}

/**
 * How full a disk is — the one fact a terminal disk table structurally
 * cannot show.
 *
 * `lsblk` reports capacity, not use. An operator with two data disks
 * reads "7.3T" and "9.1T" and has to remember which one holds their
 * media. This answers that before they have read a word, which is most
 * of the argument for the installer having a UI at all.
 */
export function CapacityBar({ used, total, tone = "neutral", hideLabel }: CapacityBarProps) {
  const pct = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
  const label = `${human(used)} used · ${human(Math.max(0, total - used))} free · ${pct}% full`;
  return (
    <div className="fk-cap" data-tone={tone}>
      <div
        className="fk-cap-track"
        role="meter"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
      >
        <i style={{ width: `${pct}%` }} />
      </div>
      {!hideLabel && <p className="fk-cap-label">{label}</p>}
    </div>
  );
}
