import "./StateRibbon.css";

export interface StateRibbonProps {
  /**
   * Whether the target's disk has been written to yet.
   *
   * The single most important fact on any screen, and the reason this is
   * one persistent element rather than a sentence repeated per screen —
   * repeated prose is prose people stop reading.
   */
  written: boolean;
  /** The disk selected for erasure, before the point of no return. */
  armedDisk?: string;
}

/** What has and has not happened to the target, always visible. */
export function StateRibbon({ written, armedDisk }: StateRibbonProps) {
  return (
    <div className="fk-ribbon" data-armed={written || Boolean(armedDisk)} role="status">
      <span className="fk-ribbon-dot" aria-hidden="true" />
      {written ? (
        <span>
          <b>This disk has been erased and written to.</b> Re-running will not repartition it.
        </span>
      ) : armedDisk ? (
        <span>
          <b>Nothing has been written yet.</b> {armedDisk} is selected for erasure — it is not
          erased until you confirm.
        </span>
      ) : (
        <span>
          <b>Nothing has been written to this machine.</b> You can close this tab or go back at any
          point.
        </span>
      )}
    </div>
  );
}
