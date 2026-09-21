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
          <b>This disk is erased and written.</b> Running again won&apos;t repartition it.
        </span>
      ) : armedDisk ? (
        <span>
          <b>Nothing&apos;s been written yet.</b> {armedDisk} is lined up to be erased, and
          won&apos;t be until you confirm.
        </span>
      ) : (
        <span>
          <b>Nothing&apos;s been written to this box.</b> Close the tab or go back whenever you
          like.
        </span>
      )}
    </div>
  );
}
