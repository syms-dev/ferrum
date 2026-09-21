import { Badge } from "./Badge";
import { CapacityBar } from "./CapacityBar";
import "./DiskCard.css";

export interface DiskPartition {
  name: string;
  fstype?: string;
  size?: string;
  mountpoint?: string;
}

export interface Disk {
  /** Kernel name, e.g. `sda`. */
  name: string;
  /** Total capacity in bytes. */
  size: number;
  /** Bytes in use, when known. Absent for an unpartitioned disk. */
  used?: number;
  model?: string;
  /**
   * The serial. Absent means the disk is UNSELECTABLE: there is nothing
   * the operator could type to name it, so the confirmation gate cannot
   * cover it. Its absence does not disqualify the machine — a floppy or
   * an empty card reader has no serial and refusing the whole host over
   * one was a real defect.
   */
  serial?: string;
  /** Stable `/dev/disk/by-id/` path. */
  byId?: string;
  partitions?: DiskPartition[];
  /** This is the disk the system is currently running from. */
  isOsDisk?: boolean;
  /** This disk already holds a ferrum installation. */
  hasFerrum?: boolean;
}

export interface DiskCardProps {
  disk: Disk;
  selected?: boolean;
  onSelect?: (name: string) => void;
}

/**
 * One disk, as something to choose between — not a row in a table.
 *
 * Stacked cards rather than a grid, deliberately: a grid invites
 * comparison by position, but the operator must compare by the label
 * they are about to TYPE. Everything here is arranged so the
 * identification line (name, size, model) is largest and the serial is
 * findable, with the rest as corroboration.
 *
 * A disk with no serial renders locked and cannot be chosen.
 */
export function DiskCard({ disk, selected = false, onSelect }: DiskCardProps) {
  const selectable = Boolean(disk.serial);
  return (
    <button
      type="button"
      className="fk-disk"
      data-selected={selected}
      data-locked={!selectable}
      aria-pressed={selectable ? selected : undefined}
      disabled={!selectable}
      onClick={selectable ? () => onSelect?.(disk.name) : undefined}
    >
      <span className="fk-disk-head">
        <span className="fk-disk-name">{disk.name}</span>
        <span className="fk-disk-size">{(disk.size / 1e12).toFixed(1)} TB</span>
        <span className="fk-disk-model">{disk.model ?? "(no model reported)"}</span>
        <span className="fk-disk-pick">
          {!selectable ? "Not selectable" : selected ? "Will be erased" : "Select"}
        </span>
      </span>

      {!selectable && (
        <p className="fk-disk-note">
          This device reports no serial, so there is nothing you could type to name it. It cannot
          be chosen — and its presence does not disqualify this machine.
        </p>
      )}

      {selectable && (
        <>
          {disk.used !== undefined && (
            <CapacityBar used={disk.used} total={disk.size} tone={selected ? "danger" : "neutral"} />
          )}

          <span className="fk-disk-badges">
            {disk.isOsDisk && <Badge tone="accent">Currently the OS disk</Badge>}
            {disk.hasFerrum && <Badge>ferrum install detected</Badge>}
            {!disk.isOsDisk && disk.used !== undefined && disk.used > 0 && (
              <Badge tone="ok">Holds data</Badge>
            )}
          </span>

          <span className="fk-disk-kv">
            <span className="fk-disk-k">serial</span>
            <span className="fk-disk-v">{disk.serial}</span>
            {disk.byId && (
              <>
                <span className="fk-disk-k">by-id</span>
                <span className="fk-disk-v">{disk.byId}</span>
              </>
            )}
          </span>

          {disk.partitions && disk.partitions.length > 0 && (
            <span className="fk-disk-parts">
              {disk.partitions.map((p) => (
                <span key={p.name}>
                  {p.name} {p.fstype ?? "—"} {p.size ?? ""}
                  {p.mountpoint ? ` mounted at ${p.mountpoint}` : ""}
                </span>
              ))}
            </span>
          )}
        </>
      )}
    </button>
  );
}
