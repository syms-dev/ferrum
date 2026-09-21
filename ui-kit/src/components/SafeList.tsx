import "./SafeList.css";

export interface SafeListProps {
  /** The disks that will NOT be touched, already described for a human. */
  disks: string[];
}

/**
 * The disks that survive.
 *
 * This claim matters as much as the positive one, and a flat list of all
 * disks cannot make it — an operator with 7TB of media needs to see that
 * it is not in scope, not infer it from absence. It updates as the
 * selection changes, so choosing visibly moves a disk OUT of the safe
 * list, which is the moment the consequence becomes legible.
 *
 * The closing sentence is `confirm.rs`'s own structural argument, kept
 * verbatim: this is a property of how the configuration is generated, not
 * a promise the UI is making on its behalf.
 */
export function SafeList({ disks }: SafeListProps) {
  return (
    <section className="fk-safe" aria-label="Disks that will not be touched">
      <h3>These disks will not be touched</h3>
      <ul>
        {disks.map((d) => (
          <li key={d}>{d}</li>
        ))}
      </ul>
      <p>
        A disk not named in the generated <code>disko.nix</code> is never opened, partitioned or
        mounted. That is a structural guarantee, not a setting.
      </p>
    </section>
  );
}
