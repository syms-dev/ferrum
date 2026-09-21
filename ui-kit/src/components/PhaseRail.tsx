import "./PhaseRail.css";

/**
 * The installer's real phases, from `crates/ferrum-install/src/state.rs`.
 *
 * These are not invented wizard steps. They are what the phase machine
 * records and what a resume resumes to, so showing anything else would
 * be showing the operator a fiction that diverges from the state file the
 * moment something goes wrong.
 */
export type Phase =
  | "generated"
  | "preflightPassed"
  | "installing"
  | "hardwareConfigured"
  | "stage2Applied"
  | "verified";

export const PHASE_LABELS: Record<Phase, string> = {
  generated: "Generated",
  preflightPassed: "Preflight passed",
  installing: "Installing",
  hardwareConfigured: "Hardware configured",
  stage2Applied: "Stage 2 applied",
  verified: "Verified",
};

const ORDER: Phase[] = [
  "generated",
  "preflightPassed",
  "installing",
  "hardwareConfigured",
  "stage2Applied",
  "verified",
];

export interface PhaseRailProps {
  current: Phase;
  /** Seconds spent in each phase that has one. */
  elapsed?: Partial<Record<Phase, number>>;
}

function mmss(s?: number): string {
  if (s === undefined) return "—";
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Where the install has got to, as the state file would say it. */
export function PhaseRail({ current, elapsed = {} }: PhaseRailProps) {
  const at = ORDER.indexOf(current);
  return (
    <ol className="fk-rail">
      {ORDER.map((p, i) => (
        <li
          key={p}
          className="fk-rail-row"
          data-state={i < at ? "done" : i === at ? "now" : "todo"}
          aria-current={i === at ? "step" : undefined}
        >
          <span>{PHASE_LABELS[p]}</span>
          <span className="fk-rail-el">{i <= at ? mmss(elapsed[p]) : "—"}</span>
        </li>
      ))}
    </ol>
  );
}
