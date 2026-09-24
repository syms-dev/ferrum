import type { ReactNode } from "react";
import { Badge } from "./Badge";
import "./RiskySetting.css";

export interface RiskySettingProps {
  /** Short, in consequence terms: "Moves this dashboard", not "port". */
  badge: string;
  /** The value in force right now, so the operator can see what they are changing from. */
  current: string;
  /** What happens after the next apply. Shown ONLY once the value changes. */
  effect?: string;
  /** How to get back in if this locks them out. */
  recovery?: string;
  /** Whether the staged value differs from what is applied. */
  changed?: boolean;
  /** The control itself — usually a SchemaField. */
  children: ReactNode;
}

/**
 * A setting that can break the thing the operator is using to change it.
 *
 * The settings audit found a group of these — the daemon's port, the
 * reverse proxy, SSO on the control plane — presented in a plain form
 * exactly like a log level. Changing any of them can end with the
 * dashboard unreachable and the only fix over SSH.
 *
 * The owner's decision was that they stay editable, with the consequence
 * named at the point of change rather than in a footnote. So this shows
 * what is in force now, and reveals the consequence only once the value
 * actually differs — a warning that is always on screen is one the
 * operator learns to scroll past, and then it is not there when it
 * matters.
 *
 * It names the way back too. "This will make the dashboard unreachable"
 * is a threat; "and here is how you recover" is a decision someone can
 * actually take.
 */
export function RiskySetting({
  badge,
  current,
  effect,
  recovery,
  changed = false,
  children,
}: RiskySettingProps) {
  return (
    <section className="fk-risky" data-changed={changed}>
      <div className="fk-risky-head">
        <Badge tone="danger">{badge}</Badge>
        <span className="fk-risky-now">{current}</span>
      </div>

      {children}

      {changed && effect && (
        <div className="fk-risky-effect" role="alert">
          <span className="fk-risky-what">{effect}</span>
          {recovery && <span className="fk-risky-how">{recovery}</span>}
        </div>
      )}
    </section>
  );
}
