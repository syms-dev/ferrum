import "./Badge.css";

export interface BadgeProps {
  children: React.ReactNode;
  /**
   * `ok` marks a disk holding data the operator cares about; `accent`
   * marks a structural fact like "this is the OS disk"; `neutral` is
   * everything else. There is deliberately no `danger` variant — a badge
   * is a property of a thing, and "about to be destroyed" is a property
   * of the *selection*, which the card and the gate own.
   */
  tone?: "neutral" | "ok" | "accent";
}

/** A short, uppercase fact about the object it sits on. */
export function Badge({ children, tone = "neutral" }: BadgeProps) {
  return <span className="fk-badge" data-tone={tone}>{children}</span>;
}
