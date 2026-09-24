import "./Badge.css";

export interface BadgeProps {
  children: React.ReactNode;
  /**
   * `ok` is a good state (a disk holding data worth keeping, a service
   * running); `accent` is a structural fact like "this is the OS disk"
   * or "behind SSO"; `danger` is a bad state the operator should act on;
   * `neutral` is everything else.
   *
   * `danger` is for a property of the THING — "not running", "no
   * authentication". It is never for "about to be destroyed", which is a
   * property of the *selection*: the disk card and the erase gate own
   * that, and a badge that borrowed it would put the same red on a disk
   * merely listed as on one actually armed.
   *
   * `warn` is the one between `accent` and `danger`: nothing is broken,
   * but the operator should read it before continuing. The installer's
   * preflight needs it — "something already answers on port 443" is not
   * a failure and is not a neutral fact either.
   */
  tone?: "neutral" | "ok" | "accent" | "danger" | "warn";
}

/** A short, uppercase fact about the object it sits on. */
export function Badge({ children, tone = "neutral" }: BadgeProps) {
  return <span className="fk-badge" data-tone={tone}>{children}</span>;
}
