import type { ReactNode } from "react";
import "./AppShell.css";

export interface NavItem {
  /** The hash route this item selects, e.g. `#/apps`. */
  href: string;
  label: string;
}

export interface AppShellProps {
  /** The host this dashboard is administering. Not decoration: ferrum is
   * installed per machine, and a browser tab that does not say which
   * machine it is pointed at is how the wrong host gets rebooted. */
  hostname: string;
  nav: NavItem[];
  current: string;
  /** The status line — what the host is doing right now. */
  status?: ReactNode;
  children: ReactNode;
}

/** Frame, navigation and identity for every dashboard view. */
export function AppShell({ hostname, nav, current, status, children }: AppShellProps) {
  return (
    <div className="fk-shell">
      <header className="fk-shell-head">
        <span className="fk-shell-brand">ferrum</span>
        <span className="fk-shell-host">{hostname}</span>
        <nav className="fk-shell-nav" aria-label="Sections">
          {nav.map((n) => (
            <a key={n.href} href={n.href} aria-current={n.href === current ? "page" : undefined}>
              {n.label}
            </a>
          ))}
        </nav>
      </header>
      {status && <div className="fk-shell-status">{status}</div>}
      <main className="fk-shell-main">{children}</main>
    </div>
  );
}
