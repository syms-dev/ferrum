import { AppShell, StatusLine, AppTile } from "@ferrum/ui-kit";

const NAV = [
  { href: "#/apps", label: "Apps" },
  { href: "#/secrets", label: "Secrets" },
  { href: "#/apply", label: "Apply" },
  { href: "#/generations", label: "Generations" },
];

export const Dashboard = () => (
  <AppShell
    hostname="ferrum.example.com"
    nav={NAV}
    current="#/apps"
    status={<StatusLine state="ok" message="Up to date on generation 48, applied 2 hours ago." />}
  >
    <AppTile
      app={{
        id: "sonarr",
        displayName: "Sonarr",
        summary: "TV series collection manager for Usenet and BitTorrent.",
        enabled: true,
        url: "sonarr.example.com",
        health: "active",
        auth: "sso",
      }}
    />
  </AppShell>
);

export const WhileApplying = () => (
  <AppShell
    hostname="ferrum.example.com"
    nav={NAV}
    current="#/apply"
    status={
      <StatusLine state="busy" message="Applying generation 49: building sonarr." progress={0.42} />
    }
  >
    <p style={{ margin: 0, color: "var(--ferrum-muted)" }}>
      The box stays reachable. Nothing switches over until the build succeeds.
    </p>
  </AppShell>
);
