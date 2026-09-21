import { Badge } from "@ferrum/ui-kit";

export const Tones = () => (
  <div style={{ display: "flex", gap: ".5rem", flexWrap: "wrap" }}>
    <Badge>Unclaimed</Badge>
    <Badge tone="ok">Running</Badge>
    <Badge tone="accent">Behind SSO</Badge>
  </div>
);

export const InContext = () => (
  <div style={{ display: "flex", gap: ".5rem", alignItems: "baseline", flexWrap: "wrap" }}>
    <strong style={{ fontFamily: "var(--ferrum-sans)" }}>Sonarr</strong>
    <Badge tone="ok">Running</Badge>
    <Badge tone="accent">Behind SSO</Badge>
  </div>
);

export const Warning = () => (
  <div style={{ display: "flex", gap: ".5rem", flexWrap: "wrap" }}>
    <Badge tone="danger">No authentication</Badge>
    <Badge tone="danger">Not running</Badge>
    <Badge>Its own login</Badge>
  </div>
);
