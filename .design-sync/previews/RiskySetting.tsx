import { RiskySetting, SchemaField } from "@ferrum/ui-kit";

const noop = () => {};

export const Untouched = () => (
  <RiskySetting badge="Moves this dashboard" current="now: 443">
    <SchemaField
      name="listenPort"
      schema={{
        type: "integer",
        title: "Listen port",
        description: "The port this dashboard is served on.",
        default: 443,
      }}
      onChange={noop}
    />
  </RiskySetting>
);

/** The consequence appears only once the value actually differs. */
export const Changed = () => (
  <RiskySetting
    badge="Moves this dashboard"
    current="now: 443"
    changed
    effect="After apply this dashboard is at https://ferrum.example.com:8443 and nothing forwards from 443."
    recovery="To recover, run ferrum rollback over SSH."
  >
    <SchemaField
      name="listenPort"
      schema={{ type: "integer", title: "Listen port", default: 443 }}
      value={8443}
      onChange={noop}
    />
  </RiskySetting>
);

export const UnpublishesEverything = () => (
  <RiskySetting
    badge="Unpublishes every app"
    current="now: on"
    changed
    effect="After apply all 7 apps lose their hostnames and certificates, and this dashboard answers only at https://192.168.2.50."
    recovery="To recover, run ferrum rollback over SSH."
  >
    <SchemaField
      name="reverseProxy"
      schema={{
        type: "boolean",
        title: "Publish apps through the reverse proxy",
        description: "nginx terminates TLS for every app.",
        default: true,
      }}
      value={false}
      onChange={noop}
    />
  </RiskySetting>
);
