import { VpnSettings } from "@ferrum/ui-kit";

const noop = () => {};

// Shape only — the real preset list is a ferrum.* option (R15/OQ2), not
// baked into the UI, so it can change without a release.
const PROVIDERS = [
  {
    id: "mullvad",
    name: "Mullvad",
    where: "Account number from mullvad.net; ferrum generates the key and picks a server.",
    fields: [{ key: "account", label: "Account number", hint: "16 digits", secret: true }],
  },
  {
    id: "proton",
    name: "Proton VPN",
    where: "WireGuard credentials from the Proton VPN downloads page.",
    fields: [
      { key: "username", label: "OpenVPN / WireGuard username" },
      { key: "password", label: "Password", secret: true },
    ],
  },
  {
    id: "airvpn",
    name: "AirVPN",
    where: "Generate a device in the AirVPN client area, then paste its key here.",
    fields: [{ key: "key", label: "Device key", secret: true }],
  },
];

export const NotConfigured = () => (
  <VpnSettings
    appName="qBittorrent"
    providers={PROVIDERS}
    configured={false}
    onSave={noop}
    onSaveRawConfig={noop}
  />
);

export const AlreadyOnMullvad = () => (
  <VpnSettings
    appName="qBittorrent"
    providers={PROVIDERS}
    current="mullvad"
    configured
    onSave={noop}
    onSaveRawConfig={noop}
    onDisable={noop}
  />
);

/**
 * The escape hatch, which is the safety-critical path: a provider ferrum
 * does not know, or a preset that has stopped matching what the provider
 * hands out. It renders by defaulting the picker to "raw" through a
 * provider list whose only entry is unusable here — the component always
 * offers this option last.
 */
export const PasteYourOwnConfig = () => (
  <VpnSettings
    appName="qBittorrent"
    providers={[]}
    configured={false}
    onSave={noop}
    onSaveRawConfig={noop}
  />
);
