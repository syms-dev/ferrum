import { VpnStatus } from "@ferrum/ui-kit";

export const TunnelUp = () => (
  <VpnStatus
    appName="qBittorrent"
    state="up"
    killSwitch
    interfaceName="wg0-mullvad"
    endpoint="185.65.134.152:51820"
    publicAddress="185.65.134.152"
    forwardedPort={52841}
    lastHandshake="38 seconds ago"
    uptime="14 days, 2 hours"
    drops={0}
  />
);

export const TunnelDownButHeld = () => (
  <VpnStatus
    appName="qBittorrent"
    state="down"
    killSwitch
    interfaceName="wg0-mullvad"
    endpoint="185.65.134.152:51820"
    lastHandshake="11 minutes ago"
  />
);

export const Leaking = () => (
  <VpnStatus
    appName="qBittorrent"
    state="down"
    killSwitch={false}
    interfaceName="wg0-mullvad"
    publicAddress="198.51.100.74"
    forwardedPort={false}
    lastHandshake="2 hours ago"
  />
);
