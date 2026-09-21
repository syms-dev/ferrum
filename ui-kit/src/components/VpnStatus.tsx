import { Badge } from "./Badge";
import { Copyable } from "./Copyable";
import "./VpnStatus.css";

export interface VpnStatusProps {
  /** The app whose traffic is tunnelled. Today only qBittorrent. */
  appName: string;
  /** `up` means the tunnel handshook recently; `down` means it has not. */
  state: "up" | "down";
  killSwitch: boolean;
  interfaceName?: string;
  endpoint?: string;
  /** The address a tracker actually sees. The whole point of the panel. */
  publicAddress?: string;
  forwardedPort?: number | false;
  lastHandshake?: string;
  uptime?: string;
  drops?: number;
}

/**
 * Whether the torrent client's traffic is really leaving through the VPN.
 *
 * The question this answers is not "is a tunnel configured" but "what
 * address does a tracker see", so that field is stated outright rather
 * than left to be inferred from an interface name.
 *
 * A down tunnel with the kill switch on is NOT an error state: that is
 * the kill switch working, and the panel says so. A down tunnel with the
 * kill switch OFF is the dangerous one — traffic is going out over the
 * operator's own address right now — and it is the only case painted as
 * danger.
 */
export function VpnStatus({
  appName,
  state,
  killSwitch,
  interfaceName,
  endpoint,
  publicAddress,
  forwardedPort,
  lastHandshake,
  uptime,
  drops,
}: VpnStatusProps) {
  const leaking = state === "down" && !killSwitch;

  return (
    <section className="fk-vpn" data-leaking={leaking} aria-label={`${appName} VPN status`}>
      <div className="fk-vpn-head">
        <h3>
          {state === "up"
            ? `${appName} traffic leaves through the VPN`
            : killSwitch
              ? `${appName} is stopped — the tunnel is down`
              : `${appName} is not using the VPN`}
        </h3>
        <Badge tone={state === "up" ? "ok" : "danger"}>
          {state === "up" ? "Tunnel up" : "Tunnel down"}
        </Badge>
        <Badge tone={killSwitch ? "accent" : "danger"}>
          {killSwitch ? "Kill switch on" : "No kill switch"}
        </Badge>
        {lastHandshake && <span className="fk-vpn-when">last handshake {lastHandshake}</span>}
      </div>

      <p className="fk-vpn-note">
        {leaking ? (
          <>
            The tunnel is down and there is no kill switch, so {appName} is reaching trackers
            from this box&apos;s own address right now.
          </>
        ) : state === "down" ? (
          <>
            {appName} is bound to the tunnel interface, so with the tunnel down it has no route
            and has stopped rather than falling back to your own address.
          </>
        ) : (
          <>
            {appName} is bound to the tunnel interface, not to the box&apos;s network. If the
            tunnel drops it loses its route and stops seeding rather than falling back to your
            own address.
          </>
        )}
      </p>

      <dl className="fk-vpn-grid">
        {interfaceName && (
          <div>
            <dt>Interface</dt>
            <dd>
              <Copyable value={interfaceName} variant="inline" describe="Copy the interface name" />
            </dd>
          </div>
        )}
        {endpoint && (
          <div>
            <dt>Endpoint</dt>
            <dd>
              <Copyable value={endpoint} variant="inline" describe="Copy the endpoint" />
            </dd>
          </div>
        )}
        {publicAddress && (
          <div>
            <dt>Address a tracker sees</dt>
            <dd>
              <Copyable value={publicAddress} variant="inline" describe="Copy the public address" />
            </dd>
          </div>
        )}
        {forwardedPort !== undefined && (
          <div>
            <dt>Forwarded port</dt>
            <dd className="fk-vpn-mono">
              {forwardedPort === false ? "none — seeding will be slow" : `${forwardedPort} · open`}
            </dd>
          </div>
        )}
        {uptime && (
          <div>
            <dt>Since</dt>
            <dd className="fk-vpn-mono">
              {uptime}
              {drops !== undefined && ` · ${drops} drops`}
            </dd>
          </div>
        )}
      </dl>
    </section>
  );
}
