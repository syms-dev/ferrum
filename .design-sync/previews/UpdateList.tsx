import { UpdateList } from "@ferrum/ui-kit";

const noop = () => {};

export const ThreeWaiting = () => (
  <UpdateList
    channel="nixos-25.05"
    checkedAgo="11 minutes ago"
    currentGeneration={48}
    nextGeneration={49}
    onBuild={noop}
    updates={[
      {
        app: "Sonarr",
        from: "4.0.10.2544",
        to: "4.0.14.2939",
        consequence: "Import list fixes. Database schema 213; the rollback carries it back.",
      },
      {
        app: "qBittorrent",
        from: "4.6.5",
        to: "5.0.4",
        consequence: "Major version. The Web UI login is replaced; SSO in front of it is unaffected.",
      },
      {
        app: "Plex",
        from: "1.41.3.9314",
        to: "1.41.5.9522",
        consequence: "Transcoder update. Plex restarts; streams in flight drop.",
      },
    ]}
  />
);

export const NothingWaiting = () => (
  <UpdateList updates={[]} channel="nixos-25.05" checkedAgo="4 minutes ago" />
);
