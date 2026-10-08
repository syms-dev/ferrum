import { AppStatusTable } from "@ferrum/ui-kit";

export const AllHealthy = () => (
  <AppStatusTable
    apps={[
      { name: "Plex", url: "plex.example.com", service: true, reachable: "200", certificate: "Let's Encrypt" },
      { name: "Sonarr", url: "sonarr.example.com", service: true, reachable: "302", certificate: "Let's Encrypt" },
      { name: "Radarr", url: "radarr.example.com", service: true, reachable: "302", certificate: "Let's Encrypt" },
      { name: "qBittorrent", url: "qbit.example.com", service: true, reachable: "302", certificate: "Let's Encrypt" },
    ]}
  />
);

export const PartlyBroken = () => (
  <AppStatusTable
    apps={[
      { name: "Plex", url: "plex.example.com", service: true, reachable: "200", certificate: "Let's Encrypt" },
      { name: "Jellyfin", url: "jellyfin.example.com", service: true, reachable: false, certificate: false },
      { name: "Prowlarr", url: "prowlarr.example.com", service: false, reachable: false, certificate: false },
      { name: "Authelia", url: "auth.example.com", service: true, reachable: "200", certificate: "self-signed" },
    ]}
  />
);
