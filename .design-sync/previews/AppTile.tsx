import { AppTile } from "@ferrum/ui-kit";

export const Running = () => (
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
);

export const OwnLogin = () => (
  <AppTile
    app={{
      id: "plex",
      displayName: "Plex",
      summary: "Media server with its own apps for TV, phone and browser.",
      enabled: true,
      url: "plex.example.com",
      health: "active",
      auth: "own-login",
    }}
  />
);

export const NotRunning = () => (
  <AppTile
    app={{
      id: "prowlarr",
      displayName: "Prowlarr",
      summary: "Indexer manager that feeds Sonarr and Radarr.",
      enabled: true,
      url: "prowlarr.example.com",
      health: "failed",
      auth: "sso",
    }}
  />
);

export const Off = () => (
  <AppTile
    app={{
      id: "jellyfin",
      displayName: "Jellyfin",
      summary: "Open-source media server. Run it instead of Plex, not alongside.",
      enabled: false,
    }}
  />
);
