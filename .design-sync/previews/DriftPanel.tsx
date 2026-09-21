import { DriftPanel } from "@ferrum/ui-kit";

const noop = () => {};

export const ThreeThings = () => (
  <DriftPanel
    generation={48}
    firstSeen="03:14:07, 21 Sep 2026"
    onReapply={noop}
    onRollback={noop}
    items={[
      {
        subject: "/etc/nginx/nginx.conf",
        kind: "Edited by hand",
        detail:
          "A proxy_pass for qbit.example.com was added below the ferrum block. Re-applying removes it.",
      },
      {
        subject: "systemctl stop sabnzbd.service",
        kind: "Stopped by hand",
        detail:
          "sabnzbd.service has been down for 6 hours 41 minutes. Generation 48 has it enabled.",
      },
      {
        subject: "/var/lib/sonarr/config.xml",
        kind: "Diverged",
        detail:
          "The root folder was changed to /mnt/scratch/tv. ferrum manages this file and will write /data/media/tv back.",
      },
    ]}
  />
);

export const OneThing = () => (
  <DriftPanel
    generation={48}
    firstSeen="09:41:22, 21 Sep 2026"
    onReapply={noop}
    onRollback={noop}
    items={[
      {
        subject: "/var/lib/radarr/config.xml",
        kind: "Diverged",
        detail: "The API key was regenerated in Radarr's own UI. Sonarr and Prowlarr still hold the old one.",
      },
    ]}
  />
);
