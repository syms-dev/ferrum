import { ApplyProgress } from "@ferrum/ui-kit";

export const Running = () => (
  <ApplyProgress
    steps={[
      { id: "eval", label: "Evaluate the configuration", state: "done" },
      { id: "build", label: "Build the system closure", state: "done" },
      { id: "activate", label: "Activate generation 48", state: "running" },
      { id: "reconcile", label: "Reconcile the apps", state: "pending" },
      { id: "verify", label: "Verify every app answers", state: "pending" },
    ]}
    lines={[
      "activating the configuration...",
      "setting up /etc...",
      "restarting sonarr.service",
      "restarting nginx.service",
    ]}
  />
);

export const Failed = () => (
  <ApplyProgress
    steps={[
      { id: "eval", label: "Evaluate the configuration", state: "done" },
      { id: "build", label: "Build the system closure", state: "done" },
      { id: "activate", label: "Activate generation 48", state: "done" },
      {
        id: "reconcile",
        label: "Reconcile the apps",
        state: "failed",
        detail: "sonarr: /data/media/tv is not writable",
      },
      { id: "verify", label: "Verify every app answers", state: "pending" },
    ]}
    lines={[
      "reconciling sonarr...",
      "  root folder /data/media/tv",
      "sonarr: POST /api/v3/rootfolder -> 400",
      "sonarr: Folder is not writable by user sonarr",
    ]}
  />
);
