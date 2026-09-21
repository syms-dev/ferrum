import { StatusLine } from "@ferrum/ui-kit";

export const Healthy = () => (
  <StatusLine state="ok" message="Up to date — generation 47, applied 2 hours ago." />
);

export const Applying = () => (
  <StatusLine state="busy" message="Applying generation 48 — building sonarr, radarr." progress={0.42} />
);

export const Drifted = () => (
  <StatusLine
    state="drifted"
    message="The running system no longer matches its configuration. Re-apply to correct it."
  />
);

export const Failed = () => (
  <StatusLine state="failed" message="Apply failed — sonarr.service did not start. See the log below." />
);
