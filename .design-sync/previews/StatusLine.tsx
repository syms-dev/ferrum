import { StatusLine } from "@ferrum/ui-kit";

export const Healthy = () => (
  <StatusLine state="ok" message="Up to date on generation 47, applied 2 hours ago." />
);

export const Applying = () => (
  <StatusLine state="busy" message="Applying generation 48: building sonarr, radarr." progress={0.42} />
);

export const Drifted = () => (
  <StatusLine
    state="drifted"
    message="Something changed this box outside of ferrum. Re-apply to put it back."
  />
);

export const Failed = () => (
  <StatusLine state="failed" message="Apply failed. sonarr.service didn't start; the log says why." />
);
