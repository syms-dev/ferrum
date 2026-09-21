import { LivenessPanel } from "@ferrum/ui-kit";

export const Talking = () => (
  <LivenessPanel
    state="talking"
    title="Building the system closure on the target"
    sinceOutput={2}
    sinceProbe={11}
  />
);

export const Quiet = () => (
  <LivenessPanel
    state="quiet"
    title="Building the system closure on the target"
    sinceOutput={240}
    sinceProbe={9}
    plausible="20 to 40 minutes"
  />
);

export const Overdue = () => (
  <LivenessPanel
    state="overdue"
    title="Waiting for the target to come back after kexec"
    sinceOutput={1870}
    sinceProbe={1870}
    attempts={31}
    likelyCause="The target has not answered SSH since it was rebooted into the installer. On a headless box this is usually a NIC the installer image has no driver for."
  />
);
