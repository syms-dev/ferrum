import { StepRail } from "@ferrum/ui-kit";

const noop = () => {};

const STEPS = [
  { label: "Check this machine", detail: "What ferrum found, and anything that would stop the install." },
  { label: "Choose a disk", detail: "The disk ferrum installs onto. Everything on it is erased." },
  { label: "Pick your apps", detail: "Plex, the *arrs, a download client. You can change this later." },
  { label: "Your domain and login", detail: "Where the apps are published, and the password that opens them." },
  { label: "Review and install", detail: "Nothing is written until you confirm on this screen." },
];

export const EarlyOn = () => <StepRail steps={STEPS} current={0} onBack={noop} />;

export const PartWayThrough = () => <StepRail steps={STEPS} current={2} onBack={noop} />;

/** After the erase is confirmed there is no way back, and the rail stops offering one. */
export const NoWayBack = () => <StepRail steps={STEPS} current={4} canGoBack={false} />;
