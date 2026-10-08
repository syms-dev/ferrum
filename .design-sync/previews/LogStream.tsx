import { LogStream } from "@ferrum/ui-kit";

const APPLY_OUTPUT = [
  "building the system configuration...",
  "these 4 derivations will be built:",
  "  /nix/store/9k2v...-unit-sonarr.service.drv",
  "  /nix/store/p71c...-nginx.conf.drv",
  "  /nix/store/x3ba...-system-path.drv",
  "  /nix/store/mq08...-nixos-system-ferrum-25.05.drv",
  "activating the configuration...",
  "setting up /etc...",
  "reloading user units for ferrum...",
  "restarting sonarr.service",
  "restarting nginx.service",
  "reloading the system manager configuration",
];

export const Applying = () => <LogStream lines={APPLY_OUTPUT} />;

export const WithAFailure = () => (
  <LogStream
    lines={[
      ...APPLY_OUTPUT,
      "warning: the following units failed: sonarr.service",
      "× sonarr.service - Sonarr",
      "     Loaded: loaded (/etc/systemd/system/sonarr.service; enabled)",
      "     Active: failed (Result: exit-code) since Sun 2026-09-21 10:04:18 EDT",
      "  Process: 4471 ExecStart=/nix/store/.../Sonarr (code=exited, status=1/FAILURE)",
      "sonarr[4471]: System.UnauthorizedAccessException: Access to the path '/data/media/tv' is denied.",
    ]}
  />
);
