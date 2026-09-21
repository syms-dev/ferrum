import { RollbackConfirm } from "@ferrum/ui-kit";

const noop = () => {};

export const Confirming = () => (
  <RollbackConfirm
    target={47}
    current={48}
    effects={[
      "Prowlarr goes back to disabled.",
      "The media root returns to /mnt/ferrum-disk-0; your files don't move.",
      "Sonarr and Radarr return to their generation-47 settings.",
    ]}
    onConfirm={noop}
    onCancel={noop}
  />
);

export const InProgress = () => (
  <RollbackConfirm target={47} current={48} busy onConfirm={noop} onCancel={noop} />
);
