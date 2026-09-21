import { Copyable } from "@ferrum/ui-kit";

export const Serial = () => (
  <Copyable value="S6B2NS0T104291" describe="Copy nvme0n1's serial" />
);

export const ByIdPath = () => (
  <Copyable
    value="/dev/disk/by-id/ata-ST8000VN004-2M2101_WSD9J4KH"
    describe="Copy sda's by-id path"
  />
);

export const Inline = () => (
  <p style={{ margin: 0, fontSize: ".9rem" }}>
    Point your DNS at <Copyable value="203.0.113.41" variant="inline" describe="Copy the IP" /> and
    the apps answer on their own names.
  </p>
);
