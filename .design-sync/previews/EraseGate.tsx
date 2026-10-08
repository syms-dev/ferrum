import { EraseGate } from "@ferrum/ui-kit";

export const ConfirmBySerial = () => (
  <EraseGate
    diskName="nvme0n1"
    serial="S6B2NS0T104291"
    otherSerials={{
      sdb: "WD-WCC7K4NVYPAL",
      sdc: "WSD9J4KH",
    }}
  />
);

export const SingleDiskMachine = () => (
  <EraseGate diskName="sda" serial="50026B7381D4A2C1" />
);
