import { SafeList } from "@ferrum/ui-kit";

export const TwoUntouched = () => (
  <SafeList disks={["sdb — WDC WD40EFRX-68N32N0 (4.0 TB)", "sdc — ST8000VN004-2M2101 (8.0 TB)"]} />
);

export const OneUntouched = () => (
  <SafeList disks={["sdb — Samsung SSD 870 QVO 2TB (2.0 TB)"]} />
);
