import { DiskCard } from "@ferrum/ui-kit";

// Decimal units: what the manufacturer prints and what lsblk reports.
const TB = 1e12;
const GB = 1e9;

export const Empty = () => (
  <DiskCard
    disk={{
      name: "sda",
      size: 8 * TB,
      model: "ST8000VN004-2M2101",
      serial: "WSD9J4KH",
      byId: "/dev/disk/by-id/ata-ST8000VN004-2M2101_WSD9J4KH",
    }}
  />
);

export const Selected = () => (
  <DiskCard
    selected
    disk={{
      name: "nvme0n1",
      size: 512 * GB,
      model: "Samsung SSD 980 PRO 512GB",
      serial: "S6B2NS0T104291",
      byId: "/dev/disk/by-id/nvme-Samsung_SSD_980_PRO_512GB_S6B2NS0T104291",
    }}
  />
);

export const HasData = () => (
  <DiskCard
    disk={{
      name: "sdb",
      size: 4 * TB,
      used: 2.9 * TB,
      model: "WDC WD40EFRX-68N32N0",
      serial: "WD-WCC7K4NVYPAL",
      byId: "/dev/disk/by-id/ata-WDC_WD40EFRX-68N32N0_WD-WCC7K4NVYPAL",
      partitions: [
        { name: "sdb1", fstype: "ext4", size: "3.6T", mountpoint: "/mnt/ferrum-disk-1" },
      ],
    }}
  />
);

export const OsDisk = () => (
  <DiskCard
    disk={{
      name: "sdc",
      size: 240 * GB,
      used: 41 * GB,
      model: "KINGSTON SA400S37240G",
      serial: "50026B7381D4A2C1",
      isOsDisk: true,
      hasFerrum: true,
      partitions: [
        { name: "sdc1", fstype: "vfat", size: "512M", mountpoint: "/boot" },
        { name: "sdc2", fstype: "ext4", size: "223G", mountpoint: "/" },
      ],
    }}
  />
);
