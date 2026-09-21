import { GenerationList } from "@ferrum/ui-kit";

export const History = () => (
  <GenerationList
    generations={[
      {
        number: 48,
        built: "2026-09-21T14:04:11Z",
        current: true,
        summary: "Enabled Prowlarr; moved the media root to the pooled /data.",
      },
      {
        number: 47,
        built: "2026-09-19T09:22:40Z",
        current: false,
        summary: "Added the second 4 TB disk to the pool.",
      },
      {
        number: 46,
        built: "2026-09-17T20:51:02Z",
        current: false,
        summary: "First install.",
      },
    ]}
  />
);

export const FirstBoot = () => (
  <GenerationList
    generations={[
      { number: 1, built: "2026-09-21T11:00:00Z", current: true, summary: "First install." },
    ]}
  />
);
