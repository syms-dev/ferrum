import { PhaseRail } from "@ferrum/ui-kit";

export const BeforeAnythingIsWritten = () => (
  <PhaseRail current="preflightPassed" elapsed={{ generated: 4, preflightPassed: 71 }} />
);

export const Installing = () => (
  <PhaseRail
    current="installing"
    elapsed={{ generated: 4, preflightPassed: 71, installing: 906 }}
  />
);

export const Done = () => (
  <PhaseRail
    current="verified"
    elapsed={{
      generated: 4,
      preflightPassed: 71,
      installing: 1284,
      hardwareConfigured: 38,
      stage2Applied: 622,
      verified: 19,
    }}
  />
);
