import { CapacityBar } from "@ferrum/ui-kit";

const TB = 1e12;

export const Filling = () => <CapacityBar used={2.9 * TB} total={4 * TB} />;

export const NearlyFull = () => <CapacityBar used={7.6 * TB} total={8 * TB} />;

export const AboutToBeErased = () => (
  <CapacityBar used={2.9 * TB} total={4 * TB} tone="danger" />
);

export const Empty = () => <CapacityBar used={0} total={8 * TB} />;
