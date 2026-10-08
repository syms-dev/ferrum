import { StateRibbon } from "@ferrum/ui-kit";

export const NothingWritten = () => <StateRibbon written={false} />;

export const Armed = () => <StateRibbon written={false} armedDisk="sda (WSD9J4KH)" />;

export const Written = () => <StateRibbon written />;
