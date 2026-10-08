import { ConfirmErase } from "@ferrum/ui-kit";

const noop = () => {};

/**
 * The scrim is `position: fixed`, which covers the browser viewport and
 * contributes no height of its own — so a preview card collapses around
 * it. `transform` on an ancestor makes that ancestor the containing
 * block for fixed children, which pins the dialog inside this box
 * without changing the component.
 *
 * Worth knowing in a real app too: any ancestor with a transform,
 * filter, or `contain` will capture this dialog the same way.
 */
const Stage = ({ children }: { children: React.ReactNode }) => (
  <div
    style={{
      position: "relative",
      transform: "translateZ(0)",
      height: "22rem",
      background: "var(--ferrum-bg)",
      borderRadius: "var(--ferrum-radius)",
    }}
  >
    {children}
  </div>
);

export const Confirming = () => (
  <Stage>
    <ConfirmErase diskName="nvme0n1" serial="S6B2NS0T104291" onConfirm={noop} onCancel={noop} />
  </Stage>
);
