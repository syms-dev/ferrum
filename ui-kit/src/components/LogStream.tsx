import { useEffect, useRef } from "react";
import "./LogStream.css";

export interface LogStreamProps {
  lines: string[];
  /** Follow new output. Turned off the moment the reader scrolls up. */
  follow?: boolean;
  onFollowChange?: (follow: boolean) => void;
  label?: string;
}

/**
 * Streaming output from the host — an apply, or an install.
 *
 * Shared between the dashboard and the installer on purpose: they are the
 * same problem. Both run a long build on a machine that is not this one,
 * and in both cases the raw output is what a defect is actually diagnosed
 * from. Every bug found while building the install path was diagnosed
 * from this text, so it is a first-class surface rather than a detail
 * behind a disclosure.
 *
 * It never yanks the scroll back. Following stops when the reader scrolls
 * up and resumes only when they return to the bottom — reading the line
 * that explains a failure while the pane jumps away from it is its own
 * small defeat.
 */
export function LogStream({ lines, follow = true, onFollowChange, label }: LogStreamProps) {
  const ref = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!follow || !ref.current) return;
    ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines, follow]);

  return (
    <pre
      className="fk-log"
      ref={ref}
      tabIndex={0}
      aria-label={label ?? "Output from the host"}
      onScroll={(e) => {
        const el = e.currentTarget;
        const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
        if (atBottom !== follow) onFollowChange?.(atBottom);
      }}
    >
      {lines.join("\n")}
    </pre>
  );
}
