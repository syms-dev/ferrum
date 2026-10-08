import { useEffect, useRef } from "react";
import "./ConfirmErase.css";

export interface ConfirmEraseProps {
  diskName: string;
  serial: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * The last thing between the operator and a wiped disk.
 *
 * The serial field alone used to be the whole gate: typing it was the
 * proof you had looked at the right disk. Adding a copy button to that
 * field made it paste-able, which is kinder and also weaker — so the
 * deliberate step moved here, where it costs one click instead of
 * sixteen characters.
 *
 * Two details carry the safety rather than the styling. Focus lands on
 * Cancel, so the reflex of hitting Enter after pasting does nothing.
 * And it restates the disk and serial, because a confirmation that
 * doesn't say what it is confirming only measures whether you can click.
 */
export function ConfirmErase({ diskName, serial, onConfirm, onCancel }: ConfirmEraseProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  return (
    <div
      className="fk-confirm-scrim"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onCancel();
          return;
        }
        if (e.key !== "Tab" || !panelRef.current) return;
        // Keep Tab inside the dialog: the controls behind it still erase
        // a disk, and a keyboard user should not reach them by accident.
        const focusable = panelRef.current.querySelectorAll<HTMLElement>("button");
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }}
    >
      <div
        className="fk-confirm"
        role="dialog"
        aria-modal="true"
        aria-labelledby="fk-confirm-h"
        ref={panelRef}
      >
        <h3 id="fk-confirm-h">Erase {diskName}?</h3>
        <p>
          Everything on <b>{diskName}</b> (serial <code>{serial}</code>) is about to be
          written over. You can&apos;t undo this once it starts.
        </p>
        <div className="fk-confirm-actions">
          <button type="button" ref={cancelRef} onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="fk-confirm-go" onClick={onConfirm}>
            Erase {diskName} and install
          </button>
        </div>
      </div>
    </div>
  );
}
