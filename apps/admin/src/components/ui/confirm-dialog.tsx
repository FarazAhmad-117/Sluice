import { useEffect, useId, useRef } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { Button } from "./button";

/**
 * A CONFIRMATION FOR A DESTRUCTIVE ACTION.
 *
 * A native `<dialog>` opened with `showModal()`, which is what makes it truly
 * modal for free: the page behind is inert, focus is held inside, Escape
 * closes it, and focus returns to the opener when it closes. Focus starts on
 * Cancel, so a stray Enter does not delete anything. The destructive button
 * says what it does in words ("Delete"), never only in red.
 */
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  busy = false,
  error,
  onConfirm,
  onClose,
}: {
  readonly open: boolean;
  readonly title: ReactNode;
  readonly children?: ReactNode;
  readonly confirmLabel: string;
  readonly busy?: boolean;
  readonly error?: string | null;
  readonly onConfirm: () => void;
  readonly onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const bodyId = useId();

  useEffect(() => {
    const element = dialog.current;
    if (element === null) return;
    if (open && !element.open) {
      element.showModal();
      cancel.current?.focus();
    } else if (!open && element.open) {
      element.close();
    }
  }, [open]);

  // On `document.body`, beside `#root`: a confirmation asked from inside a
  // drawer (the secret detail sheet) must not be inside the tree the drawer
  // made inert, or it could not be clicked.
  return createPortal(
    <dialog
      ref={dialog}
      aria-labelledby={titleId}
      aria-describedby={children === undefined ? undefined : bodyId}
      onCancel={(event) => {
        // Escape. Closing is the caller's state, and a running delete is not
        // interrupted by closing its confirmation.
        event.preventDefault();
        if (!busy) onClose();
      }}
      onClick={(event) => {
        // A click on the backdrop lands on the dialog element itself.
        if (event.target === event.currentTarget && !busy) onClose();
      }}
      className="m-auto w-[min(440px,calc(100vw-32px))] rounded-modal border border-hairline-strong bg-surface-panel p-0 text-text-body backdrop:bg-surface-base/70 light:backdrop:bg-text-primary/40"
    >
      <div className="flex flex-col gap-5 p-6">
        <div className="flex flex-col gap-2">
          <h2 id={titleId} className="m-0 text-[17px] font-semibold text-text-primary">
            {title}
          </h2>
          {children === undefined ? null : (
            <div id={bodyId} className="text-sm text-text-muted">
              {children}
            </div>
          )}
        </div>
        {error === null || error === undefined ? null : (
          <p role="alert" className="m-0 text-sm text-status-danger">
            {error}
          </p>
        )}
        <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
          <Button
            ref={cancel}
            variant="secondary"
            onClick={() => {
              if (!busy) onClose();
            }}
            aria-disabled={busy || undefined}
          >
            Cancel
          </Button>
          <Button variant="danger" loading={busy} loadingLabel="Deleting" onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </dialog>,
    document.body,
  );
}
