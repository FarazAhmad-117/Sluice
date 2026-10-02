import type { ReactNode } from "react";

/**
 * LOADING AND TROUBLE: A SKELETON BLOCK AND A CALLOUT.
 *
 * Skeletons pulse unless the viewer asked for less motion, and are hidden from
 * assistive technology: the region around them says "Loading" once, rather
 * than every grey bar announcing itself.
 *
 * A callout says what happened and what to do, with the action beside it. Its
 * tone is carried by the title and the border, never by colour alone.
 */

export function Skeleton({ className = "" }: { readonly className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`block animate-pulse rounded-input bg-surface-card motion-reduce:animate-none ${className}`}
    />
  );
}

const TONE: Record<"danger" | "warning" | "neutral", string> = {
  danger: "border-status-danger/45 bg-status-danger/8",
  warning: "border-status-warning/45 bg-status-warning/8",
  neutral: "border-hairline-strong bg-surface-panel",
};

export function Callout({
  tone = "neutral",
  title,
  children,
  action,
  role,
}: {
  readonly tone?: "danger" | "warning" | "neutral";
  readonly title: ReactNode;
  readonly children?: ReactNode;
  readonly action?: ReactNode;
  /** `alert` for a failure that just happened; omit for a standing state. */
  readonly role?: "alert" | "status";
}) {
  return (
    <div
      role={role}
      className={`flex flex-col gap-4 rounded-card border p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5 ${TONE[tone]}`}
    >
      <div className="flex min-w-0 flex-col gap-1">
        <p className="m-0 font-semibold text-text-primary">{title}</p>
        {children === undefined ? null : <div className="text-text-muted">{children}</div>}
      </div>
      {action === undefined ? null : <div className="flex shrink-0 gap-2">{action}</div>}
    </div>
  );
}
