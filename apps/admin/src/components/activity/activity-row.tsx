import { Skeleton } from "@/components/ui/feedback";
import type { ActivityLine } from "@/lib/activity/describe";
import { formatDateTime, timeAgo } from "@/lib/format/time";
import { useNow } from "@/lib/format/use-now";

/**
 * ONE LINE OF ACTIVITY: the actor's initial, the sentence, and when, with the
 * exact time as the tooltip. Shared by the Overview card and the Activity page.
 */
export function ActivityRow({ line, className = "" }: { readonly line: ActivityLine; readonly className?: string }) {
  const now = useNow();
  return (
    <li className={`grid grid-cols-[28px_minmax(0,1fr)] gap-2.5 border-t border-hairline py-2.5 ${className}`}>
      <span
        aria-hidden="true"
        className="flex size-6 items-center justify-center rounded-full border border-hairline-strong bg-surface-card text-[11px] font-semibold text-text-primary"
      >
        {line.initial}
      </span>
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="text-[13px] break-words text-text-primary">{line.sentence}</span>
        <time dateTime={new Date(line.at).toISOString()} title={formatDateTime(line.at)} className="text-xs text-text-muted">
          {timeAgo(line.at, now)}
        </time>
      </div>
    </li>
  );
}

export function ActivitySkeletonRows({ count, className = "" }: { readonly count: number; readonly className?: string }) {
  return (
    <>
      {Array.from({ length: count }, (_, index) => (
        <li key={index} aria-hidden="true" className={`grid grid-cols-[28px_minmax(0,1fr)] gap-2.5 border-t border-hairline py-2.5 ${className}`}>
          <Skeleton className="size-6 rounded-full" />
          <div className="flex flex-col gap-1.5 py-0.5">
            <Skeleton className="h-3 w-4/5" />
            <Skeleton className="h-2.5 w-1/3" />
          </div>
        </li>
      ))}
    </>
  );
}
