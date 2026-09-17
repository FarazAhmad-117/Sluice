"use client";

import { MIN_PASSWORD_BITS, MIN_PASSWORD_LENGTH } from "@/lib/auth/password";
import type { PasswordAssessment, PasswordVerdict } from "@/lib/auth/password";

/**
 * THE PASSWORD STRENGTH GATE, RENDERED.
 *
 * The rule itself and the argument for it are in `lib/auth/password.ts`. This
 * file only draws it, and it has one job beyond drawing: TO NOT OVERSTATE WHAT
 * THE ESTIMATE MEANS. The word "estimated" appears next to the number, the bar
 * is scaled against the floor rather than against some notion of perfection,
 * and the unmet requirements are listed in full rather than compressed into a
 * colour. A meter that says "Strong" and nothing else teaches people that green
 * is the goal, and green here is a heuristic with no dictionary behind it.
 */

const TONE: Record<PasswordVerdict, { bar: string; text: string; label: string }> = {
  empty: { bar: "bg-hairline", text: "text-text-muted", label: "" },
  unusable: { bar: "bg-status-danger", text: "text-status-danger", label: "Unusable" },
  weak: { bar: "bg-status-danger", text: "text-status-danger", label: "Weak" },
  fair: { bar: "bg-status-warning", text: "text-status-warning", label: "Not enough yet" },
  good: { bar: "bg-status-healthy", text: "text-status-healthy", label: "Accepted" },
  strong: { bar: "bg-status-healthy", text: "text-status-healthy", label: "Accepted, strong" },
};

export function PasswordMeter({ assessment }: { assessment: PasswordAssessment }) {
  const tone = TONE[assessment.verdict];

  return (
    <div className="flex flex-col gap-2">
      <div
        aria-hidden="true"
        className="h-1.5 w-full overflow-hidden rounded-input bg-hairline"
      >
        <div
          className={`h-full rounded-input transition-[width] duration-200 ${tone.bar}`}
          style={{ width: `${Math.round(assessment.fraction * 100)}%` }}
        />
      </div>

      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <span className={`text-base font-medium ${tone.text}`}>{tone.label}</span>
        <span className="font-mono text-sm text-text-muted">
          {assessment.verdict === "empty"
            ? `${MIN_PASSWORD_LENGTH} characters and ${MIN_PASSWORD_BITS} bits minimum`
            : `${Math.round(assessment.bits)} bits estimated, ${MIN_PASSWORD_BITS} needed`}
        </span>
      </div>

      {assessment.problems.length === 0 ? null : (
        <ul className="flex flex-col gap-1" aria-live="polite">
          {assessment.problems.map((problem) => (
            <li key={problem} className="text-base text-text-muted">
              {problem}
            </li>
          ))}
        </ul>
      )}

      <p className="text-base text-text-muted">
        This estimate has no dictionary and no breach corpus behind it, and nothing about your
        password leaves this tab. It catches short and repetitive choices. It will not catch a
        common phrase, so do not treat a green bar as a promise.
      </p>
    </div>
  );
}
