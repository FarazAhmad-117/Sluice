import type { ComponentPropsWithRef } from "react";
import { VALUE_MASK } from "@/lib/secrets/decrypt";

/**
 * A SECRET VALUE FIELD THAT HIDES WHAT IS TYPED, WITHOUT GIVING UP LINES.
 *
 * A value can be a PEM key or a JSON blob, so it stays a `<textarea>`: paste
 * and newlines work as typed. `type="password"` would mask everywhere but is
 * one line only, and would flatten such a value.
 *
 * Masking a textarea is `-webkit-text-security: disc`. It is non-standard,
 * and support outside WebKit and Blink is not something this code can rely
 * on, so it is detected, not assumed (`CSS.supports`). Where it is missing,
 * the characters are drawn transparent (the caret stays visible) with a fixed
 * mask laid over the field, so the value is still not on screen; "Show"
 * turns it back to plain text either way.
 */

const TEXT_SECURITY =
  typeof CSS !== "undefined" && typeof CSS.supports === "function" && CSS.supports("-webkit-text-security", "disc");

export function MaskedTextarea({
  shown,
  className = "",
  value,
  ...textarea
}: Omit<ComponentPropsWithRef<"textarea">, "value"> & {
  /** False: masked. The caller's Show/Hide toggle owns this. */
  readonly shown: boolean;
  readonly value: string;
}) {
  const masked = !shown;
  const native = masked && TEXT_SECURITY ? "[-webkit-text-security:disc]" : "";
  const fallback = masked && !TEXT_SECURITY ? "text-transparent caret-text-primary selection:bg-brand/30" : "";
  return (
    <div className="relative">
      <textarea {...textarea} value={value} className={`${className} ${native} ${fallback}`} />
      {masked && !TEXT_SECURITY && value !== "" ? (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute top-3 left-3 font-mono text-sm tracking-[0.12em] text-text-muted"
        >
          {VALUE_MASK}
        </span>
      ) : null}
    </div>
  );
}
