import Link from "next/link";

import {
  PRIMARY_COMMAND,
  PRIMARY_COMMAND_HREF,
} from "@/components/landing/links";
import { focusRing } from "@/components/landing/primitives";

/**
 * THE PRIMARY CALL TO ACTION. THE COMMAND ITSELF, NOT A LABEL FOR ONE.
 *
 * A senior developer reading a secrets manager's homepage is deciding whether
 * this fits in their project, and the fastest possible answer to that is the
 * line they would actually type. "Get started" says nothing; a command says
 * what the integration looks like, that it wraps rather than replaces their
 * process, and that there is no SDK to import.
 *
 * IT APPEARS EXACTLY THREE TIMES ON THE SITE: the navigation bar, the hero, and
 * the closing section. Nothing between the hero and the close asks for an
 * action, which is what lets the middle of the page be read rather than
 * negotiated. `/security` renders the navigation with no call to action at all;
 * see `SiteNav`.
 *
 * ON THE FILL. White, from `--control-solid`, rather than brand blue. On this
 * pure-black canvas white is simply the highest-contrast fill available, and a
 * blue button placed beside a white one always loses. Keeping blue for links,
 * focus rings and active navigation also means the one blue thing on screen is
 * never competing with the one white thing. Both halves are tokens.
 *
 * ON THE PROMPT GLYPH. `aria-hidden`, and not part of the accessible name. A
 * screen reader announcing "dollar sluice run dash dash node server dot js" is
 * reading out a typographic convention, so the link's name is the command and
 * the sentence underneath it carries where the link goes.
 */

type Size = "sm" | "md" | "lg";

const SIZES: Record<Size, string> = {
  /** Navigation bar. Sits beside a text link, so it cannot be tall. */
  sm: "h-9 gap-2 px-3.5 text-[13px]",
  /** Closing section. */
  md: "h-11 gap-2.5 px-4.5 text-sm",
  /** Hero. The loudest control above the fold, and the only one. */
  lg: "h-12 gap-3 px-5 text-[15px]",
};

export function CommandCta({
  size = "md",
  className = "",
}: {
  size?: Size;
  className?: string;
}) {
  return (
    <Link
      href={PRIMARY_COMMAND_HREF}
      className={`inline-flex cursor-pointer items-center justify-center rounded-full bg-control-solid font-mono font-medium tracking-[-0.01em] whitespace-nowrap text-text-on-control-solid transition-colors hover:bg-control-solid-hover ${SIZES[size]} ${focusRing} ${className}`}
    >
      <span aria-hidden="true" className="opacity-45 select-none">
        $
      </span>
      {PRIMARY_COMMAND}
    </Link>
  );
}
