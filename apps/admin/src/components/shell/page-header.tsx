import { Fragment } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { IconButton } from "@/components/ui/button";
import { IconMenu } from "@/components/ui/icons";
import { focusRing, pageGutter } from "@/components/ui/styles";
import { useShell } from "@/lib/shell/shell-context";

/**
 * THE TOP OF EVERY PAGE.
 *
 * At 1024px and up: a 56px bar, the breadcrumb on the left (the last crumb is
 * the page, `aria-current`) and the page's actions on the right.
 *
 * Below 1024px there is no sidebar, so the bar becomes the phone bar from the
 * R3 mobile mock: a menu button that opens the sidebar as a drawer, the page
 * title, and search. Page actions do not fit there; a page puts its primary
 * action in a {@link PhoneActionBar} at the bottom, under the thumb.
 */

export interface Crumb {
  readonly label: string;
  readonly to?: string;
}

export function PageHeader({
  title,
  crumbs = [],
  actions,
}: {
  /** The page's name: the last crumb, and the phone bar's title. */
  readonly title: string;
  /** The crumbs before the page itself. */
  readonly crumbs?: readonly Crumb[];
  readonly actions?: ReactNode;
}) {
  const { openNav } = useShell();
  return (
    <>
      <header
        className={`hidden h-14 shrink-0 items-center justify-between gap-4 border-b border-hairline lg:flex ${pageGutter}`}
      >
        <nav aria-label="Breadcrumb" className="min-w-0">
          <ol className="m-0 flex min-w-0 list-none items-center gap-2 p-0 text-sm text-text-muted">
            {crumbs.map((crumb) => (
              <Fragment key={crumb.label}>
                <li className="min-w-0 truncate">
                  {crumb.to === undefined ? (
                    crumb.label
                  ) : (
                    <Link
                      to={crumb.to}
                      className={`rounded-input text-text-muted no-underline transition-colors hover:text-text-primary ${focusRing}`}
                    >
                      {crumb.label}
                    </Link>
                  )}
                </li>
                <li aria-hidden="true" className="text-text-faint">
                  /
                </li>
              </Fragment>
            ))}
            <li aria-current="page" className="min-w-0 truncate font-medium text-text-primary">
              {title}
            </li>
          </ol>
        </nav>
        {actions === undefined ? null : <div className="flex shrink-0 items-center gap-2.5">{actions}</div>}
      </header>

      <header className="flex h-14 shrink-0 items-center gap-1.5 border-b border-hairline px-2 lg:hidden">
        <IconButton label="Open navigation" onClick={openNav} className="text-text-primary">
          <IconMenu className="size-5" />
        </IconButton>
        <span className="min-w-0 grow truncate font-semibold text-text-primary">{title}</span>
      </header>
    </>
  );
}

/**
 * A page's primary action on a phone: pinned to the bottom, full width, 48px,
 * clear of the home indicator. Renders a spacer in the page so the last row of
 * content is never hidden behind it. Hidden at 1024px and up, where the header
 * carries the action.
 */
export function PhoneActionBar({ children }: { readonly children: ReactNode }) {
  return (
    <>
      <div aria-hidden="true" className="h-24 shrink-0 lg:hidden" />
      <div className="fixed inset-x-0 bottom-0 z-30 border-t border-hairline bg-surface-base px-4 pt-3 pb-[calc(env(safe-area-inset-bottom)+16px)] lg:hidden">
        {children}
      </div>
    </>
  );
}
