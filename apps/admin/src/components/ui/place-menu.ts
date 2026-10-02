/**
 * WHERE A MENU OPENS, FOR A TRIGGER AT A GIVEN SPOT IN THE VIEWPORT. Pure, so
 * the flip and the edge clamping are tested without a browser.
 *
 * Below the trigger unless the menu does not fit there and there is more room
 * above; capped to the room it gets (it scrolls inside); aligned to the
 * trigger's start or end edge, then kept inside the viewport.
 */

/** Gap between trigger and menu, and the minimum margin to the viewport edge. */
const GAP = 8;
const EDGE = 8;

export interface Placement {
  readonly top: number;
  readonly left: number;
  readonly maxHeight: number;
}

/** Where a menu of `width` x `height` goes for a trigger at `rect`. Pure. */
export function placeMenu(
  rect: { top: number; bottom: number; left: number; right: number },
  size: { width: number; height: number },
  viewport: { width: number; height: number },
  align: "start" | "end",
): Placement {
  const below = viewport.height - rect.bottom - GAP - EDGE;
  const above = rect.top - GAP - EDGE;
  const up = size.height > below && above > below;
  const room = Math.max(up ? above : below, 0);
  const height = Math.min(size.height, room);
  const top = up ? rect.top - GAP - height : rect.bottom + GAP;
  const wanted = align === "end" ? rect.right - size.width : rect.left;
  const left = Math.min(Math.max(wanted, EDGE), Math.max(viewport.width - size.width - EDGE, EDGE));
  return { top, left, maxHeight: room };
}

