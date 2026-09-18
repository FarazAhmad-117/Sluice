/**
 * THE SLUG RULE, MIRRORED FOR THE FORM AND FOR NOTHING ELSE.
 *
 * `convex/lib/naming.ts` is the authority. It rejects a bad slug whatever this
 * file says, and nothing here is relied on for correctness: this exists so that
 * a wrong value is caught on the field it belongs to, while the user is still
 * looking at it, rather than as a sentence about an argument after a round
 * trip.
 *
 * SLUGS ARE REJECTED, NEVER REWRITTEN, and that rule reaches into the interface
 * as well as the server. The tempting affordance is to lowercase the display
 * name and strip everything else into a slug automatically. That is a
 * canonicalisation, it is not injective, and `a-b`, `a_b`, `a b` and `A/B` all
 * collapse to `ab`: the second one anybody creates is refused as a duplicate of
 * a name nobody chose. So the slug is its own field, always visible, always
 * typed, and the rule is printed next to it.
 *
 * `apps/web/test/naming.test.ts` pins this to the cases the server's rule turns
 * on, so the two cannot drift without a test going red.
 */

/** Lowercase letters and digits in groups, single hyphens between groups. */
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** A DNS label is capped at 63 octets; 48 leaves room for a deployment prefix. */
export const MAX_SLUG_LENGTH = 48;

/** The rule as a sentence, for the hint under the field. */
export const SLUG_HINT =
  "Lowercase letters and digits, separated by single hyphens. No spaces, and no leading or trailing hyphen.";

export function isSlug(value: string): boolean {
  if (value.length === 0 || value.length > MAX_SLUG_LENGTH) return false;
  // No `g` flag, deliberately: a global regular expression carries `lastIndex`
  // between `.test` calls and would alternate between pass and fail on one
  // input, which on a form is a field that rejects itself every other keystroke.
  return SLUG.test(value);
}
