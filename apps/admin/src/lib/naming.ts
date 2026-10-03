/**
 * THE SLUG RULE, MIRRORED FOR THE FORM AND FOR NOTHING ELSE.
 *
 * `convex/lib/naming.ts` is the authority. It rejects a bad slug whatever this
 * file says, and nothing here is relied on for correctness: this exists so that
 * a wrong value is caught on the field it belongs to, while the user is still
 * looking at it, rather than as a sentence about an argument after a round
 * trip.
 *
 * THE SERVER REJECTS A SLUG, NEVER REWRITES IT. What it receives is exactly
 * what is stored, or a refusal.
 *
 * The dashboard PROPOSES a slug from the project name (`slugFromName` in
 * `lib/projects/create-project.ts`) and SHOWS it before submit, in the hint
 * under the name ("Its address: /projects/<slug>"), with a "Change" control that
 * opens it as its own field. Proposing is a canonicalisation and it is not
 * injective: `a-b`, `a_b`, `a b` and `A/B` all collapse to `a-b` or `ab`, so
 * two different names can propose one slug. That is why the proposal is always
 * visible and editable before anything is sent, and why a collision comes
 * back as the server's duplicate-slug refusal rather than as a slug nobody
 * saw. The browser never rewrites a slug after the person has seen it.
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
