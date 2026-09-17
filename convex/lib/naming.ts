import { ConvexError } from "convex/values";

/**
 * SLUGS ARE REJECTED, NEVER REWRITTEN.
 *
 * The obvious alternative, "lowercase it and strip anything that is not a
 * letter or a digit", is a canonicalisation function, and a canonicalisation
 * function that is not injective merges rows that the person who typed them
 * believes are distinct: `a-b`, `a_b`, `a b` and `A/B` all become `ab`, so the
 * second one to be created is refused as a duplicate of a name nobody chose.
 * Worse, the error message names a slug the caller never typed.
 *
 * Rejecting is injective by construction. There is exactly one spelling of any
 * accepted slug, so `by_slug` and `by_org_slug` are exact-match indexes over a
 * space with no aliases, and the uniqueness checks in `orgs.ts` and
 * `projects.ts` are therefore real.
 *
 * The shape: lowercase letters and digits in groups, single hyphens between
 * groups, no leading, trailing or doubled hyphen. That is the LOWEST common
 * denominator across a URL path segment, a DNS label, an environment variable
 * prefix and a shell argument, which is where these strings end up.
 */
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

// A DNS label is capped at 63 octets and these end up in hostnames in every
// deployment story anyone has ever asked for. 48 leaves room for a prefix.
const MAX_SLUG_LENGTH = 48;

export function assertSlug(field: string, value: string): string {
  if (value.length === 0 || value.length > MAX_SLUG_LENGTH) {
    throw new ConvexError(
      `${field} must be between 1 and ${MAX_SLUG_LENGTH} characters.`,
    );
  }
  if (!SLUG.test(value)) {
    // The message describes the rule and does not echo the input, in case a
    // caller ever passes something they should not have.
    throw new ConvexError(
      `${field} must be lowercase letters and digits separated by single hyphens.`,
    );
  }
  return value;
}

// Long enough for a real company or project name, short enough that an
// indexed-adjacent column cannot be used as free storage.
const MAX_DISPLAY_NAME_LENGTH = 100;

/**
 * Control and format characters are rejected rather than stripped. `\p{Cf}`
 * covers the bidirectional overrides, which render as one string and sort as
 * another, and a dashboard listing organisations is exactly the place a
 * spoofed name pays off.
 */
const FORBIDDEN_IN_DISPLAY_NAME = /[\p{Cc}\p{Cf}]/u;

/**
 * Surrounding whitespace is trimmed, and the trimmed value is what is stored
 * and what the length is measured against. Trimming is safe here in a way that
 * rewriting a slug is not: a display name is not an identity, nothing looks it
 * up, and two organisations may share one.
 *
 * Over-length is REJECTED and never truncated. A silently truncated name is a
 * name nobody typed, presented back to the user as though they had.
 */
export function assertDisplayName(field: string, value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_DISPLAY_NAME_LENGTH) {
    throw new ConvexError(
      `${field} must be between 1 and ${MAX_DISPLAY_NAME_LENGTH} characters.`,
    );
  }
  if (FORBIDDEN_IN_DISPLAY_NAME.test(trimmed)) {
    throw new ConvexError(`${field} must not contain control characters.`);
  }
  return trimmed;
}
