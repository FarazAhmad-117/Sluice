import { ConvexError } from "convex/values";

/**
 * An email that has been through `normaliseEmail`. The brand exists so that
 * `repo/users.ts` can refuse a raw string: `by_email` is an exact-match index,
 * so an unnormalised write creates a second account for an address that is
 * meant to be the same one, and an unnormalised read silently fails to find
 * the account that exists. Neither shows up as an error anywhere, which is why
 * this is enforced by the compiler rather than by a convention in a comment.
 */
export type NormalisedEmail = string & {
  readonly __normalisedEmail: unique symbol;
};

// RFC 5321 caps a path at 256 octets including the angle brackets, so 254 is
// the longest address that can actually be delivered to. The cap is here so a
// megabyte of text cannot be written into an indexed column.
const MAX_EMAIL_LENGTH = 254;

// Deliberately permissive about what an address may contain and strict about
// the two things that matter here: exactly one "@" with something on each
// side, and no whitespace. Rejecting valid-but-unusual addresses would be a
// worse failure than accepting one that bounces, and this server never sends
// mail, so deliverability is not its business.
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/;

/**
 * The single place an address becomes an account identity.
 *
 * `toLowerCase` and not `toLocaleLowerCase`: the locale-aware form maps "I" to
 * a dotless "i" under a Turkish locale, so the same address would normalise to
 * two different strings depending on where the server happened to run. That is
 * a canonicalisation bug that would split one account in two.
 *
 * No Unicode normalisation beyond case. NFKC would fold visually distinct
 * characters together and merge two real mailboxes into one account; the
 * failure would be a signup rejected for an address its owner has never used,
 * which is worse than the inconsistency it fixes.
 */
export function normaliseEmail(email: string): NormalisedEmail {
  const normalised = email.trim().toLowerCase();

  // Neither message echoes the input. An address is personal data and an error
  // message travels into logs, error reporters and support tickets.
  if (normalised.length === 0 || normalised.length > MAX_EMAIL_LENGTH) {
    throw new ConvexError(
      `email must be between 1 and ${MAX_EMAIL_LENGTH} characters.`,
    );
  }
  if (!EMAIL_SHAPE.test(normalised)) {
    throw new ConvexError("email must be a single address with no spaces.");
  }

  return normalised as NormalisedEmail;
}
