/**
 * THE ONE DEFINITION OF HOW AN EMAIL ADDRESS IS CANONICALISED.
 *
 * This used to exist twice, once in `convex/lib/email.ts` and once in the
 * dashboard, kept honest only by a comment. Every client that touches an
 * account has to produce the same string from the same typed address: the
 * server looks accounts up by it on an exact-match index, and the client feeds
 * it into key derivation. Two spellings of one address on two sides means an
 * account that cannot be found, or a key that cannot be re-derived, and neither
 * surfaces as an error. It lives here because this package is the one module
 * `convex/`, `apps/admin` and later the CLI's vector generator all reach.
 *
 * It throws a plain `EmailFormatError` rather than anything framework-specific.
 * The server wraps it in a `ConvexError`; the dashboard maps it to form copy.
 * `reason` says which rule failed so each can phrase it its own way without
 * parsing a message.
 */

/**
 * RFC 5321 caps a path at 256 octets including the angle brackets, so 254 is
 * the longest address that can actually be delivered to. The cap is here so a
 * megabyte of text cannot be written into an indexed column.
 */
const MAX_EMAIL_LENGTH = 254;

/**
 * Deliberately permissive about what an address may contain and strict about
 * the two things that matter here: exactly one "@" with something on each
 * side, and no whitespace. Rejecting valid-but-unusual addresses would be a
 * worse failure than accepting one that bounces, and nothing here sends mail,
 * so deliverability is not this function's business.
 */
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/;

/** Which rule an address broke. */
export type EmailFormatReason = "length" | "shape";

export class EmailFormatError extends Error {
  readonly reason: EmailFormatReason;

  constructor(reason: EmailFormatReason, message: string) {
    super(message);
    this.name = "EmailFormatError";
    this.reason = reason;
  }
}

/**
 * Trims and lowercases an address, then checks its length and shape.
 *
 * `toLowerCase` and not `toLocaleLowerCase`: the locale-aware form maps "I" to
 * a dotless "i" under a Turkish locale, so the same address would normalise to
 * two different strings depending on the machine it ran on. On the server that
 * would split one account in two; on a client it would derive a different key.
 *
 * No Unicode normalisation beyond case. NFKC would fold visually distinct
 * characters together and merge two real mailboxes into one account; the
 * failure would be a signup rejected for an address its owner has never used,
 * which is worse than the inconsistency it fixes.
 */
export function normaliseEmail(email: string): string {
  const normalised = email.trim().toLowerCase();

  // Neither message echoes the input. An address is personal data and an error
  // message travels into logs, error reporters and support tickets.
  if (normalised.length === 0 || normalised.length > MAX_EMAIL_LENGTH) {
    throw new EmailFormatError(
      "length",
      `email must be between 1 and ${MAX_EMAIL_LENGTH} characters.`,
    );
  }
  if (!EMAIL_SHAPE.test(normalised)) {
    throw new EmailFormatError("shape", "email must be a single address with no spaces.");
  }
  return normalised;
}
