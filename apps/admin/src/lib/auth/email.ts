/**
 * THE CLIENT HALF OF `convex/lib/email.ts`, AND A DELIBERATE DUPLICATE.
 *
 * This function MUST agree with `normaliseEmail` on the server character for
 * character, and the reason is not tidiness. The normalised address is the
 * `userId` argument handed to `deriveMasterUnlockKey`, so it is hashed into the
 * Argon2id SALT. Two spellings of one address produce two different salts,
 * therefore two different master unlock keys, therefore a user who cannot open
 * their own wrapped private key. The failure is silent at signup and fatal at
 * login.
 *
 * WHY THE SALT IS THE EMAIL AND NOT THE CONVEX USER ID. `deriveMUK` is
 * documented as taking a user id, and the Convex `Id<"users">` would be the
 * better identifier: it is opaque, it never changes, and an address change
 * would not orphan a key. It cannot be used, and the reason is a hard ordering
 * constraint rather than a preference:
 *
 *   - `auth.login` takes `email` and `authVerifier`. The verifier is derived
 *     from the MUK. So the MUK must exist BEFORE login returns, and login is
 *     the first thing that tells a client its user id.
 *   - `auth.signup` returns the user id, but it requires the verifier and the
 *     wrapped blobs as ARGUMENTS, so the MUK must exist before signup returns
 *     too.
 *
 * There is no ordering in which a client knows its user id before it needs the
 * key. The only stable identifier the browser holds at both moments is the
 * address the person typed. That is a real cost and it is written here rather
 * than discovered later: CHANGING AN ACCOUNT'S EMAIL WOULD CHANGE ITS MASTER
 * UNLOCK KEY AND ORPHAN EVERY WRAPPED BLOB. The backend has no email change
 * endpoint today. If one is ever added it must re-wrap the private keys under a
 * key derived from the new address, inside the same client transaction, or it
 * will destroy accounts.
 *
 * WHY THIS IS NOT IMPORTED FROM `convex/lib/email.ts`. That module throws
 * `ConvexError` from `convex/values`, and it is server code the dashboard has
 * no business bundling. The duplication is real and it is a drift hazard; it is
 * pinned by `test/email.test.ts`, which is the only thing keeping the two
 * honest.
 */

/** RFC 5321 caps a path at 256 octets including the angle brackets. */
const MAX_EMAIL_LENGTH = 254;

/** Exactly one "@" with something on each side, and no whitespace. */
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/;

export class EmailFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EmailFormatError";
  }
}

/**
 * `toLowerCase` and not `toLocaleLowerCase`, matching the server: the
 * locale-aware form maps "I" to a dotless "i" under a Turkish locale, so the
 * same address would normalise to two different strings depending on the
 * user's machine. Here that would mean two different Argon2id salts for one
 * account.
 *
 * No Unicode normalisation beyond case, also matching the server.
 */
export function normaliseEmail(email: string): string {
  const normalised = email.trim().toLowerCase();

  // Neither message echoes the input. An address is personal data and an error
  // message travels into logs and error reporters.
  if (normalised.length === 0 || normalised.length > MAX_EMAIL_LENGTH) {
    throw new EmailFormatError(
      `Enter an email address between 1 and ${MAX_EMAIL_LENGTH} characters.`,
    );
  }
  if (!EMAIL_SHAPE.test(normalised)) {
    throw new EmailFormatError("Enter a single email address with no spaces.");
  }
  return normalised;
}

/** True when `normaliseEmail` would accept this input. Never throws. */
export function isValidEmail(email: string): boolean {
  try {
    normaliseEmail(email);
    return true;
  } catch {
    return false;
  }
}

/** The part before the "@", lowercased. Used by the password strength gate. */
export function emailLocalPart(email: string): string {
  const at = email.trim().toLowerCase().indexOf("@");
  return at <= 0 ? "" : email.trim().toLowerCase().slice(0, at);
}
