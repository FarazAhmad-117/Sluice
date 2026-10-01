import { EmailFormatError, normaliseEmail as normalise } from "@sluice/crypto";

/**
 * THE DASHBOARD'S VIEW OF `normaliseEmail`, WHICH NOW HAS ONE DEFINITION.
 *
 * The canonicalisation rule lives in `@sluice/crypto` (`src/email.ts`) and the
 * server reaches the same function through `convex/lib/email.ts`. It used to be
 * written out twice, here and on the server, and kept in step by a comment;
 * that duplicate is gone, so the two sides can no longer drift.
 *
 * WHY AGREEMENT MATTERS HERE, as of today. The normalised address is the
 * `userId` argument handed to `deriveMasterUnlockKey`, so it is hashed into the
 * Argon2id SALT. Two spellings of one address would produce two different
 * salts, therefore two different master unlock keys, therefore a user who
 * cannot open their own wrapped private key. That is still the current state:
 * until the account-salt task lands and the salt becomes a random per-account
 * value, CHANGING AN ACCOUNT'S EMAIL WOULD CHANGE ITS MASTER UNLOCK KEY AND
 * ORPHAN EVERY WRAPPED BLOB. The backend has no email change endpoint. After
 * that task the address is only the lookup key for `auth.login`, and this
 * paragraph should be rewritten to say so.
 *
 * THE ONE THING THIS FILE ADDS IS COPY. The package's messages are written for
 * the server, where they arrive in a `ConvexError` and name the `email` field.
 * On a form the person needs an instruction instead, so the dashboard rethrows
 * with its own wording, chosen by `reason` rather than by parsing a message.
 * The class and `name` are unchanged, so `messageForUser` in `auth-context.tsx`
 * still recognises it. Neither message echoes the input: an address is personal
 * data and an error message travels into logs and error reporters.
 */

export { EmailFormatError };

const FORM_MESSAGES = {
  length: "Enter an email address between 1 and 254 characters.",
  shape: "Enter a single email address with no spaces.",
} as const;

/** Trimmed, lowercased and validated, exactly as the server will see it. */
export function normaliseEmail(email: string): string {
  try {
    return normalise(email);
  } catch (error) {
    if (error instanceof EmailFormatError) {
      throw new EmailFormatError(error.reason, FORM_MESSAGES[error.reason]);
    }
    throw error;
  }
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
