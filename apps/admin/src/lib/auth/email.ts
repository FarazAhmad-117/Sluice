import { EmailFormatError, normaliseEmail as normalise } from "@sluice/crypto";

/**
 * THE DASHBOARD'S VIEW OF `normaliseEmail`, WHICH NOW HAS ONE DEFINITION.
 *
 * The canonicalisation rule lives in `@sluice/crypto` (`src/email.ts`) and the
 * server reaches the same function through `convex/lib/email.ts`. It used to be
 * written out twice, here and on the server, and kept in step by a comment;
 * that duplicate is gone, so the two sides can no longer drift.
 *
 * WHY AGREEMENT MATTERS HERE. The normalised address is the LOOKUP KEY, and
 * nothing more: `auth.getLoginSalt` and `auth.login` find the account by it.
 * It is no longer an input to the master unlock key. The key is salted with a
 * random per-account value minted at signup, so CHANGING AN ACCOUNT'S EMAIL
 * WOULD NOT CHANGE ITS MASTER UNLOCK KEY and would orphan nothing; the backend
 * still has no email change endpoint, but that is now a missing feature rather
 * than a cryptographic impossibility. What disagreement between client and
 * server would cost today is lookup: two spellings of one address would be two
 * accounts at signup, or a login that finds the decoy salt instead of the real
 * one and fails with the generic message every wrong password gets.
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
