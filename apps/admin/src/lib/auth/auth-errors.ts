import { ConvexError } from "convex/values";
import { fromHex } from "@sluice/crypto";
// The one server sentence the dashboard rewrites, imported from where the
// server throws it so the two cannot drift. `convex/lib/errors.ts` imports
// nothing, so this pulls no server code into the browser bundle.
import { DUPLICATE_UID } from "@convex/lib/errors";
import { DerivationBusyError } from "@/lib/crypto/derive";
import { ACCOUNT_SALT_HEX } from "./session-store";

/**
 * HOW AN AUTH FAILURE BECOMES A SENTENCE ON A FORM, AND HOW A SALT FROM THE
 * SERVER IS ACCEPTED OR REFUSED.
 *
 * Split out of `auth-context.tsx` so both can be tested without rendering a
 * React tree. Two rules hold for everything here:
 *
 *  - NO MESSAGE ECHOES ITS INPUT. Not the salt, not the uid, not the address.
 *    None of them is secret, but an error message travels into logs, error
 *    reporters and support tickets, and this file is not the place to decide
 *    case by case which identifiers may go there.
 *  - THE DECOY IS NOT AN ERROR. For an address with no account, `getLoginSalt`
 *    returns a decoy salt of exactly the same shape as a real one. It passes
 *    `decodeLoginSalt`, the derivation runs, and `login` then refuses with the
 *    same sentence a wrong password gets. Nothing here could tell the two
 *    apart, and nothing tries.
 */

/** The dashboard's wording for {@link DUPLICATE_UID}. */
export const DUPLICATE_UID_MESSAGE =
  "Account setup collided with an existing account id. Submit the form again.";

/**
 * The salt `getLoginSalt` returned is not exactly 32 lowercase hex characters.
 *
 * The server stores and returns exactly that, real or decoy, so this means a
 * broken server or a broken transport. It is never a wrong password and never
 * an unknown address. The message says so and does not echo the value.
 */
export class AccountSaltError extends Error {
  constructor() {
    super("The server returned an unusable account salt. Try again, and report it if it persists.");
    this.name = "AccountSaltError";
  }
}

/**
 * Turns `getLoginSalt`'s `accountSalt` into the bytes to derive under.
 *
 * CHECKED BEFORE DECODING, against the same {@link ACCOUNT_SALT_HEX} the
 * session store loads with, so a salt the login flow accepts is always one
 * that survives a reload. `fromHex` alone would accept uppercase and any
 * width; the width would then be refused by `deriveMUK`, but only as an
 * opaque error from inside the derivation. Here it fails before any Argon2
 * work, as an {@link AccountSaltError} a person can act on.
 *
 * Takes `unknown` on purpose. The value comes off the network, and the caller
 * passes `reply?.accountSalt`, so a null or missing reply lands here too and
 * becomes the same error instead of a `TypeError` from destructuring.
 */
export function decodeLoginSalt(hex: unknown): Uint8Array {
  if (typeof hex !== "string" || !ACCOUNT_SALT_HEX.test(hex)) throw new AccountSaltError();
  return fromHex(hex);
}

/**
 * Turns anything thrown during signup, login or unlock into a sentence for the
 * form.
 *
 * `ConvexError.data` is where the server's own message arrives, and it is
 * passed through, with ONE exception: the duplicate-uid refusal, because "uid"
 * means nothing to the person at the form and the remedy, submitting again so
 * a fresh uid is minted, is not one they would guess. Errors this file knows
 * to carry a safe, input-free message pass through by name. Everything else,
 * including the plain `Error`s the flows throw for a mismatched or malformed
 * uid, gets a generic line: a raw error string on a login form is noise at
 * best and an information leak at worst.
 */
export function messageForUser(cause: unknown): string {
  if (cause instanceof ConvexError) {
    const data: unknown = cause.data;
    if (data === DUPLICATE_UID) return DUPLICATE_UID_MESSAGE;
    if (typeof data === "string" && data.length > 0) return data;
  }
  if (cause instanceof DerivationBusyError) {
    return "A key derivation is already running. Wait for it to finish.";
  }
  if (cause instanceof Error && cause.name.startsWith("Derivation")) return cause.message;
  if (cause instanceof Error && cause.name === "EmailFormatError") return cause.message;
  if (cause instanceof Error && cause.name === "UnwrapFailedError") return cause.message;
  if (cause instanceof Error && cause.name === "WrappedKeyFormatError") return cause.message;
  if (cause instanceof AccountSaltError) return cause.message;
  return "Something went wrong. Try again.";
}

export class AuthFlowError extends Error {
  constructor(cause: unknown) {
    super(messageForUser(cause));
    this.name = "AuthFlowError";
  }
}
