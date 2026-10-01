import { ConvexError } from "convex/values";
import { EmailFormatError, normaliseEmail as normalise } from "@sluice/crypto";

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

/**
 * The single place an address becomes an account identity on the server.
 *
 * The rule itself -- trim, `toLowerCase` rather than `toLocaleLowerCase`, the
 * RFC 5321 length cap, one "@" and no whitespace -- is defined once in
 * `@sluice/crypto` (`src/email.ts`), where the reasons for each part are
 * written down. It is there rather than here because every client must apply
 * the identical rule before it derives a key, and a second copy is exactly the
 * drift hazard that used to exist between this file and the dashboard.
 *
 * What this wrapper adds is the brand and the transport. The package's
 * messages are the server's messages verbatim ("email must be ..."), and they
 * are rethrown as `ConvexError` so they reach the caller as `data` rather than
 * as an opaque server error. They never echo the input.
 */
export function normaliseEmail(email: string): NormalisedEmail {
  try {
    return normalise(email) as NormalisedEmail;
  } catch (error) {
    if (error instanceof EmailFormatError) throw new ConvexError(error.message);
    throw error;
  }
}
