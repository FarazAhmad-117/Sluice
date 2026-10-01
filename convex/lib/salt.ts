import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { ACCOUNT_SALT_BYTES, toHex, utf8 } from "@sluice/crypto";
import { pepper } from "./verifier";

/**
 * Domain string for the decoy. Versioned and distinct from the verifier
 * decoy's (`sluice/auth/decoy/v1`), so the two HMACs under one pepper can
 * never produce the same output from the same input. The `|` separates the
 * label from the address; the label contains no `|`, so the split is
 * unambiguous.
 */
const DECOY_SALT_LABEL = "sluice/decoy-salt/v1|";

/**
 * THE ACCOUNT SALT `getLoginSalt` RETURNS FOR AN ADDRESS WITH NO ACCOUNT.
 *
 * `HMAC-SHA256(key = pepper, message = utf8(label || email))`, truncated to the
 * first {@link ACCOUNT_SALT_BYTES} bytes, lowercase hex.
 *
 * WHY EXACTLY 16 BYTES. A real salt is 16 bytes, and the client checks the
 * width of what it gets back before spending an Argon2 run on it. A decoy of
 * any other width would fail that check, or simply look different, and the
 * endpoint would answer "no such account" by size. Truncating an HMAC keeps
 * its unpredictability per bit, so 128 bits of it is as good a decoy as the
 * whole digest.
 *
 * WHY KEYED AND DETERMINISTIC. Deterministic so that asking twice for one
 * address gets the same answer, as it would for a real account; a fresh random
 * decoy per call would be told apart by calling twice. Keyed under the pepper
 * so nobody outside the deployment can compute it, and so cannot check
 * whether an answer is the decoy for that address.
 *
 * WHAT IT DOES NOT HIDE. Whether an address has an account is already public
 * through signup's duplicate-email message, a limit SECURITY.md publishes.
 * This only keeps the login path from being a cheaper, quieter way to ask.
 *
 * `email` must already be normalised; this function does not normalise, so
 * that it has exactly one spelling of each address to key on, the caller's.
 */
export function decoySalt(email: string): string {
  const mac = hmac(sha256, pepper(), utf8.encode(DECOY_SALT_LABEL + email));
  return toHex(mac.subarray(0, ACCOUNT_SALT_BYTES));
}
