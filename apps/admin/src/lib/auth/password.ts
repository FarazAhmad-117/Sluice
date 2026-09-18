import { emailLocalPart } from "./email";

/**
 * THE PASSWORD STRENGTH GATE.
 *
 * WHY THIS IS A SECURITY CONTROL AND NOT A NICETY. The Argon2id salt is
 * `SHA-256("sluice/muk-salt/v1" || userId)` where the user id is the account's
 * email address. The address is public, so the salt is public, so the salt
 * contributes NOTHING to the difficulty of guessing a particular account's key.
 * It only stops one precomputed table from covering every account at once.
 *
 * That leaves the password as the ONLY entropy in the master unlock key, which
 * is the root of the entire key hierarchy. Argon2id at m=64MiB, t=3, p=4 makes
 * each guess expensive; it does not make a small guess space large. A six
 * character password is at most a few billion candidates, and an attacker who
 * has stolen the wrapped key bundle grinds them offline at their own pace with
 * no rate limit and no way for anyone to notice. There is no lockout to hide
 * behind: the attack does not touch the server.
 *
 * THE RULE, STATED ONCE, so it can be argued with:
 *
 *   A password is accepted when ALL of these hold, measured on the NFC
 *   normalised string, which is the exact string `deriveMUK` feeds to Argon2id:
 *
 *   1. At least 12 codepoints.
 *   2. At least 60 bits of estimated entropy by the conservative model below.
 *   3. Not on the embedded blocklist, and not a blocklist entry with digits or
 *      punctuation stuck on either end.
 *   4. Does not contain the local part of the account's email address, and does
 *      not contain "sluice".
 *
 * WHY 12 AND 60. Twelve is the floor at which a passphrase of three ordinary
 * words, or a random-ish string a human will actually retype, can clear the
 * entropy bar at all. Sixty bits is the point at which an offline grind at
 * Argon2id's cost stops being a weekend: at roughly 1.6 seconds per guess on
 * the user's own hardware, and assuming an attacker buys three orders of
 * magnitude of parallelism over that, 2^60 candidates is still far outside the
 * reach of anyone who is not a state. It is deliberately NOT 128: a bar nobody
 * can clear gets routed around with a password manager entry that is then
 * pasted into a sticky note, and the product has no recovery path to catch
 * that.
 *
 * WHAT THIS MODEL IS NOT. It is not zxcvbn. It has no dictionary of English
 * words, no leaked-password corpus, no keyboard adjacency graph. It will
 * cheerfully pass "Thermostat-Thermostat-19" with a score it does not deserve,
 * because it can see the repeat but not the dictionary hit. Bringing in a real
 * estimator means bringing in a dependency and several hundred kilobytes; that
 * is a decision for a human, and the honest position is that THIS GATE CATCHES
 * SHORT AND REPETITIVE PASSWORDS AND LITTLE ELSE. It is a floor, not a
 * guarantee, and the interface says "estimated" everywhere for that reason.
 *
 * NOTHING HERE EVER LEAVES THE BROWSER. The password is not sent anywhere for
 * scoring, there is no breach-corpus lookup, and no k-anonymity range query.
 * That is a deliberate trade: a range query to an external service would catch
 * far more, and it would also tell that service that somebody is choosing a
 * password right now, with a five character prefix of its hash.
 */

/** The minimum length, in codepoints of the NFC normalised password. */
export const MIN_PASSWORD_LENGTH = 12;

/** The entropy floor, in bits, by the estimator below. */
export const MIN_PASSWORD_BITS = 60;

/**
 * A short embedded blocklist. Deliberately small and deliberately honest about
 * being small: it exists to catch the handful of strings that are typed when
 * somebody is not really choosing a password, not to stand in for a corpus.
 * Every entry is at least eight characters, because anything shorter is already
 * rejected by the length rule and would only make this list look bigger than it
 * is.
 */
const BLOCKLIST = new Set([
  "password",
  "password1",
  "password123",
  "passw0rd",
  "p@ssword",
  "p@ssw0rd",
  "12345678",
  "123456789",
  "1234567890",
  "123456789012",
  "qwertyuiop",
  "qwerty123",
  "iloveyou",
  "sunshine",
  "princess",
  "football",
  "baseball",
  "superman",
  "trustno1",
  "letmein1",
  "letmeinnow",
  "welcome1",
  "welcome123",
  "admin123",
  "administrator",
  "changeme",
  "changeit",
  "secret123",
  "correcthorsebatterystaple",
  "correct horse battery staple",
]);

/** Five buckets, so the meter has something to say that is not a number. */
export type PasswordVerdict = "empty" | "unusable" | "weak" | "fair" | "good" | "strong";

export interface PasswordAssessment {
  /** Estimated bits. "Estimated" is load bearing: see the header. */
  readonly bits: number;
  readonly verdict: PasswordVerdict;
  /** True only when every rule passes. The submit control reads this. */
  readonly acceptable: boolean;
  /** Every unmet requirement, in the order a person should fix them. */
  readonly problems: readonly string[];
  /** 0 to 1, for the meter width. Saturates at twice the entropy floor. */
  readonly fraction: number;
}

/**
 * The character pool the password actually draws from.
 *
 * Counting the pool by classes USED rather than classes AVAILABLE is the
 * conservative direction: a twelve character all-lowercase password scores
 * against a pool of 26, not of 95, which is what an attacker who notices the
 * pattern would do.
 */
function poolSize(password: string): number {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  // Printable ASCII minus letters, digits and space: 32 punctuation marks.
  if (/[!-/:-@[-`{-~]/.test(password)) pool += 32;
  if (/ /.test(password)) pool += 1;
  // Anything outside ASCII is credited a flat, modest amount. A real estimate
  // would need to know which script and which input method; this is a floor
  // that does not pretend otherwise.
  //
  // THE RANGE IS WRITTEN AS ESCAPES AND MUST STAY THAT WAY. It used to carry a
  // literal NUL byte and a literal DEL byte, which is the same regular
  // expression and a worse file: git and grep both classify a source file
  // containing a NUL as binary, so this module dropped out of text searches and
  // showed no diff on review.
  //
  // `no-control-regex` is suppressed rather than satisfied, because the control
  // characters are the point: this asks whether the password holds anything
  // outside 7-bit ASCII, and the low end of that range is where the answer is.
  // eslint-disable-next-line no-control-regex
  if (/[^\u0000-\u007f]/.test(password)) pool += 100;
  return pool;
}

/**
 * Effective length: how many codepoints carry NEW information.
 *
 * Each codepoint is worth 1, reduced when it is predictable from what came
 * before. The three reductions are the only patterns this model can see:
 *
 *   - a repeat of the immediately preceding character ("aaaa"), worth 0.2
 *   - a step of one from the preceding character ("abcd", "1234"), worth 0.4
 *   - a character that has already appeared anywhere earlier, worth 0.6
 *
 * The weights are judgement, not measurement, and they are chosen to be
 * pessimistic rather than flattering.
 */
function effectiveLength(codepoints: readonly number[]): number {
  const seen = new Set<number>();
  let total = 0;
  for (let i = 0; i < codepoints.length; i++) {
    const current = codepoints[i] as number;
    const previous = i > 0 ? (codepoints[i - 1] as number) : undefined;
    if (previous !== undefined && current === previous) total += 0.2;
    else if (previous !== undefined && Math.abs(current - previous) === 1) total += 0.4;
    else if (seen.has(current)) total += 0.6;
    else total += 1;
    seen.add(current);
  }
  return total;
}

/** Strips leading and trailing digits and punctuation, for the blocklist check. */
function blocklistKey(password: string): string {
  return password
    .toLowerCase()
    .replace(/^[^a-z]+/, "")
    .replace(/[^a-z]+$/, "");
}

function verdictFor(bits: number, acceptable: boolean): PasswordVerdict {
  if (!acceptable) {
    if (bits < 28) return "unusable";
    if (bits < 45) return "weak";
    return "fair";
  }
  if (bits < 80) return "good";
  return "strong";
}

/**
 * Scores a candidate password. Pure, synchronous, and safe to call on every
 * keystroke: it never hashes, never allocates 64 MiB, and never leaves the tab.
 *
 * `email` is optional so the function can be tested on its own, but the signup
 * form always passes it: a password containing the account's own local part is
 * the single most guessable thing a person picks that still looks long.
 */
export function assessPassword(password: string, email = ""): PasswordAssessment {
  if (password.length === 0) {
    return { bits: 0, verdict: "empty", acceptable: false, problems: [], fraction: 0 };
  }

  // NFC, because that is exactly what `deriveMUK` normalises to before it
  // hashes. Scoring the un-normalised string would measure a string that is
  // never the one protecting the key.
  const normalised = password.normalize("NFC");
  const codepoints = Array.from(normalised, (character) => character.codePointAt(0) ?? 0);

  const pool = poolSize(normalised);
  const bits = pool <= 1 ? 0 : effectiveLength(codepoints) * Math.log2(pool);

  const problems: string[] = [];

  if (codepoints.length < MIN_PASSWORD_LENGTH) {
    problems.push(`Use at least ${MIN_PASSWORD_LENGTH} characters. This has ${codepoints.length}.`);
  }
  if (bits < MIN_PASSWORD_BITS) {
    problems.push(
      "Add length or variety. Several unrelated words beat one word with numbers on the end.",
    );
  }
  if (BLOCKLIST.has(blocklistKey(normalised)) || BLOCKLIST.has(normalised.toLowerCase())) {
    problems.push("This is one of the most commonly chosen passwords. Pick something else.");
  }
  if (normalised.toLowerCase().includes("sluice")) {
    problems.push('Do not put "sluice" in the password for your Sluice account.');
  }
  const local = emailLocalPart(email);
  if (local.length >= 3 && normalised.toLowerCase().includes(local)) {
    problems.push("Do not put your email address into your password.");
  }

  const acceptable = problems.length === 0;
  return {
    bits,
    verdict: verdictFor(bits, acceptable),
    acceptable,
    problems,
    fraction: Math.max(0, Math.min(1, bits / (MIN_PASSWORD_BITS * 2))),
  };
}
