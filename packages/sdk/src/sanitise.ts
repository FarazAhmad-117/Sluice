/**
 * RENDER-SITE SANITISATION FOR ATTACKER-INFLUENCED TEXT.
 *
 * `RevocationNotice.reason` is signed, so it is authentic -- but authentic text
 * written by a compromised or malicious admin client is still hostile text, and
 * it lands on the one log line an operator reads during an incident.
 * `@sluice/crypto` validates that reason and deliberately does NOT sanitise it,
 * because sanitising would change the bytes the signature covers and every
 * notice would then fail to verify. So the cleaning has to happen here, at the
 * render site, and the signed bytes stay untouched on the decision object.
 *
 * WHAT EACH CLASS OF CHARACTER ACTUALLY DOES TO A TERMINAL:
 *
 * - `` (ESC) begins an ANSI sequence. `ESC [ 2 J` clears the operator's
 *   screen, wiping the context they were reading. `ESC ] 8 ; ;` opens an OSC 8
 *   hyperlink, so the "reason" renders as a clickable link to anywhere.
 * - `\r` returns the cursor to column zero. `"key leaked\rall fine"` prints as
 *   `all fine` and the real reason never appears on screen at all.
 * - `\n` forges whole log lines, so a reason can fabricate an `INFO all clear`
 *   entry directly beneath the shutdown record it is part of.
 * - C1 (U+0080-U+009F) are the single-byte forms of the same escapes; some
 *   terminals still honour them, and they survive naive ``-only filters.
 * - U+202E RIGHT-TO-LEFT OVERRIDE and its relatives reverse visual order, so
 *   the rendered line reads as something other than its own bytes. U+2066-2069
 *   (isolates) and U+200E/U+200F (marks) do the same job more quietly.
 * - Lone surrogates are not valid text at all and render unpredictably.
 *
 * WHY U+FFFD RATHER THAN DELETION. Deleting a control character hides the fact
 * that the reason was tampered with; the sanitised line would look innocent.
 * Substituting the replacement character preserves the length and leaves a
 * visible mark, so an operator can see that someone put something there.
 *
 * WHY THERE IS A LENGTH CAP HERE AS WELL AS IN CRYPTO. `@sluice/crypto` caps
 * `reason` at 512 UTF-16 code units, which bounds the wire cost. This cap is
 * about the log line: 512 characters of adversary-chosen text scrolls the
 * surrounding context off an 80x24 terminal, which is a cheaper way to hide the
 * real message than any escape sequence.
 *
 * This function never throws. It runs on the shutdown path, where an exception
 * would mean a revocation that failed to take effect.
 */

/** Total output budget in UTF-16 code units, including the ellipsis marker. */
const MAX_RENDERED_LENGTH = 256;

const ELLIPSIS = "…";
const REPLACEMENT = "�";

/**
 * True for a code point that must never reach a log line.
 *
 * Written against code points rather than a regular expression on purpose: a
 * regex over UTF-16 code units cannot distinguish a lone surrogate from half of
 * a legitimate pair, and the emoji case in the tests depends on that
 * distinction.
 */
function isHostile(codePoint: number): boolean {
  return (
    // C0 controls and DEL.
    codePoint <= 0x1f ||
    codePoint === 0x7f ||
    // C1 controls.
    (codePoint >= 0x80 && codePoint <= 0x9f) ||
    // LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK.
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    // LRE, RLE, PDF, LRO, RLO.
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    // LRI, RLI, FSI, PDI.
    (codePoint >= 0x2066 && codePoint <= 0x2069) ||
    // Unpaired surrogate. `for...of` yields these as single characters.
    (codePoint >= 0xd800 && codePoint <= 0xdfff)
  );
}

/**
 * Renders arbitrary text safe for a single log line.
 *
 * Declared as taking a `string` but guarded at runtime anyway: the value
 * arrives from a database row via a subscription, and a TypeScript type is not
 * a runtime guarantee. A non-string gets a fixed placeholder rather than
 * `String(value)`, because `String()` on a hostile object runs its `toString`.
 */
export function sanitiseForLog(reason: string): string {
  if (typeof reason !== "string") return "<non-string reason>";

  let out = "";
  for (const character of reason) {
    const codePoint = character.codePointAt(0);
    const safe = codePoint === undefined || isHostile(codePoint) ? REPLACEMENT : character;
    if (out.length + safe.length > MAX_RENDERED_LENGTH - ELLIPSIS.length) {
      return out + ELLIPSIS;
    }
    out += safe;
  }
  return out;
}
