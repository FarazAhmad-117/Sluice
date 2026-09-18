/**
 * MASKING A SECRET, AND THE ONE THING THE PAGE WILL SHOW INSTEAD.
 *
 * Reveal-on-hover is the obvious interaction for a secret on a landing page and
 * it is the wrong one. A zero-knowledge product whose marketing site prints
 * plaintext on mouseover has argued against itself before the reader reaches
 * the threat model. So this goes the other way: the masked state is the resting
 * state, and revealing resolves the mask into the value's SHA-256 FINGERPRINT,
 * never its value.
 *
 * That is the claim in one gesture. The page proves it is holding a specific
 * secret -- the fingerprint is stable per value and computed here, from the real
 * bytes, by WebCrypto -- without ever being able to show it to you. Change the
 * input by one character and every glyph changes.
 *
 * This is a plain module rather than a component because its consumer is a
 * CANVAS. The labels live on the globe's markers, drawn in the same loop that
 * draws the dots, so there is no DOM node to hang a React component on and no
 * way to drive it at sixty frames a second through state without re-rendering
 * the page on every frame.
 */

/** Characters of SHA-256 hex shown. 16 hex characters is 64 bits: plenty to identify. */
export const FINGERPRINT_CHARS = 16;

/** The resting state, and the same width as a fingerprint so nothing shifts. */
export const MASK = "•".repeat(FINGERPRINT_CHARS);

/** The scramble alphabet is hex, because the destination is hex. */
const HEX = "0123456789abcdef";

/** Milliseconds for a full tumble in either direction. */
export const TUMBLE_MS = 620;

/** Fraction of the run before the first glyph may settle. The rest stagger after. */
const FIRST_SETTLE = 0.4;

/**
 * The digest of `value`, truncated to {@link FINGERPRINT_CHARS}.
 *
 * Returns null rather than throwing when `crypto.subtle` is absent, which
 * happens on a page served over plain HTTP from a non-loopback host. A caller
 * that threw there would take the hero down over a flourish; one that gets null
 * simply never leaves the mask, and the mask is the honest resting state.
 */
export async function fingerprint(value: string): Promise<string | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  try {
    const digest = await subtle.digest("SHA-256", new TextEncoder().encode(value));
    let hex = "";
    for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
    return hex.slice(0, FINGERPRINT_CHARS);
  } catch {
    return null;
  }
}

/**
 * One frame of a tumble from whatever was there toward `target`.
 *
 * `progress` runs 0..1. Each glyph slot settles at its own point in that range,
 * staggered left to right, and shows a random hex character until it does. The
 * output is always exactly {@link FINGERPRINT_CHARS} long, which is what keeps
 * a canvas label from changing width mid-animation.
 *
 * Pure apart from `Math.random`, and deliberately takes progress rather than
 * holding a clock: the caller already has a frame timestamp, and a module with
 * its own timer would animate in a backgrounded tab.
 */
export function tumbleFrame(target: string, progress: number): string {
  if (progress >= 1) return target;
  if (progress <= 0) return target === MASK ? MASK : MASK;

  let out = "";
  for (let i = 0; i < FINGERPRINT_CHARS; i++) {
    const settleAt = FIRST_SETTLE + (1 - FIRST_SETTLE) * (i / (FINGERPRINT_CHARS - 1));
    out += progress >= settleAt ? target[i]! : HEX[(Math.random() * HEX.length) | 0]!;
  }
  return out;
}
