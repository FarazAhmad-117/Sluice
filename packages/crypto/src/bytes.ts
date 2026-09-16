export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Not side-channel safe: this throws on the first malformed pair, so the time
 * taken leaks the position of invalid input. Only decode values that are public
 * (token ids, public keys) or supplied by the token holder themselves.
 */
export function fromHex(hex: string): Uint8Array {
  // Both messages name the field and the reason, like every other guard in this
  // package, and NEITHER echoes the input. A caller may hand this a string that
  // is partly secret, and an error message travels into logs, error reporters
  // and support tickets. The position is safe to report -- this function throws
  // on the first bad pair, so its timing already leaks exactly that -- while
  // the content is not.
  if (hex.length % 2 !== 0) {
    throw new Error(`hex must have an even number of characters, got ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = hex.slice(i * 2, i * 2 + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
      throw new Error(`hex must contain only [0-9a-fA-F]; invalid pair at index ${i}`);
    }
    out[i] = Number.parseInt(pair, 16);
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Compares contents in time independent of where they differ, so an attacker
 * cannot binary-search a secret byte by byte.
 *
 * Length is NOT hidden: a length mismatch returns early. Callers must not rely
 * on this to conceal the length of secret material. In practice every caller
 * compares fixed-width values (32-byte keys, 64-byte signatures) where length
 * is public anyway.
 *
 * EMPTY INPUT THROWS. It used to return `true` for two empty buffers, which is
 * arithmetically defensible and operationally a trap: an SDK comparing two
 * values it failed to read -- a missing environment variable, an absent header,
 * a truncated database row -- got `true` and treated that as a successful
 * authentication. No legitimate call compares nothing to nothing, so this is a
 * caller bug and it says so instead of answering it. Either side being empty
 * throws, because comparing a real secret against a value that failed to load
 * is the same bug.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length === 0 || b.length === 0) {
    throw new Error("constantTimeEqual inputs must not be empty");
  }
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** WebCrypto refuses a single getRandomValues call larger than this. */
const MAX_RANDOM_BYTES = 65536;

export function randomBytes(length: number): Uint8Array {
  // Validate up front: `new Uint8Array(1.5)` silently truncates to length 1,
  // which would hand back fewer random bytes than the caller asked for, and
  // an oversized request throws an opaque DOMException from the platform.
  if (!Number.isInteger(length) || length < 0) {
    throw new Error("length must be a non-negative integer");
  }
  if (length > MAX_RANDOM_BYTES) {
    throw new Error(`length must be at most ${MAX_RANDOM_BYTES} bytes`);
  }
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export const utf8 = {
  encode: (s: string) => new TextEncoder().encode(s),
  // fatal: true on purpose. Decrypted plaintext is attacker-influenceable, and
  // the lenient default substitutes U+FFFD for invalid sequences, turning a
  // corruption signal into a plausible-looking string. AEAD authentication
  // catches most of this earlier; this is defence in depth and costs nothing.
  decode: (b: Uint8Array) => new TextDecoder("utf-8", { fatal: true }).decode(b),
};
