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
  if (hex.length % 2 !== 0) throw new Error("hex string must have even length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = hex.slice(i * 2, i * 2 + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) throw new Error("invalid hex string");
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
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
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
