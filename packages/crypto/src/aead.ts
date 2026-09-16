import { randomBytes } from "./bytes.js";

/**
 * AES-256-GCM sealed data.
 *
 * There is deliberately no `tag` field. WebCrypto appends the 16-byte GCM
 * authentication tag to the ciphertext rather than returning it separately, so
 * `ciphertext` is always `plaintext.length + 16` bytes and the tag travels with
 * it. Splitting them apart would only create a way to store them inconsistently.
 *
 * There is deliberately no algorithm or format version field either, and none
 * should be added. This is a crypto primitive, not a storage format; folding a
 * storage concern in here makes the auditable core harder to review. The storage
 * layer binds the algorithm version into the associated data alongside the
 * environment id instead, which makes the version authenticated rather than a
 * mutable database column an attacker could edit independently of the ciphertext.
 */
export interface SealedBox {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

const KEY_BYTES = 32;

/**
 * 96 bits, the size GCM is designed around.
 *
 * Because nonces are random rather than counted, the birthday bound applies:
 * roughly 2^32 messages under a single key before collision probability reaches
 * about 2^-32, and a repeated nonce under one key is catastrophic. No caller
 * approaches that here, since keys are per environment. A key that ever seals a
 * high-volume stream needs rotation, not a larger nonce.
 */
const NONCE_BYTES = 12;

/**
 * Re-views bytes as `ArrayBuffer`-backed for the WebCrypto boundary.
 *
 * TypeScript 5.7 made `Uint8Array` generic over its backing buffer, so a plain
 * `Uint8Array` is `Uint8Array<ArrayBufferLike>` and no longer satisfies DOM's
 * `BufferSource`, which excludes `SharedArrayBuffer`. Sluice never puts key
 * material in shared memory, so the check below is effectively always true; the
 * copy exists so the cast is never a lie, because a shared-backed view would be
 * rejected by the platform at runtime anyway.
 */
function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer) return bytes as Uint8Array<ArrayBuffer>;
  return new Uint8Array(bytes);
}

async function importKey(key: Uint8Array): Promise<CryptoKey> {
  // Checked explicitly rather than left to WebCrypto: AES-GCM also accepts 16
  // and 24 byte keys, so a short key would silently import as AES-128 instead
  // of failing. The message reports only the length the caller already knows.
  if (key.length !== KEY_BYTES) {
    throw new Error(`key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }
  return crypto.subtle.importKey("raw", asBufferSource(key), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Rejects a present-but-empty `associatedData`.
 *
 * GCM treats empty AAD and absent AAD as the same input, so an empty array binds
 * nothing at all. A caller deriving AAD from an environment id that turned out to
 * be an empty string would get an unbound ciphertext and no error -- silently
 * losing the one property the parameter exists to provide. Fail loudly instead.
 */
function checkAssociatedData(associatedData: Uint8Array | undefined): void {
  if (associatedData && associatedData.length === 0) {
    throw new Error("associatedData must not be empty; omit it instead");
  }
}

/**
 * Encrypts `plaintext` under `key`, optionally binding it to `associatedData`.
 *
 * `associatedData` is authenticated but not encrypted. Binding a ciphertext to
 * something like an environment id means a `dev` blob cannot be replayed into
 * `prod`, even by someone with write access to the database.
 *
 * The nonce is generated fresh per call from the CSPRNG. Nonce reuse under one
 * key is catastrophic for GCM -- it leaks the XOR of the two plaintexts and the
 * GHASH authentication key -- so nothing in this module may ever accept a
 * caller-supplied nonce.
 */
export async function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): Promise<SealedBox> {
  checkAssociatedData(associatedData);
  const cryptoKey = await importKey(key);
  const nonce = randomBytes(NONCE_BYTES);
  // Built conditionally rather than passing `additionalData: undefined`:
  // exactOptionalPropertyTypes rejects an explicit undefined for an optional
  // property.
  const params: AesGcmParams = { name: "AES-GCM", iv: asBufferSource(nonce), tagLength: 128 };
  if (associatedData) params.additionalData = asBufferSource(associatedData);
  const ciphertext = await crypto.subtle.encrypt(params, cryptoKey, asBufferSource(plaintext));
  return { ciphertext: new Uint8Array(ciphertext), nonce };
}

/**
 * Decrypts and authenticates a {@link SealedBox}.
 *
 * Rejects if the key, nonce, ciphertext, tag or associated data do not all
 * match what was sealed. The rejection carries no detail about which of them
 * failed -- WebCrypto reports a bare `OperationError` -- so it cannot be used
 * as a decryption oracle. Callers must treat any rejection as "this data is not
 * authentic" and must never fall back to using the undecrypted bytes.
 */
export async function unseal(
  key: Uint8Array,
  box: SealedBox,
  associatedData?: Uint8Array,
): Promise<Uint8Array> {
  checkAssociatedData(associatedData);
  // A SealedBox is reconstituted from an untrusted database, so the module
  // enforces its own advertised invariant rather than trusting the row. GCM
  // accepts arbitrary IV lengths -- it derives J0 through GHASH when the IV is
  // not 96 bits -- so without this check a tampered row carrying a longer nonce
  // would decrypt perfectly happily.
  if (box.nonce.length !== NONCE_BYTES) {
    throw new Error(`nonce must be ${NONCE_BYTES} bytes, got ${box.nonce.length}`);
  }
  const cryptoKey = await importKey(key);
  const params: AesGcmParams = { name: "AES-GCM", iv: asBufferSource(box.nonce), tagLength: 128 };
  if (associatedData) params.additionalData = asBufferSource(associatedData);
  const plaintext = await crypto.subtle.decrypt(params, cryptoKey, asBufferSource(box.ciphertext));
  return new Uint8Array(plaintext);
}
