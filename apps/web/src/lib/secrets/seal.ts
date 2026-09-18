import { seal, secretAssociatedData, toHex, utf8 } from "@sluice/crypto";

/**
 * SEALING ONE SECRET, CLIENT SIDE.
 *
 * The mirror of `openSecret` in `decrypt.ts`, and the only place this
 * application turns a name and a value into the four fields
 * `secrets.createSecret` and `secrets.updateSecret` take. The server receives
 * hex and nothing else: it cannot decrypt, it holds no project data key, and
 * nothing in `convex/secrets.ts` computes the associated data these ciphertexts
 * are bound to.
 *
 * ASSOCIATED DATA IS PINNED IN CLIENT CODE. `secretAssociatedData` is the one
 * definition of the rule and is shared with the backend and the SDK; fetching
 * it from a server would let that server hand this client the associated data
 * of a different environment and undo the environment binding entirely, which
 * is the one property that binding exists to provide.
 */

/** The four fields both write mutations take, named exactly as they name them. */
export interface SealedSecretFields {
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly valueCiphertext: string;
  readonly valueNonce: string;
}

export interface SecretPlaintext {
  /** The environment the row will belong to, spelled as the server returns it. */
  readonly environmentId: string;
  readonly name: string;
  readonly value: string;
}

/**
 * Seals a name and a value under the project data key for their environment.
 *
 * `pdk` is 32 raw bytes and is NOT logged, NOT stored and NOT persisted. The
 * name and the value are arguments and are not retained here.
 *
 * ON THE TWO NONCES. `seal` generates its own nonce per call and accepts none,
 * so the two are independent draws from the CSPRNG and a collision is a 2^-96
 * event. The check below is therefore unreachable in practice, and it is here
 * anyway because the consequence is not proportionate to the probability: both
 * fields are sealed under the SAME key, so one nonce used twice leaks the XOR
 * of the two plaintexts and the GHASH authentication key, which is total loss
 * of authentication for that project data key. `convex/secrets.ts` refuses such
 * a row; this refuses to build one, so the failure is a clear error rather than
 * a server-side rejection about a field the user never saw.
 */
export async function sealSecret(
  pdk: Uint8Array,
  secret: SecretPlaintext,
): Promise<SealedSecretFields> {
  // The NAMED field, not a bare string, so that a diff which swaps a project id
  // for an environment id is visible at the call site.
  const aad = secretAssociatedData({ environmentId: secret.environmentId });

  const [name, value] = await Promise.all([
    seal(pdk, utf8.encode(secret.name), aad),
    seal(pdk, utf8.encode(secret.value), aad),
  ]);

  const nameNonce = toHex(name.nonce);
  const valueNonce = toHex(value.nonce);
  if (nameNonce === valueNonce) {
    throw new Error("A nonce may not be reused under one project data key.");
  }

  return {
    nameCiphertext: toHex(name.ciphertext),
    nameNonce,
    valueCiphertext: toHex(value.ciphertext),
    valueNonce,
  };
}
