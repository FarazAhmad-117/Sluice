import { newId, seal, secretAssociatedData, toHex, utf8 } from "@sluice/crypto";
import type { SecretField } from "@sluice/crypto";
import type { EnvironmentKey } from "./pdk";

/**
 * SEALING ONE SECRET, CLIENT SIDE.
 *
 * The mirror of `openSecret` in `decrypt.ts`, and the only place this
 * application turns a name and a value into the four ciphertext fields
 * `secrets.createSecret` and `secrets.updateSecret` take. The server receives
 * hex and nothing else: it cannot decrypt, it holds no project data key, and
 * nothing in `convex/secrets.ts` computes the associated data these ciphertexts
 * are bound to.
 *
 * EVERY CIPHERTEXT IS SEALED FOR ONE EXACT SLOT. The associated data names
 * four things, through `secretAssociatedData` in `@sluice/crypto`:
 *
 *   environmentUid  the environment's permanent `env_` id. Taken from the
 *                   {@link EnvironmentKey}, which carries the uid its grant was
 *                   verified under, and NEVER from a column on a secret row: a
 *                   row's columns are what somebody with write access edits.
 *   secretUid       the secret's permanent `sec_` id, minted HERE with
 *                   `newId("sec")` for a new secret and read off the row being
 *                   replaced for an update. A ciphertext moved into another
 *                   secret's row does not open there.
 *   version         1 for a new secret, the replaced row's version plus one
 *                   for an update. An old version served as current does not
 *                   open as current.
 *   field           `"name"` for the name and `"value"` for the value. The two
 *                   halves of one row have DIFFERENT associated data, so a
 *                   value swapped into the name slot (where the dashboard shows
 *                   it in the clear, unasked) does not open there.
 *
 * The server stores `secretUid` and `version` exactly as this client states
 * them, and refuses a create that is not version 1 or an update that is not
 * exactly the current version plus one. That refusal is the compare-and-set
 * that stops two editors from both writing "version 3"; the binding here is
 * what makes a stored row that disagrees with its own columns unopenable.
 *
 * ASSOCIATED DATA IS PINNED IN CLIENT CODE. `secretAssociatedData` is the one
 * definition of the rule and is shared with the backend and the SDK; fetching
 * it from a server would let that server hand this client the associated data
 * of a different slot and undo the binding entirely.
 */

/** The four ciphertext fields both write mutations take, named exactly as they name them. */
export interface SealedSecretFields {
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly valueCiphertext: string;
  readonly valueNonce: string;
}

/**
 * Which secret, and which version of it, a pair of ciphertexts is sealed for.
 *
 * The environment is not here on purpose: it comes with the key. See the
 * header and {@link EnvironmentKey}.
 */
export interface SecretSlot {
  /** The secret's permanent `sec_` id, shared by every version of it. */
  readonly secretUid: string;
  /** The version these ciphertexts ARE, not the one they replace. */
  readonly version: number;
}

export interface SecretPlaintext extends SecretSlot {
  readonly name: string;
  readonly value: string;
}

/** A brand-new secret's slot: a fresh permanent id, at the only version a new secret has. */
export function newSecretSlot(): SecretSlot {
  return { secretUid: newId("sec"), version: 1 };
}

/**
 * The slot for the version that will replace `current`.
 *
 * `current` must be the row being edited exactly as the server returned it.
 * Its `secretUid` is kept, because every version of one secret shares it, and
 * the version is one more than the row's own, because that is the only value
 * `updateSecret` accepts. If somebody else has written in the meantime, the
 * server refuses this write with a message saying so; nothing here guesses.
 */
export function nextSecretSlot(current: SecretSlot): SecretSlot {
  return { secretUid: current.secretUid, version: current.version + 1 };
}

/**
 * Seals a name and a value for one slot of the environment `key` belongs to.
 *
 * `key.pdk` is 32 raw bytes and is NOT logged, NOT stored and NOT persisted.
 * The name and the value are arguments and are not retained here.
 *
 * ON THE TWO NONCES. `seal` generates its own nonce per call and accepts none,
 * so the two are independent draws from the CSPRNG and a collision is a 2^-96
 * event. The check below is therefore unreachable in practice, and it is here
 * anyway because the consequence is not proportionate to the probability: both
 * fields are sealed under the SAME key, so one nonce used twice leaks the XOR
 * of the two plaintexts and the GHASH authentication key, which is total loss
 * of authentication for that project data key. Different associated data for
 * the two fields does not change that: a nonce reused under one key is broken
 * whatever the associated data is. `convex/secrets.ts` refuses such a row;
 * this refuses to build one, so the failure is a clear error rather than a
 * server-side rejection about a field the user never saw.
 */
export async function sealSecret(
  key: EnvironmentKey,
  secret: SecretPlaintext,
): Promise<SealedSecretFields> {
  // Built outside any `try`, so a malformed uid or version is reported as the
  // argument error it is. The NAMED fields, not a joined string, so a diff
  // that swaps one id for another is visible at the call.
  const bind = (field: SecretField) =>
    secretAssociatedData({
      environmentUid: key.environmentUid,
      secretUid: secret.secretUid,
      version: secret.version,
      field,
    });
  const nameAad = bind("name");
  const valueAad = bind("value");

  const [name, value] = await Promise.all([
    seal(key.pdk, utf8.encode(secret.name), nameAad),
    seal(key.pdk, utf8.encode(secret.value), valueAad),
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
