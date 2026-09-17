import { utf8 } from "@sluice/crypto";

/**
 * THE ASSOCIATED DATA RULE FOR SECRETS. READ THIS BEFORE WRITING A CLIENT.
 *
 * Every secret ciphertext in Sluice, both the name and the value, is sealed
 * with AES-GCM under associated data of exactly:
 *
 *     utf8("sluice/secret/v1|" + environmentId)
 *
 * where `environmentId` is the Convex id of the environment the row belongs
 * to, spelled exactly as the server returns it.
 *
 * WHY THE VERSION IS IN HERE AND NOT IN A COLUMN. Associated data is
 * authenticated: change one byte of it and decryption fails. A column is not.
 * If the algorithm version sat in `secrets.algorithmVersion`, someone with
 * write access to the database could edit it independently of the ciphertext
 * it describes, and roll a row back to a weaker version while the ciphertext
 * stayed intact and still decrypted. Putting it inside the AAD means the
 * version and the ciphertext cannot be separated: a row whose version is
 * altered simply stops decrypting, loudly, which is the correct failure.
 *
 * WHY THE ENVIRONMENT ID IS IN HERE. Without it, a `dev` row could be copied
 * into `prod` by anyone with write access to the table and would decrypt
 * perfectly, because the project data key is per environment but the AAD would
 * bind nothing. The server's half of this defence is that no mutation accepts
 * an environment id for a row that already has one, so a secret cannot be
 * moved between environments through the API either. Both halves are needed:
 * this one stops the database operator, the other stops the API caller.
 *
 * WHY THE SERVER PUBLISHES IT BUT NEVER USES IT. Nothing on this server seals
 * or opens a secret, and nothing ever will; the string is here so that the web
 * client and the SDK compute it identically from one definition rather than
 * from two hand-copied literals, where a single character of drift produces
 * ciphertext nobody can read and no error until they try.
 *
 * A CLIENT MUST NOT FETCH THIS VALUE FROM THE SERVER AT RUNTIME. It is pinned
 * in client code, the way the org revocation public key is pinned in customer
 * configuration. A server that could choose the associated data could hand a
 * client the AAD of a different environment and undo the binding entirely,
 * which is the one thing this rule exists to prevent.
 */
export const SECRET_AAD_PREFIX = "sluice/secret/v1|";

export function secretAssociatedData(environmentId: string): Uint8Array {
  // The environment id is always present on a real row, so this cannot produce
  // the empty AAD that `seal` rejects. It is checked anyway: an empty string
  // here would bind the ciphertext to the version and to nothing else, and it
  // would look exactly like a correct call.
  if (environmentId.length === 0) {
    throw new Error("environmentId must not be empty");
  }
  return utf8.encode(SECRET_AAD_PREFIX + environmentId);
}
