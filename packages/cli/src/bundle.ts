import { fromHex, pdkAssociatedData, secretAssociatedData, unseal } from "@sluice/crypto";
import type { RevocationNotice, SecretBundle } from "@sluice/sdk";
import type { TokenIdentity } from "./config";

/**
 * TURNING ONE `bundle.getBundle` RESULT INTO SECRETS AND INTO A NOTICE.
 *
 * TWO FUNCTIONS, NOT ONE, AND THAT SPLIT IS THE WHOLE POINT OF THIS FILE.
 *
 * `convex/bundle.ts` answers a revoked token with the signed notice and NO
 * secrets, and it answers a token whose project data key grant has vanished
 * with the notice and no key. Its own comment says why: refusing to answer
 * would also withhold the notice, so a token whose grant disappeared could
 * never be told it was revoked.
 *
 * A single `decryptBundle` throws on both of those, and a shell that called it
 * first and read the notice from the result would reproduce exactly the bug the
 * server went out of its way to avoid: no grant, therefore an exception,
 * therefore no revocation, therefore a stolen token that runs forever. So
 * {@link readRevocation} is PURE, takes no key, cannot throw, and runs before
 * anything is decrypted. {@link decryptSecrets} is allowed to fail as loudly as
 * it likes, because by then the notice is already on its way to the core.
 *
 * A FAILURE HERE IS NEVER A SHUTDOWN AND NEVER A TRANSPORT ERROR. A bundle that
 * will not open is a bundle this process does not install: the last known good
 * secrets stay, the failure is logged by name, and at boot the core's own boot
 * deadline decides. Nothing in this file may reach `exit`.
 *
 * PARTIAL DECRYPTION IS REFUSED. During a re-key the bundle can legitimately
 * carry rows at more than one project data key version while a token holds a
 * wrap for one of them. Installing the subset that happens to open would start
 * an application with some of its configuration missing, which fails later,
 * elsewhere, and looks like the application's bug. Holding the last known good
 * set and waiting for the next push is both safer and, on a reactive
 * subscription, usually a matter of milliseconds.
 */

export interface RawSecretRow {
  readonly secretId: string;
  readonly lineageId: string;
  readonly version: number;
  readonly pdkVersion: number;
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly valueCiphertext: string;
  readonly valueNonce: string;
}

export interface RawRevocationNotice {
  readonly tokenId: string;
  readonly epoch: number;
  readonly revokedAt: number;
  readonly reason: string;
  /** Lowercase hex of the 64 byte Ed25519 signature. */
  readonly signature: string;
}

/** Exactly the shape `convex/bundle.ts` returns. Nothing here reads anything else. */
export interface RawBundle {
  readonly environmentId: string;
  readonly epoch: number;
  readonly pdkVersion?: number | undefined;
  readonly wrappedPDK?: string | undefined;
  readonly pdkNonce?: string | undefined;
  readonly secrets: readonly RawSecretRow[];
  readonly revocationNotice?: RawRevocationNotice | undefined;
}

export interface ParsedRevocation {
  readonly notice: RevocationNotice;
  readonly signature: Uint8Array;
}

export type BundleDecryptCode =
  | "no-grant"
  | "pdk-unwrap"
  | "pdk-version-mismatch"
  | "row-open"
  | "bad-name"
  | "duplicate-name"
  | "malformed";

export class BundleDecryptError extends Error {
  readonly code: BundleDecryptCode;

  constructor(code: BundleDecryptCode, message: string) {
    super(message);
    this.name = "BundleDecryptError";
    this.code = code;
  }
}

const SIGNATURE_HEX = /^[0-9a-f]{128}$/;

/**
 * What a decrypted secret name is allowed to be.
 *
 * The POSIX rule, deliberately, and not a looser one. A name containing `=`
 * splits an environment entry in two. A name containing a NUL truncates it. A
 * name that differs from another only by case is one variable on Windows and
 * two everywhere else, so the same configuration would behave differently on a
 * developer's laptop and in production. Refusing at this boundary makes that a
 * message somebody reads rather than a bug somebody debugs.
 */
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

// `fatal: true` so that a plaintext which is not valid UTF-8 throws instead of
// rendering replacement characters that look like a corrupt secret and are
// really a decoding bug.
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * THE SIGNED NOTICE, LIFTED OFF THE BUNDLE WITHOUT TOUCHING A KEY.
 *
 * Returns `undefined` for anything it cannot read, and NEVER throws. This runs
 * on the path to a shutdown, where an exception is a revocation that failed to
 * take effect, and it runs on data straight off a subscription that anyone with
 * write access to the database can shape.
 *
 * It VALIDATES NOTHING beyond the shape needed to hand the core a well-typed
 * event, and it must not. Authenticity is `SluiceCore`'s decision, made by
 * `verifyRevocation` against the organisation key pinned in this customer's own
 * configuration. A transport that pre-screened notices would be a transport
 * with an opinion about the kill switch, and every opinion here is a way to
 * drop a genuine one.
 *
 * The four signed fields are passed through BYTE FOR BYTE. Trimming, lowering
 * or sanitising `reason` here would change the bytes the signature covers and
 * every notice in the product would stop verifying. Sanitisation happens at the
 * render site, inside the SDK.
 */
export function readRevocation(raw: RawBundle | null | undefined): ParsedRevocation | undefined {
  const notice = (raw as { revocationNotice?: unknown } | null | undefined)?.revocationNotice as
    | Partial<RawRevocationNotice>
    | null
    | undefined;
  if (typeof notice !== "object" || notice === null) return undefined;
  if (typeof notice.tokenId !== "string") return undefined;
  if (typeof notice.epoch !== "number" || !Number.isSafeInteger(notice.epoch)) return undefined;
  if (typeof notice.revokedAt !== "number" || !Number.isSafeInteger(notice.revokedAt)) {
    return undefined;
  }
  if (typeof notice.reason !== "string") return undefined;
  if (typeof notice.signature !== "string" || !SIGNATURE_HEX.test(notice.signature)) {
    return undefined;
  }
  let signature: Uint8Array;
  try {
    signature = fromHex(notice.signature);
  } catch {
    return undefined;
  }
  return {
    notice: {
      tokenId: notice.tokenId,
      epoch: notice.epoch,
      revokedAt: notice.revokedAt,
      reason: notice.reason,
    },
    signature,
  };
}

/**
 * Opens every row in the bundle, or opens none of them.
 *
 * NO MESSAGE THIS FUNCTION PRODUCES CONTAINS A NAME, A VALUE, A KEY OR A
 * CIPHERTEXT. An unopenable row is named by its `lineageId`, which is a server
 * side identifier an operator can paste into the dashboard and which reveals
 * nothing about the secret. The AEAD failures deliberately carry no detail
 * about which input was wrong, matching `@sluice/crypto`: inventing a
 * distinction between a wrong key, a tampered ciphertext and wrong associated
 * data would turn this into a decryption oracle.
 */
export async function decryptSecrets(
  identity: TokenIdentity,
  raw: RawBundle,
): Promise<SecretBundle> {
  if (
    typeof raw !== "object" ||
    raw === null ||
    typeof raw.environmentId !== "string" ||
    typeof raw.epoch !== "number" ||
    !Number.isSafeInteger(raw.epoch) ||
    raw.epoch < 0 ||
    !Array.isArray(raw.secrets)
  ) {
    throw new BundleDecryptError(
      "malformed",
      "The Sluice bundle did not have the shape this build understands.",
    );
  }

  if (
    typeof raw.wrappedPDK !== "string" ||
    typeof raw.pdkNonce !== "string" ||
    typeof raw.pdkVersion !== "number"
  ) {
    // The token authenticated and the environment exists; there is simply no
    // `pdkGrants` row for it. Named separately from every other failure because
    // the fix is an administrative one, in the dashboard, and no amount of
    // retrying changes it.
    throw new BundleDecryptError(
      "no-grant",
      "This service token has no project data key grant on its environment, so it cannot " +
        "open any secret. Issue the token a grant in the Sluice dashboard. Sluice is not " +
        "exiting: a missing grant is not a revocation.",
    );
  }

  let pdk: Uint8Array;
  try {
    pdk = await unseal(
      identity.unwrapKey,
      { ciphertext: fromHex(raw.wrappedPDK), nonce: fromHex(raw.pdkNonce) },
      // Pinned in client code and NEVER taken from the server. A deployment
      // that could choose these bytes could hand this process the associated
      // data of a different grant.
      pdkAssociatedData({ granteeType: "token", granteeId: identity.tokenIdHashHex }),
    );
  } catch {
    throw new BundleDecryptError(
      "pdk-unwrap",
      "The project data key in this bundle could not be opened with this token's unwrap key. " +
        "The bundle is not authentic for this token, or the grant was wrapped to a different " +
        "grantee.",
    );
  }

  const associatedData = secretAssociatedData({ environmentId: raw.environmentId });
  const secrets: Record<string, string> = {};
  try {
    for (const row of raw.secrets) {
      if (row.pdkVersion !== raw.pdkVersion) {
        // Expected during a re-key and only then. The next push carries the
        // matching wrap, so holding the last known good set costs milliseconds.
        throw new BundleDecryptError(
          "pdk-version-mismatch",
          `A secret in this bundle is sealed under project data key version ${row.pdkVersion} ` +
            `while this token holds version ${raw.pdkVersion}. This is what a re-key looks ` +
            "like from here. Sluice is holding the last known good secrets and waiting for " +
            "the next update.",
        );
      }

      const name = await open(pdk, associatedData, row, row.nameCiphertext, row.nameNonce);
      const value = await open(pdk, associatedData, row, row.valueCiphertext, row.valueNonce);

      if (!ENV_NAME.test(name)) {
        throw new BundleDecryptError(
          "bad-name",
          `The secret with lineage id ${safeId(row.lineageId)} has a name that cannot be an ` +
            "environment variable. Names must start with a letter or an underscore and " +
            "contain only letters, digits and underscores. The name is not printed here.",
        );
      }
      if (Object.prototype.hasOwnProperty.call(secrets, name)) {
        throw new BundleDecryptError(
          "duplicate-name",
          `Two secrets in this environment decrypt to the same name, one of them with ` +
            `lineage id ${safeId(row.lineageId)}. Sluice will not choose between them. ` +
            "The name is not printed here.",
        );
      }
      secrets[name] = value;
    }
  } finally {
    // The project data key is zeroed as soon as the last row is open. It stays
    // recoverable from `identity.unwrapKey` and the wrap, so this is hygiene
    // rather than a control: it shortens the window in which a heap dump or a
    // core file contains the key that opens every secret in the environment.
    pdk.fill(0);
  }

  return { epoch: raw.epoch, secrets };
}

async function open(
  pdk: Uint8Array,
  associatedData: Uint8Array,
  row: RawSecretRow,
  ciphertext: string,
  nonce: string,
): Promise<string> {
  try {
    const plaintext = await unseal(
      pdk,
      { ciphertext: fromHex(ciphertext), nonce: fromHex(nonce) },
      associatedData,
    );
    return decoder.decode(plaintext);
  } catch {
    // `fromHex` and `decode` are inside the `try` deliberately. A row that is
    // not hex, and a plaintext that is not UTF-8, are both rows this token did
    // not write, and both must fail as "not authentic" rather than as a parse
    // error carrying the offending bytes in its message.
    throw new BundleDecryptError(
      "row-open",
      `The secret with lineage id ${safeId(row.lineageId)} could not be opened with this ` +
        "environment's project data key. Sluice is holding the last known good secrets.",
    );
  }
}

/**
 * A lineage id, or a placeholder.
 *
 * The id is a server side identifier and is safe to show, but it arrives from
 * the same untrusted row as everything else, so a value that is not a short
 * opaque string never reaches a terminal.
 */
function safeId(value: unknown): string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value) ? value : "unknown";
}
