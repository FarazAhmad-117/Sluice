import {
  assertId,
  fromHex,
  pdkAssociatedData,
  secretAssociatedData,
  unseal,
} from "@sluice/crypto";
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

/**
 * One secret, as `convex/bundle.ts` returns it.
 *
 * `secretUid` and `version` are what this row's two ciphertexts are BOUND to,
 * together with the bundle's `environmentUid` and the field each ciphertext
 * fills. The name is sealed under field `"name"` and the value under field
 * `"value"`, so a row's two halves have different associated data. All four
 * arrive as plain columns that anyone with database write access can edit,
 * and that is the point: none of them is trusted, every one is re-derived into
 * the associated data, and a row whose ciphertext was sealed for any other
 * slot fails to open. A server cannot swap the values of two secrets (the
 * `secretUid` differs), move a name into a value (the field differs), or put a
 * superseded value into the current version's row (the `version` differs).
 *
 * `secretUid` is the secret's PERMANENT `sec_` id, minted by the client that
 * created the secret and shared by every version of it. It replaced the Convex
 * document id `secretId`, for the same reason `environmentUid` replaced
 * `environmentId`: a document id is re-minted when an org moves cells, and
 * ciphertext bound to it would stop opening on the day of the move. This file
 * never reads a `secretId` value; its mere presence on a row with no
 * `secretUid` is how an older backend is recognised and named.
 *
 * `lineageId` is DISPLAY ONLY AND OPTIONAL. It names a row in an error message
 * so an operator can find it in the dashboard, and is bound into nothing. It is
 * optional because the backend may stop sending it now that `secretUid` names a
 * secret permanently; {@link rowLabel} falls back to the `secretUid`.
 */
export interface RawSecretRow {
  readonly secretUid: string;
  readonly lineageId?: string | undefined;
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
  /**
   * The environment's PERMANENT id, `env_` plus 32 lowercase hex, minted by the
   * client that created the environment. Both associated data rules bind it.
   *
   * Never the Convex document id. That id is local to one deployment and is
   * re-minted when an org moves cells, so ciphertext bound to it would stop
   * opening on the day of the move, and no server could repair it because no
   * server holds a key. A bundle that still carries only `environmentId` is a
   * bundle from a backend this build does not speak to, and is refused as
   * malformed rather than guessed at.
   */
  readonly environmentUid: string;
  readonly epoch: number;
  /**
   * The generation of the project data key this token's grant wraps. Bound
   * into the grant's associated data, so an old wrap served under a newer
   * version number (a rotation rolled back by the server) fails to unwrap.
   * Absent, together with `wrappedPDK` and `pdkNonce`, when there is no grant.
   */
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

/** The one message for a bundle shaped by a backend that predates this CLI. */
const OLDER_BACKEND =
  "This bundle comes from a Sluice backend older than this CLI; deploy the backend " +
  "and the CLI together. Sluice is keeping any last known good secrets.";

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
 * CIPHERTEXT. An unopenable row is named by {@link rowLabel}: its `lineageId`,
 * or failing that its `secretUid`, both identifiers an operator can paste into
 * the dashboard and neither of which reveals anything about the secret. The AEAD failures deliberately carry no detail
 * about which input was wrong, matching `@sluice/crypto`: inventing a
 * distinction between a wrong key, a tampered ciphertext and wrong associated
 * data would turn this into a decryption oracle.
 */
export async function decryptSecrets(
  identity: TokenIdentity,
  raw: RawBundle,
): Promise<SecretBundle> {
  if (typeof raw === "object" && raw !== null && raw.environmentUid === undefined) {
    // VERSION SKEW, NAMED AS SUCH. A bundle with no `environmentUid` but with
    // the v1 `environmentId` field is not hostile, it is a backend that has not
    // been deployed alongside this CLI. It is still refused, as `malformed`,
    // because the v1 id cannot be bound into the v2 associated data and
    // guessing would decrypt nothing. But the operator is told the fix rather
    // than handed a shape error. The value of the old field is never echoed: it
    // arrived from the same untrusted row as everything else.
    if (Object.prototype.hasOwnProperty.call(raw, "environmentId")) {
      throw new BundleDecryptError("malformed", OLDER_BACKEND);
    }
  }

  if (
    typeof raw !== "object" ||
    raw === null ||
    typeof raw.environmentUid !== "string" ||
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

  // THE SAME VERSION SKEW, ONE LEVEL DOWN. A backend that already sends
  // `environmentUid` but whose rows still carry only the Convex document id
  // `secretId`, with no permanent `secretUid`, is a backend from between the
  // two changes. Its rows cannot be bound and would fail as `row-open`, which
  // reads like tampering; this names the real cause instead. Nothing from the
  // old field is echoed.
  if (
    raw.secrets.some(
      (row: unknown) =>
        typeof row === "object" &&
        row !== null &&
        (row as { secretUid?: unknown }).secretUid === undefined &&
        Object.prototype.hasOwnProperty.call(row, "secretId"),
    )
  ) {
    throw new BundleDecryptError("malformed", OLDER_BACKEND);
  }

  // EVERY ASSOCIATED DATA VALUE IS BUILT INSIDE A GUARD.
  //
  // `assertId`, `pdkAssociatedData` and `secretAssociatedData` validate what
  // they are given and THROW a plain `Error` when an id is not well formed or a
  // version is not a positive whole number. Those values come straight off a
  // subscription that anyone with database write access can shape, so a
  // malformed one is an ordinary hostile input, not a bug, and it must fail
  // exactly like every other bundle that will not open: as a named
  // `BundleDecryptError` that the shell logs by code while keeping any last
  // known good set. Letting the crypto layer's throw out unconverted would make
  // a malformed bundle an anonymous exception on the same code path that, one
  // bundle later, has to deliver a shutdown. A malformed bundle must never
  // become an exception on the path to a shutdown.
  //
  // The guards are this narrow on purpose. They wrap only the pure functions
  // whose throw is a statement about their input; they do not wrap `unseal`,
  // which has its own named failures below. No message repeats the offending
  // value, for the same reason `safeId` exists.
  //
  // SEPARATE GUARDS, NOT ONE, so each message blames only what it can know is
  // wrong. The environment id is checked first and on its own, with the crypto
  // package's own validator, so its failure is that id's fault and says so.
  // The secret associated data is no longer built here: it now names the
  // secret, its version and the field, so there is one pair per row, built in
  // the row loop under that row's failure code.
  //
  // The environment check runs BEFORE the grant check, so a bundle whose
  // environment id is unusable is reported as malformed even when it also lacks
  // a grant. The bad id is the root cause: reporting `no-grant` instead would
  // send an operator to the dashboard to issue a grant that could never have
  // helped.
  try {
    assertId("env", "environmentUid", raw.environmentUid);
  } catch {
    throw new BundleDecryptError(
      "malformed",
      "The Sluice bundle named its environment with an id that is not a permanent " +
        "environment id, so none of its secrets can be bound to it. Sluice is keeping any " +
        "last known good secrets.",
    );
  }

  // A MISSING GRANT IS ALL THREE FIELDS ABSENT, AND ONLY THEN. That is exactly
  // what `convex/bundle.ts` sends when there is no `pdkGrants` row. Any other
  // combination, one or two of the three present, or a wrap or nonce that is
  // not a string, is not a missing grant but a malformed one, and is reported
  // as `malformed` below. Calling it `no-grant` would send an operator to the
  // dashboard to issue a grant the token already has. A `pdkVersion` that is
  // present but is not a positive whole number (`"1"`, `null`, `1.5`) is
  // likewise malformed, and is caught by the crypto layer's own version rule
  // in the guard after this one.
  if (raw.wrappedPDK === undefined && raw.pdkNonce === undefined && raw.pdkVersion === undefined) {
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

  if (
    typeof raw.wrappedPDK !== "string" ||
    typeof raw.pdkNonce !== "string" ||
    raw.pdkVersion === undefined
  ) {
    // Part of a grant. No value is echoed: all three came off the same
    // untrusted bundle.
    throw new BundleDecryptError(
      "malformed",
      "The Sluice bundle carried an incomplete project data key grant, so no secret can be " +
        "opened. Sluice is keeping any last known good secrets.",
    );
  }

  // `pdkVersion` is bound into the grant's associated data, so a wrap of the
  // OLD key served under the new version number (a rotation rolled back by
  // the server, which would have this process seal new secrets under a key a
  // removed member still holds) fails to unwrap below. It is the one field
  // here that is both server supplied and validated by the crypto layer, so a
  // malformed one throws from `pdkAssociatedData` and is converted here.
  //
  // ONE FIXED MESSAGE, deliberately neutral about which input was wrong. By
  // now the environment id has passed the same check above, so the candidates
  // are the bundle's `pdkVersion` and this token's own `tokenIdHashHex`, which
  // is computed locally. The first is far likelier, but a local bug must never
  // be reported as certainly the server's fault, and the value is never echoed.
  const pdkVersion = raw.pdkVersion;
  let pdkAAD: Uint8Array;
  try {
    // Pinned in client code and NEVER taken from the server beyond the id and
    // the version the bundle names. A deployment that could choose these bytes
    // could hand this process the associated data of a different grant.
    pdkAAD = pdkAssociatedData({
      environmentUid: raw.environmentUid,
      pdkVersion,
      granteeType: "token",
      granteeId: identity.tokenIdHashHex,
    });
  } catch {
    throw new BundleDecryptError(
      "malformed",
      "Sluice could not build the associated data this bundle's key grant is bound to: " +
        "the grant's key version is not a positive whole number, or this token's identity " +
        "is not in the form it must be. Sluice is keeping any last known good secrets.",
    );
  }

  let pdk: Uint8Array;
  try {
    pdk = await unseal(
      identity.unwrapKey,
      { ciphertext: fromHex(raw.wrappedPDK), nonce: fromHex(raw.pdkNonce) },
      // Bound to the environment and the key version as well as to this token
      // since v2, so a grant copied into another environment's row, or an old
      // grant relabelled as the current version, fails HERE, at the first
      // unwrap.
      pdkAAD,
    );
  } catch {
    throw new BundleDecryptError(
      "pdk-unwrap",
      "The project data key in this bundle could not be opened with this token's unwrap key. " +
        "The bundle is not authentic for this token, or the grant was wrapped to a different " +
        "grantee, for a different environment or for a different key version.",
    );
  }

  const secrets: Record<string, string> = {};
  try {
    for (const row of raw.secrets as readonly unknown[] as readonly RawSecretRow[]) {
      if (typeof row !== "object" || row === null) {
        // Not a row at all. Reading a field off it would be a raw TypeError on
        // the path to a shutdown, so it fails as the unreadable row it is.
        throw unreadableRow(row);
      }

      // CHECKED BEFORE IT IS COMPARED, because the comparison's message prints
      // it. A row's `pdkVersion` is an untrusted column, and anything that is
      // not a positive whole number (a 10,000 character string, an escape
      // sequence, `null`) would otherwise be interpolated into a log line. It
      // is not a re-key either, so it fails as the unreadable row it is. The
      // bundle's own `pdkVersion` needs no such check here: the grant guard
      // above has already held it to the crypto layer's version rule.
      if (!Number.isSafeInteger(row.pdkVersion) || row.pdkVersion < 1) {
        throw unreadableRow(row);
      }

      if (row.pdkVersion !== raw.pdkVersion) {
        // Expected during a re-key and only then. The next push carries the
        // matching wrap, so keeping any last known good set costs milliseconds.
        throw new BundleDecryptError(
          "pdk-version-mismatch",
          `A secret in this bundle is sealed under project data key version ${row.pdkVersion} ` +
            `while this token holds version ${raw.pdkVersion}. This is what a re-key looks ` +
            "like from here. Sluice is keeping any last known good secrets and waiting for " +
            "the next update.",
        );
      }

      // TWO ASSOCIATED DATA VALUES PER ROW, ONE PER FIELD. The name and the
      // value of a row are sealed under different associated data, both bound
      // to this environment, this secret's permanent id and this version. That
      // is what makes every splice a database writer can perform fail to open
      // rather than decrypt and be believed: another secret's value in this row
      // (wrong `secretUid`), the name ciphertext in the value slot (wrong
      // field), or a superseded value under the current version number (wrong
      // `version`). What it does NOT catch is the whole old row served with its
      // own old version, whose associated data is correct for it; that needs a
      // client-side ratchet on the highest version seen.
      //
      // `secretUid` and `version` are untrusted columns and
      // `secretAssociatedData` THROWS on a malformed one. That throw is
      // converted to the same `row-open` an unopenable ciphertext produces, and
      // like that failure it refuses the whole bundle: a row that cannot be
      // bound is a row that cannot be opened, and partial decryption is refused
      // for the reason in the header of this file.
      let nameAAD: Uint8Array;
      let valueAAD: Uint8Array;
      try {
        const slot = {
          environmentUid: raw.environmentUid,
          secretUid: row.secretUid,
          version: row.version,
        };
        nameAAD = secretAssociatedData({ ...slot, field: "name" });
        valueAAD = secretAssociatedData({ ...slot, field: "value" });
      } catch {
        throw unreadableRow(row);
      }

      const name = await open(pdk, nameAAD, row, row.nameCiphertext, row.nameNonce);
      const value = await open(pdk, valueAAD, row, row.valueCiphertext, row.valueNonce);

      if (!ENV_NAME.test(name)) {
        throw new BundleDecryptError(
          "bad-name",
          `The secret ${rowLabel(row)} has a name that cannot be an ` +
            "environment variable. Names must start with a letter or an underscore and " +
            "contain only letters, digits and underscores. The name is not printed here.",
        );
      }
      if (Object.prototype.hasOwnProperty.call(secrets, name)) {
        throw new BundleDecryptError(
          "duplicate-name",
          `Two secrets in this environment decrypt to the same name, one of them ` +
            `the secret ${rowLabel(row)}. Sluice will not choose between them. ` +
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
    throw unreadableRow(row);
  }
}

/**
 * THE ONE `row-open` FAILURE, whatever made the row unreadable: a ciphertext
 * that will not open, a secret id or version that cannot be bound, or an entry
 * that is not a row. One message for all of them, so the error says nothing
 * about which input was wrong, matching the AEAD failures it sits beside.
 */
function unreadableRow(row: unknown): BundleDecryptError {
  return new BundleDecryptError(
    "row-open",
    `The secret ${rowLabel(row)} could not be opened with this ` +
      "environment's project data key. Sluice is keeping any last known good secrets.",
  );
}

/**
 * How every message names a row: its `lineageId` when the row carries one,
 * otherwise its `secretUid`, each through {@link safeId}. Takes `unknown`
 * because it is called on entries that may not be rows at all, and must never
 * throw on one, since it runs while building the error for exactly those.
 */
function rowLabel(row: unknown): string {
  if (typeof row !== "object" || row === null) return safeId(undefined);
  const { lineageId, secretUid } = row as { lineageId?: unknown; secretUid?: unknown };
  return lineageId !== undefined ? safeId(lineageId) : safeId(secretUid);
}

/**
 * An identifier, or a placeholder.
 *
 * The id is a server side identifier and is safe to show, but it arrives from
 * the same untrusted row as everything else, so a value that is not a short
 * opaque string never reaches a terminal.
 */
function safeId(value: unknown): string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value) ? value : "unknown";
}
