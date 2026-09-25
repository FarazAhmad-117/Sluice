import { deriveTokenKeys, parseToken, toHex, tokenIdHash } from "@sluice/crypto";
import { MAX_DRAIN_MS, MIN_MAX_OFFLINE_DURATION_MS } from "@sluice/sdk";

/**
 * EVERYTHING `sluice run` NEEDS, READ FROM THE ENVIRONMENT AND VALIDATED ONCE.
 *
 * WHY THIS IS A PURE FUNCTION OVER A RECORD RATHER THAN A READER OF
 * `process.env`. Configuration bugs on this product are security bugs: a
 * process that starts with the wrong organisation key has no kill switch, and
 * nothing anywhere reports it until the incident. A pure function is one every
 * hostile spelling can be enumerated against in a test, which is the only thing
 * that makes the guarantee worth anything.
 *
 * NOTHING HERE EVER ECHOES A VALUE IT WAS GIVEN. `SLUICE_TOKEN` is a bearer
 * credential whose second half reconstructs the key that opens every secret in
 * the environment, and a refusal message travels into logs, CI output, error
 * reporters and support tickets. Messages name the VARIABLE and the expected
 * shape; they never name what was found. That costs a little diagnostic comfort
 * and it is not negotiable.
 */

/** Anything longer and a revoked process is alive for too long. */
const DEFAULT_DRAIN_MS = 5_000;

/**
 * How long a child that ignored SIGTERM gets before SIGKILL.
 *
 * Separate from the drain window on purpose. The drain is the customer's chance
 * to flush; this is the operating system's. A child that ignores SIGTERM is
 * either wedged or deliberately resisting, and both get the same answer.
 */
const DEFAULT_KILL_GRACE_MS = 5_000;

const DEFAULT_BOOT_TIMEOUT_MS = 30_000;

/** A ceiling on every duration read here, so a typo cannot disable a deadline. */
const MAX_CONFIGURABLE_MS = 600_000;

const PUBLIC_KEY_HEX_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The token's key material, wrapped so that logging it is hard by accident.
 *
 * Same device, and the same stated limit, as `MintedToken` in `@sluice/crypto`:
 * `toJSON` and the Node inspect hook live on the PROTOTYPE, so `{ ...identity }`
 * and `structuredClone(identity)` both defeat them. Pass this object, never a
 * copy of it.
 */
export class TokenIdentity {
  /** Lowercase hex of the 16 byte id. Public: the server stores only its hash. */
  readonly tokenIdHex: string;
  /** The stored form, and the grantee id on this token's project data key grant. */
  readonly tokenIdHashHex: string;
  readonly environment: string;
  /** Raw id bytes, needed to sign a handshake. */
  readonly tokenId: Uint8Array;
  /** SECRET. Signs handshakes. */
  readonly tokenSecret: Uint8Array;
  /** SECRET. Opens the project data key. Never transmitted, ever. */
  readonly unwrapKey: Uint8Array;

  private constructor(fields: {
    tokenIdHex: string;
    tokenIdHashHex: string;
    environment: string;
    tokenId: Uint8Array;
    tokenSecret: Uint8Array;
    unwrapKey: Uint8Array;
  }) {
    this.tokenIdHex = fields.tokenIdHex;
    this.tokenIdHashHex = fields.tokenIdHashHex;
    this.environment = fields.environment;
    this.tokenId = fields.tokenId;
    this.tokenSecret = fields.tokenSecret;
    this.unwrapKey = fields.unwrapKey;
  }

  static fromToken(token: string): TokenIdentity {
    const { environment, tokenId, tokenSecret } = parseToken(token);
    const { unwrapKey } = deriveTokenKeys(tokenId, tokenSecret);
    return new TokenIdentity({
      tokenIdHex: toHex(tokenId),
      tokenIdHashHex: tokenIdHash({ tokenId }),
      environment,
      tokenId,
      tokenSecret,
      unwrapKey,
    });
  }

  /** The public half only. Every JSON path in this process routes through here. */
  toJSON(): { tokenIdHash: string; environment: string } {
    return { tokenIdHash: this.tokenIdHashHex, environment: this.environment };
  }

  /**
   * Keeps an inspected identity from printing key bytes at a terminal.
   *
   * The symbol is looked up rather than imported from `node:util`, matching
   * `@sluice/crypto`: an import would tie this module to Node, and the
   * redaction is worth having in any runtime that supports the hook.
   */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "[TokenIdentity redacted]";
  }
}

export interface RunConfig {
  readonly identity: TokenIdentity;
  /** Pinned by the customer. See `SluiceCoreOptions.orgRevocationPublicKey`. */
  readonly orgRevocationPublicKey: string;
  /** The deployment address the reactive subscription connects to. */
  readonly convexUrl: string;
  /** The full handshake endpoint, already joined. */
  readonly handshakeUrl: string;
  readonly drainMs: number;
  readonly killGraceMs: number;
  readonly bootTimeoutMs: number;
  /** Undefined means unlimited, which is the documented default. */
  readonly maxOfflineDurationMs: number | undefined;
  /** Where the revocation epoch floor is persisted. */
  readonly stateDir: string | undefined;
}

export type ConfigResult =
  | { readonly ok: true; readonly config: RunConfig }
  | { readonly ok: false; readonly message: string };

function fail(message: string): ConfigResult {
  return { ok: false, message };
}

/**
 * Reads one optional duration.
 *
 * An unparseable value is a REFUSAL rather than a fall back to the default. A
 * `SLUICE_DRAIN_MS=5s` that silently became 5000 would be a deadline nobody
 * could reason about, and a `SLUICE_MAX_OFFLINE_MS=0` that silently became
 * unlimited would be the opposite of what the operator asked for.
 */
function duration(
  name: string,
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number,
): { ok: true; value: number } | { ok: false; message: string } {
  if (raw === undefined || raw === "") return { ok: true, value: fallback };
  // `Number()` rather than `parseInt`: `parseInt("5s")` is 5, which is exactly
  // the silent misreading this refuses.
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    return {
      ok: false,
      message: `${name} must be a whole number of milliseconds between ${min} and ${max}.`,
    };
  }
  return { ok: true, value };
}

/**
 * Turns the deployment address into the HTTP action origin.
 *
 * Convex serves functions from a `convex.cloud` host and `httpRouter` routes
 * from the matching `convex.site` host, and the handshake is an `httpAction`.
 * Getting this wrong is a 404 on every boot, so it is derived rather than asked
 * for. A deployment that is not on `convex.cloud` must set
 * `SLUICE_CONVEX_SITE_URL`, because there is nothing to derive from.
 */
function siteOrigin(convexUrl: string): string | null {
  const suffix = ".convex.cloud";
  if (convexUrl.endsWith(suffix)) {
    return `${convexUrl.slice(0, -suffix.length)}.convex.site`;
  }
  return null;
}

function isLoopback(url: URL): boolean {
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
}

/**
 * Plain http is refused off loopback.
 *
 * The handshake response carries a bearer credential and the subscription
 * carries every ciphertext in the environment. Over plain http on a real
 * network both are readable by anything on the path, and the failure is
 * invisible: everything works.
 */
function checkOrigin(
  name: string,
  raw: string,
): { ok: true; value: string } | { ok: false; message: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, message: `${name} must be an absolute URL.` };
  }
  if (url.protocol === "https:") return { ok: true, value: trimSlash(raw) };
  if (url.protocol === "http:" && isLoopback(url)) return { ok: true, value: trimSlash(raw) };
  return { ok: false, message: `${name} must use https, or http only on localhost.` };
}

function trimSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

export function loadConfig(env: Record<string, string | undefined>): ConfigResult {
  const rawToken = env.SLUICE_TOKEN;
  if (rawToken === undefined || rawToken === "") {
    return fail(
      "SLUICE_TOKEN is not set. Create a service token in the Sluice dashboard and put it " +
        "in this process's environment.",
    );
  }

  const orgKey = env.SLUICE_ORG_REVOCATION_PUBLIC_KEY;
  if (orgKey === undefined || orgKey === "") {
    return fail(
      "SLUICE_ORG_REVOCATION_PUBLIC_KEY is not set. It is your organisation's Ed25519 " +
        "revocation public key, 64 lowercase hex characters, pinned in your own " +
        "configuration and never fetched from a Sluice server. A server that could supply " +
        "this key could sign its own revocation notices and kill every process you run.",
    );
  }
  if (!PUBLIC_KEY_HEX_PATTERN.test(orgKey)) {
    // Uppercase is rejected rather than folded, matching `SluiceCore` and
    // `@sluice/crypto`. A key folded here would look right at boot and would
    // not verify inside `verifyRevocation`, so the process would start with a
    // kill switch that silently never fires.
    return fail("SLUICE_ORG_REVOCATION_PUBLIC_KEY must be exactly 64 lowercase hex characters.");
  }

  const rawConvexUrl = env.SLUICE_CONVEX_URL;
  if (rawConvexUrl === undefined || rawConvexUrl === "") {
    return fail("SLUICE_CONVEX_URL is not set. It is your Sluice deployment address.");
  }
  const convexUrl = checkOrigin("SLUICE_CONVEX_URL", rawConvexUrl);
  if (!convexUrl.ok) return fail(convexUrl.message);

  const rawSiteUrl = env.SLUICE_CONVEX_SITE_URL;
  let siteUrl: string;
  if (rawSiteUrl !== undefined && rawSiteUrl !== "") {
    const checked = checkOrigin("SLUICE_CONVEX_SITE_URL", rawSiteUrl);
    if (!checked.ok) return fail(checked.message);
    siteUrl = checked.value;
  } else {
    const derived = siteOrigin(convexUrl.value);
    if (derived === null) {
      return fail(
        "SLUICE_CONVEX_SITE_URL must be set when SLUICE_CONVEX_URL is not a convex.cloud " +
          "address. The handshake endpoint is served from a different origin to the " +
          "subscription.",
      );
    }
    siteUrl = derived;
  }

  const drain = duration("SLUICE_DRAIN_MS", env.SLUICE_DRAIN_MS, DEFAULT_DRAIN_MS, 0, MAX_DRAIN_MS);
  if (!drain.ok) return fail(drain.message);
  const killGrace = duration(
    "SLUICE_KILL_GRACE_MS",
    env.SLUICE_KILL_GRACE_MS,
    DEFAULT_KILL_GRACE_MS,
    0,
    MAX_CONFIGURABLE_MS,
  );
  if (!killGrace.ok) return fail(killGrace.message);
  const bootTimeout = duration(
    "SLUICE_BOOT_TIMEOUT_MS",
    env.SLUICE_BOOT_TIMEOUT_MS,
    DEFAULT_BOOT_TIMEOUT_MS,
    0,
    MAX_CONFIGURABLE_MS,
  );
  if (!bootTimeout.ok) return fail(bootTimeout.message);

  let maxOffline: number | undefined;
  if (env.SLUICE_MAX_OFFLINE_MS !== undefined && env.SLUICE_MAX_OFFLINE_MS !== "") {
    const parsed = duration(
      "SLUICE_MAX_OFFLINE_MS",
      env.SLUICE_MAX_OFFLINE_MS,
      MIN_MAX_OFFLINE_DURATION_MS,
      MIN_MAX_OFFLINE_DURATION_MS,
      Number.MAX_SAFE_INTEGER,
    );
    if (!parsed.ok) return fail(parsed.message);
    maxOffline = parsed.value;
  }

  let identity: TokenIdentity;
  try {
    identity = TokenIdentity.fromToken(rawToken);
  } catch {
    // The thrown message is discarded deliberately. `parseToken` is careful
    // never to echo its input, but this is the one place in the product that
    // handles a raw token string, and a future change to that message must not
    // be able to turn this into a leak.
    return fail(
      "SLUICE_TOKEN is not a Sluice service token. The expected shape is " +
        "slc_<environment>_<32 hex characters>.<64 hex characters>.",
    );
  }

  return {
    ok: true,
    config: {
      identity,
      orgRevocationPublicKey: orgKey,
      convexUrl: convexUrl.value,
      handshakeUrl: `${siteUrl}/handshake`,
      drainMs: drain.value,
      killGraceMs: killGrace.value,
      bootTimeoutMs: bootTimeout.value,
      maxOfflineDurationMs: maxOffline,
      stateDir: env.SLUICE_STATE_DIR === "" ? undefined : env.SLUICE_STATE_DIR,
    },
  };
}
