import { signHandshake, toHex } from "@sluice/crypto";
import { sanitiseForLog } from "@sluice/sdk";
import type { TokenIdentity } from "./config";

/**
 * TRADING A SIGNATURE FOR A FIVE MINUTE BUNDLE TOKEN.
 *
 * A service token holds a secret it must never transmit, so it proves
 * possession by signing a timestamp instead. `convex/http.ts` checks the clock
 * first, verifies the signature, refuses a replayed one, and answers with a
 * short-lived JWT.
 *
 * WHY THE SHORT LIFETIME IS THE SHELL'S PROBLEM AND NOT THE SERVER'S. A live
 * subscription whose bundle token has expired still re-runs when a revocation
 * row lands, and the query then throws. The SDK sees a transport error, and a
 * transport error never means revocation, so the process carries on from cache
 * indefinitely. A WORKLOAD THAT STOPS RE-HANDSHAKING IS UN-REVOKABLE. The
 * re-handshake timer in `shell.ts` is what stops that, and it is a kill switch
 * obligation rather than a freshness nicety.
 *
 * NOTHING HERE EVER PUTS A CREDENTIAL IN AN ERROR. The request body carries a
 * signature, which is public, and never the token secret. The response body
 * carries a bearer JWT, so a failure that echoed the body would put that JWT in
 * every log that caught it. The one thing that IS echoed is the server's own
 * `error` string, sanitised, because those strings are a fixed set chosen by
 * `convex/http.ts` to leak nothing and one of them, the clock skew refusal, is
 * the only thing that tells an operator their machine's clock is wrong.
 */

/** Guards against a deployment that answers with something enormous. */
const MAX_ERROR_BODY_CHARACTERS = 2_000;

export interface BundleCredential {
  /** The bearer JWT. NEVER logged, never persisted, never put in an error. */
  readonly token: string;
  /** Unix milliseconds. Drives the re-handshake timer. */
  readonly expiresAt: number;
}

export interface Handshaker {
  handshake(): Promise<BundleCredential>;
}

export class HandshakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeError";
  }
}

/** The one shape of `fetch` this uses, so a test can supply four lines. */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface HttpHandshakerOptions {
  readonly url: string;
  readonly identity: TokenIdentity;
  readonly fetch: FetchLike;
  /** Unix milliseconds. Injected so the signed timestamp is testable. */
  readonly now: () => number;
}

export class HttpHandshaker implements Handshaker {
  readonly #url: string;
  readonly #identity: TokenIdentity;
  readonly #fetch: FetchLike;
  readonly #now: () => number;

  constructor(options: HttpHandshakerOptions) {
    this.#url = options.url;
    this.#identity = options.identity;
    this.#fetch = options.fetch;
    this.#now = options.now;
  }

  async handshake(): Promise<BundleCredential> {
    const unixSeconds = Math.floor(this.#now() / 1000);
    const signature = toHex(
      signHandshake(this.#identity.tokenId, this.#identity.tokenSecret, unixSeconds),
    );

    let response: Response;
    try {
      response = await this.#fetch(this.#url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tokenId: this.#identity.tokenIdHex,
          unixSeconds,
          signature,
        }),
      });
    } catch (error) {
      // The cause is deliberately not interpolated. A DNS or TLS failure from
      // an arbitrary runtime carries whatever text that runtime chose, which on
      // some of them includes the full request. The operator needs to know the
      // endpoint was unreachable, and they already know its address.
      throw new HandshakeError(
        `The Sluice handshake endpoint could not be reached. Sluice is holding its last ` +
          `known good secrets and will retry. Cause class: ${errorClass(error)}.`,
      );
    }

    if (!response.ok) {
      throw new HandshakeError(
        `The Sluice handshake was refused with HTTP ${response.status}. ` +
          `${await serverMessage(response)}`,
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new HandshakeError(
        "The Sluice handshake endpoint answered with something that is not JSON. Check that " +
          "SLUICE_CONVEX_SITE_URL points at the deployment's HTTP actions origin.",
      );
    }

    const token = (body as { token?: unknown } | null)?.token;
    const expiresAt = (body as { expiresAt?: unknown } | null)?.expiresAt;
    if (typeof token !== "string" || token.length === 0) {
      throw new HandshakeError("The Sluice handshake response carried no bundle token.");
    }
    if (typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt)) {
      throw new HandshakeError("The Sluice handshake response carried no usable expiry.");
    }
    if (expiresAt <= this.#now()) {
      // Accepting this would arm the re-handshake timer with a negative delay
      // and, worse, would look like a working credential. An already-expired
      // credential means the two clocks disagree by more than the lifetime, and
      // that is a configuration failure rather than something to retry into.
      throw new HandshakeError(
        "The Sluice handshake returned a bundle token that has already expired. This " +
          "machine's clock and the deployment's disagree by more than the token lifetime.",
      );
    }
    return { token, expiresAt };
  }
}

/**
 * The server's own refusal string, sanitised, or nothing.
 *
 * `convex/http.ts` answers with one of three fixed strings and interpolates
 * nothing into them, so this is safe to show. It is sanitised anyway: this code
 * cannot prove what is on the other end of the URL an operator configured, and
 * an attacker who controls that answer controls a line on an operator's
 * terminal during an incident.
 */
async function serverMessage(response: Response): Promise<string> {
  try {
    const raw = await response.text();
    if (raw.length === 0 || raw.length > MAX_ERROR_BODY_CHARACTERS) return "";
    const parsed = JSON.parse(raw) as { error?: unknown } | null;
    const message = parsed?.error;
    if (typeof message !== "string") return "";
    return sanitiseForLog(message);
  } catch {
    // A body that is not JSON is a body this code will not print. It is the
    // likeliest place for an HTML error page from a proxy, escape sequences and
    // all, and there is nothing in one an operator needs.
    return "";
  }
}

/** The constructor name only. Never the message, which can carry the request. */
function errorClass(error: unknown): string {
  const name = (error as { name?: unknown } | null)?.name;
  return typeof name === "string" && /^[A-Za-z]{1,40}$/.test(name) ? name : "unknown";
}
