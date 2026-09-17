import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { internal } from "./_generated/api";

/**
 * THE ONLY UNAUTHENTICATED ENDPOINT IN SLUICE.
 *
 * A service token cannot present a session: it holds a secret it must never
 * transmit, and it proves possession by signing instead. This is where that
 * proof is traded for a short-lived bundle token, and it is therefore the one
 * door in the product that anyone on the internet can knock on.
 *
 * WHAT LIVES HERE AND WHAT DOES NOT. This file parses the request, checks its
 * shape, and checks the clock. It touches no table and performs no
 * cryptography. Everything else is `handshake.ts`, in ONE mutation, because the
 * replay check has to insert and fail on conflict inside a single transaction;
 * the long note there explains what splitting it costs.
 *
 * THE CLOCK CHECK IS HERE, FIRST, AND THAT IS THE POINT. Rejecting a stale or
 * future timestamp needs no key, no lookup and no curve arithmetic, so doing it
 * before anything else means a flood of garbage costs this deployment a JSON
 * parse and a regex. Verify first and every unauthenticated request buys an
 * Ed25519 verification, which is the cheapest denial of service there is
 * against a server that is otherwise careful.
 *
 * WHAT THIS ENDPOINT STILL LACKS, stated rather than left to be discovered:
 * there is no rate limit and no brute-force lockout on it. That is recorded in
 * the backend plan as a gap, and it is the obvious target.
 */

/**
 * Sixty seconds either side of server time.
 *
 * The window is why a captured handshake is not replayable for ever, and the
 * nonce table is why it is not replayable even once. Neither is sufficient
 * alone: without the window a signature is good until the heat death of the
 * universe as soon as the nonce row is reaped, and without the nonce it is good
 * for a full two minutes to anyone who saw it go past.
 */
const CLOCK_SKEW_SECONDS = 60;

const TOKEN_ID_PATTERN = /^[0-9a-f]{32}$/;
const SIGNATURE_PATTERN = /^[0-9a-f]{128}$/;

/**
 * The refusals.
 *
 * `REFUSED` is one string for every authentication outcome: unknown token id,
 * bad signature, replayed signature, revoked token, expired token. A caller
 * learns that it failed and nothing else. `handshake.ts` makes that true of the
 * TIMING as well, which is the half a constant string cannot buy on its own.
 *
 * `MALFORMED` and `SKEWED` are deliberately distinct from it, and they leak
 * nothing: both are decided entirely from the request, before any row is read,
 * so they tell the caller only what the caller already sent. In exchange an
 * SDK on a machine with a wrong clock gets told so, instead of retrying a
 * correct credential for ever against a generic failure.
 */
const MALFORMED = "The handshake request is malformed.";
const SKEWED =
  "The handshake timestamp is outside the acceptance window. Check this machine's clock.";
const REFUSED = "Handshake refused.";

/**
 * `no-store` because the body contains a bearer credential. A cache anywhere on
 * the path holding one of these is a token handed to the next caller.
 */
function respond(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

const handshake = httpAction(async (ctx, request) => {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return respond(400, { error: MALFORMED });
  }

  if (typeof body !== "object" || body === null) {
    return respond(400, { error: MALFORMED });
  }
  const { tokenId, unixSeconds, signature } = body as Record<string, unknown>;

  // Canonical lowercase hex, rejected rather than folded, the rule every
  // identifier in this codebase obeys. A value with two accepted spellings is
  // two different index keys and two different digests.
  if (typeof tokenId !== "string" || !TOKEN_ID_PATTERN.test(tokenId)) {
    return respond(400, { error: MALFORMED });
  }
  if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature)) {
    return respond(400, { error: MALFORMED });
  }
  // `Object.is(unixSeconds, -0)` is not decoration: `-0 < 0` is false,
  // `Number.isSafeInteger(-0)` is true, and `String(-0)` is `"0"`, so a `-0`
  // here would sign the same bytes as `0` while comparing as a different
  // value. `@sluice/crypto` rejects it on the signing path for exactly this
  // reason, and the two ends have to agree.
  if (
    typeof unixSeconds !== "number" ||
    !Number.isSafeInteger(unixSeconds) ||
    unixSeconds < 0 ||
    Object.is(unixSeconds, -0)
  ) {
    return respond(400, { error: MALFORMED });
  }

  // CHECK 1. Before any cryptography and before any row is read.
  if (
    Math.abs(Math.floor(Date.now() / 1000) - unixSeconds) > CLOCK_SKEW_SECONDS
  ) {
    return respond(400, { error: SKEWED });
  }

  const result = await ctx.runMutation(internal.handshake.completeHandshake, {
    tokenId,
    unixSeconds,
    signature,
  });

  if (!result.ok) return respond(401, { error: REFUSED });

  return respond(200, { token: result.token, expiresAt: result.expiresAt });
});

const http = httpRouter();

http.route({ path: "/handshake", method: "POST", handler: handshake });

export default http;
