import { describe, expect, it } from "vitest";
import { ConvexError } from "convex/values";
import { newId, toHex } from "@sluice/crypto";
import { DUPLICATE_UID } from "@convex/lib/errors";
import {
  AccountSaltError,
  DUPLICATE_UID_MESSAGE,
  decodeLoginSalt,
  messageForUser,
} from "../src/lib/auth/auth-errors";

/**
 * THE TWO GATES BETWEEN A SERVER REPLY AND THE FORM.
 *
 * `decodeLoginSalt` decides whether `getLoginSalt`'s answer is something to
 * spend 64 MiB of Argon2 on. `messageForUser` decides what the person sees
 * when anything fails. Both are pinned here for the same two properties: they
 * refuse exactly what they should, and nothing they produce carries the input
 * that caused it.
 */

const VALID = "303132333435363738393a3b3c3d3e3f";

describe("decodeLoginSalt", () => {
  it("decodes 32 lowercase hex characters to the 16 bytes they spell", () => {
    const bytes = decodeLoginSalt(VALID);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(toHex(bytes)).toBe(VALID);
  });

  /**
   * Every shape a broken server, a broken transport or a missing reply can
   * produce. Uppercase is refused although `fromHex` would accept it: the
   * session store loads with the same pattern, so a salt accepted here in
   * uppercase would be one the unlock prompt then refused after a reload.
   */
  it.each([
    ["too short", VALID.slice(0, 30)],
    ["too long", `${VALID}30`],
    ["uppercase", VALID.toUpperCase()],
    ["not hex", "zz".repeat(16)],
    ["odd length", VALID.slice(0, 31)],
    ["padded with whitespace", ` ${VALID}`],
    ["empty", ""],
    ["a number", 42],
    ["a byte array", new Uint8Array(16)],
    ["an object", { accountSalt: VALID }],
    ["null", null],
    ["undefined", undefined],
  ])("refuses a salt that is %s, without echoing it", (_label, input) => {
    let caught: unknown;
    try {
      decodeLoginSalt(input);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(AccountSaltError);
    const message = (caught as Error).message;
    if (typeof input === "string" && input.length > 0) {
      expect(message).not.toContain(input);
      expect(message.toLowerCase()).not.toContain(input.trim().slice(0, 8).toLowerCase());
    }
  });
});

describe("messageForUser", () => {
  /**
   * The constant is imported from the module the server throws it from, so a
   * rewording on the server moves this match with it instead of silently
   * stopping it from firing.
   */
  it("rewrites the server's duplicate-uid refusal into an instruction", () => {
    const message = messageForUser(new ConvexError(DUPLICATE_UID));
    expect(message).toBe(DUPLICATE_UID_MESSAGE);
    expect(message).not.toMatch(/\buid\b/);
  });

  it("passes AccountSaltError's own sentence through", () => {
    expect(messageForUser(new AccountSaltError())).toBe(new AccountSaltError().message);
  });

  it("passes other server sentences through unchanged", () => {
    expect(messageForUser(new ConvexError("Invalid email or verifier."))).toBe(
      "Invalid email or verifier.",
    );
  });

  /**
   * The flows throw plain `Error`s for a mismatched or malformed uid, and
   * `assertId` throws one naming only the field. None of that text reaches the
   * form, so no uid or salt can either.
   */
  it("never shows a uid or a salt, whatever the error carried", () => {
    const uid = newId("usr");
    const causes = [
      new Error(`account id ${uid} does not match`),
      new Error(`salt ${VALID} is wrong`),
      new TypeError(`cannot read accountSalt of ${uid}`),
      { message: `${uid} ${VALID}` },
      `${uid} ${VALID}`,
    ];
    for (const cause of causes) {
      const message = messageForUser(cause);
      expect(message).toBe("Something went wrong. Try again.");
      expect(message).not.toContain(uid);
      expect(message).not.toContain(VALID);
    }
  });
});
