import { describe, expect, it } from "vitest";
import { LIVE_WINDOW_MS, canRevoke, connectionState } from "../src/lib/tokens/connection";

const NOW = 1_800_000_000_000;
const active = { status: "active" as const, lastSeenAt: null, expiresAt: null };

describe("connectionState", () => {
  it("says never connected until the first handshake", () => {
    expect(connectionState(active, NOW)).toBe("never");
  });

  it("is live within the window and idle after it", () => {
    expect(connectionState({ ...active, lastSeenAt: NOW - LIVE_WINDOW_MS + 1 }, NOW)).toBe("live");
    expect(connectionState({ ...active, lastSeenAt: NOW - LIVE_WINDOW_MS }, NOW)).toBe("idle");
  });

  it("puts revoked before everything, then expired", () => {
    expect(connectionState({ status: "revoked", lastSeenAt: NOW, expiresAt: NOW - 1 }, NOW)).toBe("revoked");
    expect(connectionState({ ...active, lastSeenAt: NOW, expiresAt: NOW }, NOW)).toBe("expired");
  });

  it("offers revoke for everything not already revoked", () => {
    expect(canRevoke("live")).toBe(true);
    expect(canRevoke("expired")).toBe(true);
    expect(canRevoke("revoked")).toBe(false);
  });
});
