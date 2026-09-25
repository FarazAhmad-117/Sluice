import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NO_PERSISTED_FLOOR } from "@sluice/sdk";
import { FileEpochFloorStore, floorFilePath } from "../src/floor";

const TOKEN_ID_HASH = "b".repeat(64);

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "sluice-floor-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function store(): FileEpochFloorStore {
  return new FileEpochFloorStore(dir, TOKEN_ID_HASH);
}

describe("FileEpochFloorStore", () => {
  it("reports the explicit sentinel on a first ever boot, never a bare number", () => {
    const loaded = store().load();
    expect(loaded).toEqual({ ok: true, floor: NO_PERSISTED_FLOOR });
  });

  it("round trips a floor so a restart does not reopen the replay window", () => {
    store().save(7);
    expect(store().load()).toEqual({ ok: true, floor: 7 });
  });

  it("refuses to lower a stored floor, because two processes share one file", () => {
    store().save(9);
    store().save(4);
    expect(store().load()).toEqual({ ok: true, floor: 9 });
  });

  it("writes nothing readable as a secret and keeps the plaintext token id off disk", () => {
    store().save(3);
    const raw = readFileSync(floorFilePath(dir, TOKEN_ID_HASH), "utf8");
    expect(raw).toContain(TOKEN_ID_HASH);
    expect(raw).toContain("3");
    expect(raw).not.toContain("slc_");
  });

  it("REFUSES TO START on a corrupt file rather than silently reopening the window", () => {
    writeFileSync(floorFilePath(dir, TOKEN_ID_HASH), "{not json", "utf8");
    const loaded = store().load();
    expect(loaded.ok).toBe(false);
    expect(!loaded.ok && loaded.message).toContain(floorFilePath(dir, TOKEN_ID_HASH));
  });

  it("refuses a file recorded against a different token", () => {
    writeFileSync(
      floorFilePath(dir, TOKEN_ID_HASH),
      JSON.stringify({ version: 1, tokenIdHash: "c".repeat(64), epochFloor: 5 }),
      "utf8",
    );
    expect(store().load().ok).toBe(false);
  });

  it("refuses a negative or fractional floor", () => {
    for (const bad of [-1, 1.5, "3", null]) {
      writeFileSync(
        floorFilePath(dir, TOKEN_ID_HASH),
        JSON.stringify({ version: 1, tokenIdHash: TOKEN_ID_HASH, epochFloor: bad }),
        "utf8",
      );
      expect(store().load().ok).toBe(false);
    }
  });

  it("ignores a save of the sentinel, which is not a floor anybody restored", () => {
    store().save(2);
    store().save(NO_PERSISTED_FLOOR);
    expect(store().load()).toEqual({ ok: true, floor: 2 });
  });

  it("creates the state directory if it is missing", () => {
    const nested = join(dir, "deep", "deeper");
    const nestedStore = new FileEpochFloorStore(nested, TOKEN_ID_HASH);
    nestedStore.save(1);
    expect(nestedStore.load()).toEqual({ ok: true, floor: 1 });
  });

  it("keeps the file name derived from the hash, so two tokens never share one", () => {
    const other = "d".repeat(64);
    expect(floorFilePath(dir, TOKEN_ID_HASH)).not.toBe(floorFilePath(dir, other));
  });

  it("never emits an em dash or an en dash in a refusal", () => {
    writeFileSync(floorFilePath(dir, TOKEN_ID_HASH), "{not json", "utf8");
    const loaded = store().load();
    expect(!loaded.ok && loaded.message).not.toMatch(/[\u2013\u2014]/);
  });
});
