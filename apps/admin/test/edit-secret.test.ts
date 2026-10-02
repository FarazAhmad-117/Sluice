import { describe, expect, it, vi } from "vitest";
import { ConvexError } from "convex/values";
import { newId } from "@sluice/crypto";
import { SecretOpenError, openSecret } from "../src/lib/secrets/decrypt";
import {
  SHARED_EDIT_UNAVAILABLE,
  buildRowEdit,
  buildSharedEdit,
  editSecret,
} from "../src/lib/secrets/edit-secret";
import type { EditableRow, RowEdit } from "../src/lib/secrets/edit-secret";
import { createProjectDataKey } from "../src/lib/secrets/pdk";
import type { EnvironmentKey } from "../src/lib/secrets/pdk";
import { STALE_SECRET_VERSION } from "../src/lib/secrets/write-errors";

/**
 * EDITING A VALUE. The assertion that matters is the one the server cannot
 * make: each new row opens with ITS environment's key, at the NEXT version,
 * and with no other key and at no other version.
 */

function environmentKey(pdkVersion = 1): EnvironmentKey {
  return { pdk: createProjectDataKey(), environmentUid: newId("env"), pdkVersion };
}

function row(overrides: Partial<EditableRow> = {}): EditableRow {
  return { secretId: `doc_${Math.random()}`, secretUid: newId("sec"), version: 3, ...overrides };
}

describe("buildRowEdit", () => {
  it("seals the next version of the same secret, name and value, under the row's key", async () => {
    const key = environmentKey(2);
    const current = row();
    const edit = await buildRowEdit({ key, row: current, name: "API_URL", value: "https://new" });
    expect(edit.secretId).toBe(current.secretId);
    expect(edit.version).toBe(4);
    expect(edit.pdkVersion).toBe(2);
    const opened = await openSecret(key, { ...edit, secretUid: current.secretUid });
    expect(opened).toEqual({ name: "API_URL", value: "https://new" });
    // Bound to version 4: served as version 3 it does not open.
    await expect(openSecret(key, { ...edit, secretUid: current.secretUid, version: 3 })).rejects.toBeInstanceOf(
      SecretOpenError,
    );
  });
});

describe("buildSharedEdit", () => {
  const shareUid = newId("shr");

  it("seals the shared value into every non-overridden row, each with its own key", async () => {
    const dev = { row: row({ shareUid, overridden: false }), environmentName: "development", key: environmentKey() };
    const stg = { row: row({ shareUid, overridden: false, version: 1 }), environmentName: "staging", key: environmentKey(5) };
    const prod = { row: row({ shareUid, overridden: true }), environmentName: "production", key: environmentKey() };
    const payload = await buildSharedEdit({ shareUid, name: "LOG_LEVEL", value: "info", rows: [dev, stg, prod] });

    expect(payload.shareUid).toBe(shareUid);
    // The overridden row is absent: it keeps its own value.
    expect(payload.rows.map((edit) => edit.secretId)).toEqual([dev.row.secretId, stg.row.secretId]);
    expect(payload.rows.map((edit) => edit.version)).toEqual([4, 2]);
    expect(payload.rows.map((edit) => edit.pdkVersion)).toEqual([1, 5]);

    for (const [index, target] of [dev, stg].entries()) {
      const edit = payload.rows[index]!;
      expect(await openSecret(target.key, { ...edit, secretUid: target.row.secretUid })).toEqual({
        name: "LOG_LEVEL",
        value: "info",
      });
    }
    // Development's new row does not open under staging's key.
    await expect(
      openSecret(stg.key, { ...payload.rows[0]!, secretUid: dev.row.secretUid }),
    ).rejects.toBeInstanceOf(SecretOpenError);
  });

  it("refuses before sealing when a key is not open", async () => {
    await expect(
      buildSharedEdit({
        shareUid,
        name: "N",
        value: "v",
        rows: [
          { row: row({ shareUid }), environmentName: "development", key: environmentKey() },
          { row: row({ shareUid }), environmentName: "production", key: null },
        ],
      }),
    ).rejects.toThrow("The key for production is not open");
  });

  it("does not mind a closed key on an overridden row it leaves alone", async () => {
    const payload = await buildSharedEdit({
      shareUid,
      name: "N",
      value: "v",
      rows: [
        { row: row({ shareUid }), environmentName: "development", key: environmentKey() },
        { row: row({ shareUid, overridden: true }), environmentName: "production", key: null },
      ],
    });
    expect(payload.rows).toHaveLength(1);
  });

  it("refuses a row of another share, and a share with no shared rows", async () => {
    await expect(
      buildSharedEdit({
        shareUid,
        name: "N",
        value: "v",
        rows: [{ row: row({ shareUid: newId("shr") }), environmentName: "development", key: environmentKey() }],
      }),
    ).rejects.toThrow("another secret");
    await expect(
      buildSharedEdit({
        shareUid,
        name: "N",
        value: "v",
        rows: [{ row: row({ shareUid, overridden: true }), environmentName: "development", key: environmentKey() }],
      }),
    ).rejects.toThrow("No environment uses the shared value.");
  });
});

describe("editSecret", () => {
  it("sends one updateSecret for a row", async () => {
    const sent: RowEdit[] = [];
    const outcome = await editSecret(
      { kind: "row", key: environmentKey(), row: row(), name: "N", value: "v" },
      { updateSecret: async (args) => void sent.push(args) },
    );
    expect(outcome).toEqual({ ok: true });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ version: 4 });
  });

  it("passes a stale version back with a reload", async () => {
    const outcome = await editSecret(
      { kind: "row", key: environmentKey(), row: row(), name: "N", value: "v" },
      { updateSecret: async () => Promise.reject(new ConvexError(STALE_SECRET_VERSION)) },
    );
    expect(outcome).toEqual({ ok: false, message: STALE_SECRET_VERSION, reload: true });
  });

  it("builds the shared payload but does not send it yet", async () => {
    const shareUid = newId("shr");
    const updateSecret = vi.fn(async () => ({}));
    const outcome = await editSecret(
      {
        kind: "shared",
        projectId: "prj",
        shareUid,
        name: "N",
        value: "v",
        rows: [{ row: row({ shareUid }), environmentName: "development", key: environmentKey() }],
      },
      { updateSecret },
    );
    expect(outcome).toEqual({ ok: false, message: SHARED_EDIT_UNAVAILABLE, reload: false });
    expect(updateSecret).not.toHaveBeenCalled();
  });

  it("reports its own refusals as sentences and hides anything else", async () => {
    const shareUid = newId("shr");
    const locked = await editSecret(
      {
        kind: "shared",
        projectId: "prj",
        shareUid,
        name: "N",
        value: "v",
        rows: [{ row: row({ shareUid }), environmentName: "staging", key: null }],
      },
      { updateSecret: async () => ({}) },
    );
    expect(locked).toMatchObject({ ok: false, reload: false });
    expect((locked as { message: string }).message).toContain("staging");

    const transport = await editSecret(
      { kind: "row", key: environmentKey(), row: row(), name: "N", value: "v" },
      { updateSecret: async () => Promise.reject(new Error("socket closed, ciphertext deadbeef")) },
    );
    expect(transport).toEqual({ ok: false, message: "That did not work. Try again.", reload: false });
  });
});
