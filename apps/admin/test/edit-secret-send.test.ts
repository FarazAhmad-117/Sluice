import { describe, expect, it, vi } from "vitest";
import { ConvexError } from "convex/values";
import { newId } from "@sluice/crypto";
import { openSecret } from "../src/lib/secrets/decrypt";
import { editSecret } from "../src/lib/secrets/edit-secret";
import type { EditableRow, RowEdit } from "../src/lib/secrets/edit-secret";
import { createProjectDataKey } from "../src/lib/secrets/pdk";
import type { EnvironmentKey } from "../src/lib/secrets/pdk";
import { SHARED_ROWS_CHANGED, STALE_SECRET_VERSION } from "../src/lib/secrets/write-errors";

/** `editSecret`: what is sent, through which mutation, and what comes back. */

function environmentKey(): EnvironmentKey {
  return { pdk: createProjectDataKey(), environmentUid: newId("env"), pdkVersion: 1 };
}

function row(overrides: Partial<EditableRow> = {}): EditableRow {
  return { secretId: `doc_${Math.random()}`, secretUid: newId("sec"), version: 3, ...overrides };
}

const noShared = async () => Promise.reject(new Error("not expected"));

describe("editSecret", () => {
  it("sends one updateSecret for a row", async () => {
    const sent: RowEdit[] = [];
    const outcome = await editSecret(
      { kind: "row", key: environmentKey(), row: row(), name: "N", value: "v" },
      { updateSecret: async (args) => void sent.push(args), updateSharedSecret: noShared },
    );
    expect(outcome).toEqual({ ok: true });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ version: 4 });
  });

  it("passes a stale version back with a reload", async () => {
    const outcome = await editSecret(
      { kind: "row", key: environmentKey(), row: row(), name: "N", value: "v" },
      { updateSecret: async () => Promise.reject(new ConvexError(STALE_SECRET_VERSION)), updateSharedSecret: noShared },
    );
    expect(outcome).toEqual({ ok: false, message: STALE_SECRET_VERSION, reload: true });
  });

  it("sends the shared value in one updateSharedSecret, overridden rows left out", async () => {
    const shareUid = newId("shr");
    const devKey = environmentKey();
    const dev = row({ shareUid, overridden: false });
    const prod = row({ shareUid, overridden: true });
    const sent: { projectId: string; shareUid: string; rows: readonly RowEdit[] }[] = [];
    const updateSecret = vi.fn(async () => ({}));
    const outcome = await editSecret(
      {
        kind: "shared",
        projectId: "prj",
        shareUid,
        name: "N",
        value: "v",
        rows: [
          { row: dev, environmentName: "development", key: devKey },
          { row: prod, environmentName: "production", key: environmentKey() },
        ],
      },
      { updateSecret, updateSharedSecret: async (args) => void sent.push(args) },
    );
    expect(outcome).toEqual({ ok: true });
    expect(updateSecret).not.toHaveBeenCalled();
    expect(sent).toHaveLength(1);
    expect(sent[0]!.projectId).toBe("prj");
    expect(sent[0]!.shareUid).toBe(shareUid);
    expect(sent[0]!.rows.map((edit) => edit.secretId)).toEqual([dev.secretId]);
    expect(await openSecret(devKey, { ...sent[0]!.rows[0]!, secretUid: dev.secretUid })).toEqual({
      name: "N",
      value: "v",
    });
  });

  it("asks for a reload when the share's rows changed underneath", async () => {
    const shareUid = newId("shr");
    const outcome = await editSecret(
      {
        kind: "shared",
        projectId: "prj",
        shareUid,
        name: "N",
        value: "v",
        rows: [{ row: row({ shareUid }), environmentName: "development", key: environmentKey() }],
      },
      {
        updateSecret: async () => ({}),
        updateSharedSecret: async () => Promise.reject(new ConvexError(SHARED_ROWS_CHANGED)),
      },
    );
    expect(outcome).toEqual({ ok: false, message: SHARED_ROWS_CHANGED, reload: true });
  });

  it("reports its own refusals as sentences and hides anything else", async () => {
    const shareUid = newId("shr");
    const updateSharedSecret = vi.fn(async () => ({}));
    const locked = await editSecret(
      {
        kind: "shared",
        projectId: "prj",
        shareUid,
        name: "N",
        value: "v",
        rows: [{ row: row({ shareUid }), environmentName: "staging", key: null }],
      },
      { updateSecret: async () => ({}), updateSharedSecret },
    );
    expect(locked).toMatchObject({ ok: false, reload: false });
    expect((locked as { message: string }).message).toContain("staging");
    expect(updateSharedSecret).not.toHaveBeenCalled();

    const transport = await editSecret(
      { kind: "row", key: environmentKey(), row: row(), name: "N", value: "v" },
      {
        updateSecret: async () => Promise.reject(new Error("socket closed, ciphertext deadbeef")),
        updateSharedSecret: noShared,
      },
    );
    expect(transport).toEqual({ ok: false, message: "That did not work. Try again.", reload: false });
  });
});
