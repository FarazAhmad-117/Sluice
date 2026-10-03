import { listOf } from "@/lib/list-of";
import type { EnvironmentKey } from "./pdk";
import { nextSecretSlot, sealSecret } from "./seal";
import type { SealedSecretFields } from "./seal";
import { describeWriteFailure } from "./write-errors";

/**
 * EDITING A SECRET'S VALUE: ONE ROW, OR THE SHARED VALUE EVERYWHERE AT ONCE.
 *
 * Every edit is a new version. The new ciphertexts are sealed for the slot
 * that replaces the current row: the same permanent `sec_` id, version + 1,
 * under the environment's key (see `nextSecretSlot` in `seal.ts`). The name is
 * sealed again too, because its associated data names the version: the old
 * name ciphertext would not open at the new one.
 *
 * TWO KINDS OF TARGET.
 *   - A row: a secret that lives in one environment only, or a shared
 *     secret's row that keeps its own value (an override). One `updateSecret`.
 *   - The shared value: every row of the share that is NOT overridden, each
 *     sealed under ITS environment's key, written together. Overridden rows
 *     are left alone; they keep their own value.
 *
 * A stale version or a re-keyed environment comes back with the server's own
 * sentence and `reload: true` (see `write-errors.ts`); retrying cannot help.
 */

/** A refusal this module makes before anything is sealed or sent. Its message is for a person. */
export class EditRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EditRefusal";
  }
}

/** A row exactly as listed, as far as an edit needs it. */
export interface EditableRow {
  readonly secretId: string;
  readonly secretUid: string;
  readonly version: number;
  readonly shareUid?: string;
  readonly overridden?: boolean;
}

/** What one row's edit sends: `updateSecret`'s arguments, without the session. */
export interface RowEdit extends SealedSecretFields {
  readonly secretId: string;
  readonly version: number;
  readonly pdkVersion: number;
}

export async function buildRowEdit(input: {
  readonly key: EnvironmentKey;
  readonly row: EditableRow;
  readonly name: string;
  readonly value: string;
}): Promise<RowEdit> {
  const slot = nextSecretSlot(input.row);
  const sealed = await sealSecret(input.key, { ...slot, name: input.name, value: input.value });
  return { secretId: input.row.secretId, version: slot.version, pdkVersion: input.key.pdkVersion, ...sealed };
}

export interface SharedEditPayload {
  readonly shareUid: string;
  /** One per row that uses the shared value; overridden rows are absent. */
  readonly rows: readonly RowEdit[];
}

/**
 * The shared value, sealed into every non-overridden row of `shareUid` with
 * each row's own environment key. Refuses, before sealing anything, when a row
 * belongs to another share, when no row uses the shared value, or when an
 * environment's key is not in hand.
 */
export async function buildSharedEdit(input: {
  readonly shareUid: string;
  readonly name: string;
  readonly value: string;
  readonly rows: readonly { readonly row: EditableRow; readonly environmentName: string; readonly key: EnvironmentKey | null }[];
}): Promise<SharedEditPayload> {
  const targets = input.rows.filter(({ row }) => row.overridden !== true);
  if (input.rows.some(({ row }) => row.shareUid !== input.shareUid)) {
    throw new EditRefusal("A row of another secret was given for this shared value.");
  }
  if (targets.length === 0) throw new EditRefusal("No environment uses the shared value.");
  const locked = targets.filter((target) => target.key === null).map((target) => target.environmentName);
  if (locked.length > 0) {
    throw new EditRefusal(`The key for ${listOf(locked)} is not open, so the shared value cannot be changed there.`);
  }
  const rows: RowEdit[] = [];
  for (const target of targets) {
    rows.push(await buildRowEdit({ key: target.key!, row: target.row, name: input.name, value: input.value }));
  }
  return { shareUid: input.shareUid, rows };
}

export type EditRequest =
  | {
      readonly kind: "row";
      readonly key: EnvironmentKey;
      readonly row: EditableRow;
      readonly name: string;
      readonly value: string;
    }
  | {
      readonly kind: "shared";
      readonly projectId: string;
      readonly shareUid: string;
      readonly name: string;
      readonly value: string;
      readonly rows: readonly { readonly row: EditableRow; readonly environmentName: string; readonly key: EnvironmentKey | null }[];
    };

export interface EditMutations {
  readonly updateSecret: (args: RowEdit) => Promise<unknown>;
  /** `secrets.updateSharedSecret`, without the session: every shared row at once, or none. */
  readonly updateSharedSecret: (args: { readonly projectId: string } & SharedEditPayload) => Promise<unknown>;
}

export type EditOutcome = { readonly ok: true } | { readonly ok: false; readonly message: string; readonly reload: boolean };

/** The one entry point the edit drawer calls. Never throws. */
export async function editSecret(request: EditRequest, mutations: EditMutations): Promise<EditOutcome> {
  try {
    if (request.kind === "row") {
      await mutations.updateSecret(await buildRowEdit(request));
      return { ok: true };
    }
    // The server refuses the write unless `rows` is exactly the share's
    // current non-overridden rows, each at its version + 1, so a row added,
    // removed or overridden in the meantime comes back as a reload.
    const payload = await buildSharedEdit(request);
    await mutations.updateSharedSecret({ projectId: request.projectId, ...payload });
    return { ok: true };
  } catch (cause) {
    if (cause instanceof EditRefusal) {
      // One of this module's own refusals above: already a sentence, and it
      // carries no ciphertext. Anything else goes through the generic mapper.
      return { ok: false, message: cause.message, reload: false };
    }
    return { ok: false, ...describeWriteFailure(cause) };
  }
}
