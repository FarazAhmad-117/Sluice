import { closeSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { NO_PERSISTED_FLOOR, type EpochFloor } from "@sluice/sdk";

/**
 * OBLIGATION FOUR: PERSIST AND RESTORE THE REVOCATION EPOCH FLOOR.
 *
 * `SluiceCoreOptions.initialEpochFloor` is required and has no default
 * precisely so that a shell cannot forget this quietly. A shell that answers
 * `NO_PERSISTED_FLOOR` on every start has chosen to reopen a replay window at
 * every restart: Ed25519 signatures are deterministic, so anyone who ever
 * observed a genuine revocation notice holds bytes that verify forever, and a
 * process that has seen nothing accepts them. On a supervised workload that
 * restarts on exit, that is an indefinite denial of service from one captured
 * message.
 *
 * WHY A CORRUPT FILE REFUSES TO START, WHICH IS A REAL COST AND A DELIBERATE
 * ONE. The alternative is to treat an unreadable floor as "nothing stored",
 * which is exactly the sentinel, and that turns one bad byte on disk into a
 * silently reopened replay window with nothing in any log to say so. The whole
 * point of the sentinel is that "I have no storage" cannot be confused with "I
 * restored a floor", and a fallback here would reintroduce the confusion one
 * layer down. So a corrupt file is a named, loud failure that tells the
 * operator the exact path and that deleting it is safe on a first boot and
 * reopens a replay window otherwise. That is a decision an operator can make
 * and a fallback is not.
 *
 * WHY THE FILE IS KEYED BY THE TOKEN ID HASH. The hash is the form the server
 * already stores, and the plaintext id is the identifier `tokenIdHash` exists
 * to keep out of places it does not need to be. A directory listing of a state
 * directory is one of those places.
 *
 * THIS IS PER TOKEN AND NOT PER PROCESS. Two `sluice run` processes sharing one
 * token share this file, which is correct: they share a revocation epoch too.
 * See the note on {@link FileEpochFloorStore.save} for what that costs.
 */

/** Bumped only if the file's shape changes. An unknown version is corrupt. */
const FORMAT_VERSION = 1;

interface FloorFile {
  readonly version: number;
  readonly tokenIdHash: string;
  readonly epochFloor: number;
}

export type FloorLoad =
  | { readonly ok: true; readonly floor: EpochFloor }
  | { readonly ok: false; readonly message: string };

export interface EpochFloorStore {
  load(): FloorLoad;
  /** Called after every accepted notice. Never lowers what is already stored. */
  save(floor: EpochFloor): void;
}

/**
 * The default state directory.
 *
 * Under the user's home rather than a temp directory, because a floor that a
 * reboot clears is a floor that does nothing. If there is no home directory to
 * write to, the caller must supply `SLUICE_STATE_DIR`; guessing a path is how a
 * container ends up persisting to a layer that is discarded on restart.
 */
export function defaultStateDir(): string | null {
  try {
    const home = homedir();
    if (typeof home !== "string" || home.length === 0) return null;
    return join(home, ".sluice");
  } catch {
    return null;
  }
}

export function floorFilePath(stateDir: string, tokenIdHashHex: string): string {
  return join(stateDir, `epoch-floor-${tokenIdHashHex}.json`);
}

export class FileEpochFloorStore implements EpochFloorStore {
  readonly #path: string;
  readonly #dir: string;
  readonly #tokenIdHashHex: string;

  constructor(stateDir: string, tokenIdHashHex: string) {
    this.#dir = stateDir;
    this.#tokenIdHashHex = tokenIdHashHex;
    this.#path = floorFilePath(stateDir, tokenIdHashHex);
  }

  get path(): string {
    return this.#path;
  }

  load(): FloorLoad {
    let raw: string;
    try {
      raw = readFileSync(this.#path, "utf8");
    } catch (error) {
      // A missing file is the only benign read failure, and it is the honest
      // first boot. Every other one, including a permission error, is reported
      // rather than folded into the sentinel: a state directory this process
      // cannot read is a state directory it cannot write either, so treating it
      // as a first boot would mean silently running with no floor forever.
      if ((error as { code?: string } | null)?.code === "ENOENT") {
        return { ok: true, floor: NO_PERSISTED_FLOOR };
      }
      return { ok: false, message: this.#corrupt("it could not be read") };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { ok: false, message: this.#corrupt("it is not valid JSON") };
    }
    const file = parsed as Partial<FloorFile> | null;
    if (typeof file !== "object" || file === null) {
      return { ok: false, message: this.#corrupt("it is not an object") };
    }
    if (file.version !== FORMAT_VERSION) {
      return { ok: false, message: this.#corrupt("its format version is not one this build reads") };
    }
    if (file.tokenIdHash !== this.#tokenIdHashHex) {
      return { ok: false, message: this.#corrupt("it was written for a different service token") };
    }
    if (
      typeof file.epochFloor !== "number" ||
      !Number.isSafeInteger(file.epochFloor) ||
      file.epochFloor < 0
    ) {
      return { ok: false, message: this.#corrupt("its epoch floor is not a whole number of zero or more") };
    }
    return { ok: true, floor: file.epochFloor };
  }

  /**
   * Writes the floor, and never lowers it.
   *
   * THE READ BEFORE THE WRITE IS NOT REDUNDANT. Two `sluice run` processes on
   * one token share this file. Without the `max`, the one that started earlier
   * and is still at a lower floor would overwrite the other's higher value the
   * next time it accepted anything, and a replay the fleet had already refused
   * would become acceptable again.
   *
   * IT IS STILL NOT ATOMIC ACROSS PROCESSES, and there is no lock here. Two
   * writers can interleave read and write, so a raise can be lost. The RENAME
   * is atomic, so no reader ever sees half a file; what can be lost is one
   * increment, which costs one extra window for one replay rather than a
   * corrupted floor. A lock file would trade that for a stale lock wedging a
   * boot, which on this product is the worse failure.
   *
   * A FAILED WRITE IS NOT FATAL AND MUST NOT BE. This runs immediately after a
   * revocation was accepted, on the path to exiting. Throwing here would turn a
   * full disk into a revoked process that stayed alive, so the failure is
   * reported by the caller's logger and the exit proceeds.
   */
  save(floor: EpochFloor): void {
    // The sentinel is not a floor. Writing it would mean recording "I have
    // nothing", which is what an absent file already says, and doing it after a
    // real floor was stored would erase it.
    if (floor === NO_PERSISTED_FLOOR) return;

    const current = this.load();
    if (current.ok && current.floor !== NO_PERSISTED_FLOOR && current.floor >= floor) return;

    mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    const body: FloorFile = {
      version: FORMAT_VERSION,
      tokenIdHash: this.#tokenIdHashHex,
      epochFloor: floor,
    };
    // Written to a sibling and renamed over the target. A partially written
    // file is the one corruption this code can cause itself, and it would
    // refuse the next boot; the rename makes that unreachable.
    const temporary = `${this.#path}.${process.pid}.tmp`;
    const handle = openSync(temporary, "w", 0o600);
    try {
      writeSync(handle, JSON.stringify(body));
    } finally {
      closeSync(handle);
    }
    try {
      renameSync(temporary, this.#path);
    } catch (error) {
      try {
        unlinkSync(temporary);
      } catch {
        // Nothing to do. A stray temp file is untidy and harmless; it is never
        // read, because only the exact path is ever loaded.
      }
      throw error;
    }
  }

  #corrupt(why: string): string {
    return (
      `The stored revocation epoch floor at ${this.#path} is unusable because ${why}. ` +
      "Sluice is refusing to start rather than treating it as a first boot, because that " +
      "would silently accept a replay of any revocation notice this token has already " +
      "acted on. If this really is a first boot, delete the file. If it is not, understand " +
      "that deleting it reopens that replay window before you do."
    );
  }
}
