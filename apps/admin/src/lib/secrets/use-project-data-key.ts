import { useEffect, useState } from "react";
import type { MasterUnlockKey } from "@sluice/crypto";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import { convexClient } from "@/lib/convex-provider";
import { loadEnvironmentKey } from "./environment-key";
import type { ProjectDataKeyState } from "./environment-key";

export { loadEnvironmentKey } from "./environment-key";
export type { ProjectDataKeyState } from "./environment-key";

/**
 * THE PROJECT DATA KEY FOR THE SELECTED ENVIRONMENT, OR AN HONEST REASON THERE
 * IS NONE.
 *
 * It fetches the environment and the caller's own grant, and opens the grant
 * with the master unlock key. Everything downstream of it, every secret name
 * on screen, every revealed value, every secret written, depends on this one
 * key, and there is no other route to it.
 *
 * THE GRANT IS OPENED FOR ONE EXACT SLOT. Its associated data names the
 * environment's permanent uid, the key version, and the grantee, and all three
 * are supplied here rather than trusted from the blob:
 *
 *   environmentUid  `uid` off `environments.getEnvironment`. The ENVIRONMENT'S
 *                   record, never a column on a secret row.
 *   pdkVersion      the grant's own `pdkVersion` off `getMyPdkGrant`.
 *   grantee         `"user"` and `session.userUid`, the caller's permanent
 *                   `usr_` id. Never `session.userId`, the Convex document id,
 *                   which no grant is keyed by and `pdkAssociatedData` refuses
 *                   by shape.
 *
 * WHAT THE UNWRAP PROVES, SCOPED EXACTLY. Every input above except the grantee
 * arrived from the server. A successful unwrap proves only that this user once
 * wrapped this key for that uid, that version and this grantee: a uid the
 * server invented, or a grant moved onto another environment's row, does not
 * open. The ready state hands out an {@link EnvironmentKey} carrying that uid
 * and version beside the key, so everything sealed or opened from it is bound
 * to them and to no others.
 *
 * It does NOT prove that the uid is the environment the user SELECTED, or the
 * one named on screen. A hostile server asked about "production" can answer
 * with staging's uid and this user's genuine staging grant; the unwrap
 * succeeds, the pane says production, and writes are sealed into staging. The
 * checks below catch the server's answers DISAGREEING (with each other, with
 * the selected id, with the listing the selection came from), which turns a
 * server bug into a clean failure. They cannot catch a server that lies
 * consistently, because every one of those answers is the server's word. See
 * `pdk.ts` and "WHAT PINNING THE CONSTRUCTION DOES NOT PIN" in
 * `packages/crypto/src/protocol.ts`; pinning name to uid on the client is
 * follow-up work.
 *
 * WHY THIS IS A ONE-SHOT FETCH RATHER THAN `useQuery`, which is what every
 * other read in this dashboard uses. Two reasons, and the first is the one that
 * forces it.
 *
 *   1. `useQuery` RE-THROWS. A member of an org who holds no grant is a normal,
 *      expected state, it is the state of every colleague because nothing wraps
 *      an existing key to a second member, and `getMyPdkGrant` answers them
 *      with a refusal. Through `useQuery` that refusal becomes an exception
 *      thrown during render, which takes down the pane and, without an error
 *      boundary, the route. A state that common must be a value this surface
 *      can render, not a crash.
 *   2. A grant is not live data. It changes when the environment is re-keyed
 *      and at no other time, so a subscription buys a redraw nobody will ever
 *      observe, in exchange for putting key material on a reactive channel.
 *      The cost is stated rather than hidden: if another client re-keys this
 *      environment, this tab keeps the key it opened until the selection
 *      changes or the page is reloaded, and its writes are refused by the
 *      server with "This environment's key changed since you opened it",
 *      which the forms show as written, with a way to reload.
 *
 * THE KEY NEVER LEAVES MEMORY. It is not persisted, not logged, and not held in
 * a ref that outlives the selection: the stored result is TAGGED with the
 * environment and the master unlock key it belongs to and is discarded during
 * render the moment either changes, so a key from the previous environment is
 * unrenderable rather than merely short-lived.
 *
 * The fetch, the consistency checks and the unwrap themselves live in
 * `environment-key.ts`, shared with `useEnvironmentKeys`, so a whole
 * project's keys are loaded with exactly the steps one environment's key is.
 */

/** A settled result, tagged with what it belongs to. See the header. */
interface Settled {
  readonly environmentId: Id<"environments">;
  readonly muk: MasterUnlockKey;
  readonly state: ProjectDataKeyState;
}

const IDLE: ProjectDataKeyState = { status: "idle" };
const LOADING: ProjectDataKeyState = { status: "loading" };

/**
 * `listedEnvironmentUid` is the `uid` of the selected row in the
 * `listEnvironments` result the selection was made from, or `null` when there
 * is no such row yet. It is compared with what `getEnvironment` says, as one of
 * the consistency checks in the loader. Both come from the same server; see
 * the header for why that is a bug check and not a defence.
 */
export function useProjectDataKey(
  environmentId: Id<"environments"> | null,
  listedEnvironmentUid: string | null,
): ProjectDataKeyState {
  const { session, muk, locked } = useAuth();
  const sessionToken = session?.sessionToken ?? null;
  // The PERMANENT uid. See the header: user grants are keyed and bound by it.
  const userUid = session?.userUid ?? null;

  const [settled, setSettled] = useState<Settled | null>(null);

  // Whether there is anything to fetch at all, decided during render. Nothing
  // below writes state synchronously from the effect, which would cascade a
  // second render pass on every selection.
  const fetchable =
    environmentId !== null && sessionToken !== null && userUid !== null && muk !== null;

  useEffect(() => {
    if (!fetchable || environmentId === null || sessionToken === null || userUid === null) return;
    if (muk === null) return;
    if (convexClient === null) return;
    const client = convexClient;

    // `cancelled` rather than an AbortController: the work that must not land
    // is the `setState`, not the request.
    let cancelled = false;

    void loadEnvironmentKey(client, {
      sessionToken,
      environmentId,
      listedEnvironmentUid,
      userUid,
      muk,
    }).then((state) => {
      if (!cancelled) setSettled({ environmentId, muk, state });
    });

    return () => {
      cancelled = true;
    };
  }, [fetchable, environmentId, listedEnvironmentUid, sessionToken, userUid, muk]);

  if (environmentId === null || sessionToken === null || userUid === null) return IDLE;
  if (muk === null) {
    // Signed in, vault shut. Not an error and not a loading state: the user has
    // to type their password, and the right hand panel is where they do.
    return locked ? { status: "locked" } : IDLE;
  }
  if (convexClient === null) {
    return { status: "failed", message: "This build has no Convex deployment URL." };
  }
  // The tag check. Reference equality on `muk` is the point: locking and
  // unlocking produces a different key object, so a project data key opened
  // before the lock is never served after it.
  if (settled === null || settled.environmentId !== environmentId || settled.muk !== muk) {
    return LOADING;
  }
  return settled.state;
}
