import { useEffect, useMemo, useState } from "react";
import type { MasterUnlockKey } from "@sluice/crypto";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import { convexClient } from "@/lib/convex-provider";
import { loadEnvironmentKey } from "./environment-key";
import type { ProjectDataKeyState } from "./environment-key";

/**
 * EVERY ENVIRONMENT KEY OF ONE PROJECT, EACH WITH ITS OWN HONEST STATE.
 *
 * A secret set for "All environments" is sealed once per environment, under
 * each environment's own key, so the add-secret drawer needs every key of the
 * project at once. Each one is loaded by {@link loadEnvironmentKey}, with
 * exactly the fetch, consistency checks and unwrap `useProjectDataKey` makes
 * for one; see that hook's header for what the unwrap proves and why it is a
 * one-shot fetch.
 *
 * `uid` on each input is the environment's `uid` from `listEnvironments`, and
 * is checked against what `getEnvironment` says, exactly as the single hook
 * checks `listedEnvironmentUid`.
 *
 * Returns `null` while `environments` is `undefined` (the list is still
 * loading), and otherwise one state per listed environment, keyed by its
 * Convex `environmentId`.
 *
 * TAGGED, LIKE THE SINGLE HOOK. Each settled state is stored with the master
 * unlock key and uid it was loaded under, and is ignored during render the
 * moment either no longer matches, so a key opened before a lock is never
 * served after it, and a key loaded for one listing is never served under a
 * changed one. Keys are memory only: never log, persist or serialise the map.
 */

interface Settled {
  readonly muk: MasterUnlockKey;
  readonly uid: string;
  readonly state: ProjectDataKeyState;
}

type Entry = readonly [environmentId: Id<"environments">, uid: string];

const IDLE: ProjectDataKeyState = { status: "idle" };
const LOADING: ProjectDataKeyState = { status: "loading" };
const LOCKED: ProjectDataKeyState = { status: "locked" };
const NO_DEPLOYMENT: ProjectDataKeyState = {
  status: "failed",
  message: "This build has no Convex deployment URL.",
};

export function useEnvironmentKeys(
  environments: readonly { environmentId: Id<"environments">; uid: string }[] | undefined,
): ReadonlyMap<string, ProjectDataKeyState> | null {
  const { session, muk, locked } = useAuth();
  const sessionToken = session?.sessionToken ?? null;
  // The PERMANENT uid: user grants are keyed and bound by it.
  const userUid = session?.userUid ?? null;

  // A value, not the array: `listEnvironments` hands back a new array on every
  // update, and the effect must re-run when the LIST changes, not its identity.
  // "null" while the list itself is still loading.
  const signature = JSON.stringify(
    environments?.map((environment): Entry => [environment.environmentId, environment.uid]) ??
      null,
  );

  const [settled, setSettled] = useState<ReadonlyMap<string, Settled>>(() => new Map());

  useEffect(() => {
    if (sessionToken === null || userUid === null || muk === null) return;
    if (convexClient === null) return;
    const client = convexClient;
    const entries = JSON.parse(signature) as Entry[] | null;
    if (entries === null) return;
    const listed = new Set<string>(entries.map(([environmentId]) => environmentId));

    // The work that must not land after a change is the `setState`.
    let cancelled = false;

    for (const [environmentId, uid] of entries) {
      void loadEnvironmentKey(client, {
        sessionToken,
        environmentId,
        listedEnvironmentUid: uid,
        userUid,
        muk,
      }).then((state) => {
        if (cancelled) return;
        setSettled((previous) => {
          // Drops anything settled under an earlier master unlock key, or for an
          // environment that has left the list, so no key lingers in state
          // longer than it can be served.
          const next = new Map<string, Settled>();
          for (const [id, value] of previous) {
            if (value.muk === muk && listed.has(id)) next.set(id, value);
          }
          next.set(environmentId, { muk, uid, state });
          return next;
        });
      });
    }

    return () => {
      cancelled = true;
    };
  }, [signature, sessionToken, userUid, muk]);

  return useMemo(() => {
    const entries = JSON.parse(signature) as Entry[] | null;
    // No list yet, so no answer yet: null, not an empty map, which would read
    // as "this project has no environments".
    if (entries === null) return null;
    const result = new Map<string, ProjectDataKeyState>();
    for (const [environmentId, uid] of entries) {
      let state: ProjectDataKeyState;
      if (sessionToken === null || userUid === null) state = IDLE;
      else if (muk === null) state = locked ? LOCKED : IDLE;
      else if (convexClient === null) state = NO_DEPLOYMENT;
      else {
        // The tag check. Reference equality on `muk` is the point: locking and
        // unlocking produces a different key object.
        const value = settled.get(environmentId);
        state = value !== undefined && value.muk === muk && value.uid === uid ? value.state : LOADING;
      }
      result.set(environmentId, state);
    }
    return result;
  }, [signature, settled, sessionToken, userUid, muk, locked]);
}
