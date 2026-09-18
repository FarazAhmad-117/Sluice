import { useEffect, useState } from "react";
import { ConvexError } from "convex/values";
import type { MasterUnlockKey } from "@sluice/crypto";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import { convexClient } from "@/lib/convex-provider";
import { PdkUnwrapError, unwrapProjectDataKey } from "./pdk";

/**
 * THE PROJECT DATA KEY FOR THE SELECTED ENVIRONMENT, OR AN HONEST REASON THERE
 * IS NONE.
 *
 * It fetches the caller's own grant from `environments.getMyPdkGrant` and opens
 * it with the master unlock key. Everything downstream of it, every secret name
 * on screen, every revealed value, every secret written, depends on this one
 * key, and there is no other route to it.
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
 *      nonce and version checks rather than silently accepted.
 *
 * THE KEY NEVER LEAVES MEMORY. It is not persisted, not logged, and not held in
 * a ref that outlives the selection: the stored result is TAGGED with the
 * environment and the master unlock key it belongs to and is discarded during
 * render the moment either changes, so a key from the previous environment is
 * unrenderable rather than merely short-lived.
 */

export type ProjectDataKeyState =
  /** No environment selected, or no session yet. Nothing to fetch. */
  | { readonly status: "idle" }
  /** A session exists and the vault does not. The password reopens it. */
  | { readonly status: "locked" }
  | { readonly status: "loading" }
  | { readonly status: "ready"; readonly pdk: Uint8Array }
  /**
   * The server declined to hand over a grant. Its own sentence is carried
   * through rather than replaced, because the server has more than one reason
   * and both of its messages are already written for a person: the shared
   * refusal for a member with no grant, and a distinct one for a session that
   * has expired.
   */
  | { readonly status: "refused"; readonly message: string }
  /** The grant arrived and did not open, or the call did not complete. */
  | { readonly status: "failed"; readonly message: string };

/** A settled result, tagged with what it belongs to. See the header. */
interface Settled {
  readonly environmentId: Id<"environments">;
  readonly muk: MasterUnlockKey;
  readonly state: ProjectDataKeyState;
}

const IDLE: ProjectDataKeyState = { status: "idle" };
const LOADING: ProjectDataKeyState = { status: "loading" };

export function useProjectDataKey(
  environmentId: Id<"environments"> | null,
): ProjectDataKeyState {
  const { session, muk, locked } = useAuth();
  const sessionToken = session?.sessionToken ?? null;
  const userId = session?.userId ?? null;

  const [settled, setSettled] = useState<Settled | null>(null);

  // Whether there is anything to fetch at all, decided during render. Nothing
  // below writes state synchronously from the effect, which would cascade a
  // second render pass on every selection.
  const fetchable =
    environmentId !== null && sessionToken !== null && userId !== null && muk !== null;

  useEffect(() => {
    if (!fetchable || environmentId === null || sessionToken === null || userId === null) return;
    if (muk === null) return;
    if (convexClient === null) return;

    // `cancelled` rather than an AbortController: the work that must not land
    // is the `setState`, not the request.
    let cancelled = false;

    const settle = (state: ProjectDataKeyState) => {
      if (!cancelled) setSettled({ environmentId, muk, state });
    };

    void (async () => {
      try {
        const grant = await convexClient.query(api.environments.getMyPdkGrant, {
          sessionToken,
          environmentId,
        });
        const pdk = await unwrapProjectDataKey(
          muk,
          { wrappedPDK: grant.wrappedPDK, nonce: grant.nonce },
          // The caller's OWN identity. `getMyPdkGrant` takes no grantee
          // argument, so this is the only grantee the blob can belong to, and
          // the associated data would not verify for any other.
          { granteeType: "user", granteeId: userId },
        );
        settle({ status: "ready", pdk });
      } catch (cause) {
        if (cause instanceof ConvexError && typeof cause.data === "string") {
          settle({ status: "refused", message: cause.data });
          return;
        }
        if (cause instanceof PdkUnwrapError) {
          settle({ status: "failed", message: cause.message });
          return;
        }
        // Anything else is a transport failure or a bug. It gets a generic
        // sentence: a raw error string on this surface is noise at best, and
        // the thrown value may carry ciphertext.
        settle({
          status: "failed",
          message: "The key for this environment could not be fetched. Try again.",
        });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [fetchable, environmentId, sessionToken, userId, muk]);

  if (environmentId === null || sessionToken === null || userId === null) return IDLE;
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
