import { ConvexError } from "convex/values";
import type { ConvexReactClient } from "convex/react";
import type { MasterUnlockKey } from "@sluice/crypto";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { PdkUnwrapError, unwrapProjectDataKey } from "./pdk";
import type { EnvironmentKey } from "./pdk";

/**
 * ONE ENVIRONMENT'S KEY, FETCHED AND OPENED, AS A STATE A SCREEN CAN RENDER.
 *
 * The steps and checks every hook that hands out an {@link EnvironmentKey}
 * goes through, lifted out of `useProjectDataKey` unchanged so that
 * `useEnvironmentKeys` loads a whole project's keys the same way. What the
 * unwrap proves, what it cannot, and why this is a one-shot fetch rather than
 * a subscription are stated in the header of `use-project-data-key.ts`.
 *
 * It never throws: every outcome, including a refusal and a transport
 * failure, comes back as a {@link ProjectDataKeyState}.
 */

export type ProjectDataKeyState =
  /** No environment selected, or no session yet. Nothing to fetch. */
  | { readonly status: "idle" }
  /** A session exists and the vault does not. The password reopens it. */
  | { readonly status: "locked" }
  | { readonly status: "loading" }
  | { readonly status: "ready"; readonly key: EnvironmentKey }
  /**
   * The server declined to hand over a grant. Its own sentence is carried
   * through rather than replaced, because the server has more than one reason
   * and both of its messages are already written for a person: the shared
   * refusal for a member with no grant, and a distinct one for a session that
   * has expired.
   */
  | { readonly status: "refused"; readonly message: string }
  /**
   * The caller holds a grant, for a key generation the environment has moved
   * past (or not yet reached). A state of its own rather than `refused`,
   * because `refused` tells the user they hold no key, which is not what is
   * happening, and rather than `failed`, because nothing is broken: waiting
   * is the fix. No key is handed out, so no write form renders.
   */
  | { readonly status: "rekeying"; readonly message: string }
  /** The grant arrived and did not open, or the call did not complete. */
  | { readonly status: "failed"; readonly message: string };

/** The one method of the Convex client the loader uses, so a test can stand in for it. */
export type KeyQueryClient = Pick<ConvexReactClient, "query">;

export interface EnvironmentKeyRequest {
  readonly sessionToken: string;
  readonly environmentId: Id<"environments">;
  /**
   * The `uid` of this environment's row in the `listEnvironments` result the
   * selection was made from, or `null` when there is no such row yet. Compared
   * with what `getEnvironment` says. Both come from the same server; see the
   * hook's header for why that is a bug check and not a defence.
   */
  readonly listedEnvironmentUid: string | null;
  /** The caller's PERMANENT `usr_` uid. User grants are keyed and bound by it. */
  readonly userUid: string;
  readonly muk: MasterUnlockKey;
}

/** The server's answers about one environment disagreed. See the check that uses it. */
const INCONSISTENT =
  "The server's answers about this environment did not agree with each other, so its key was not opened. Reload the page.";

/**
 * The grant and the environment are at different key generations.
 *
 * The hook fetches once and does not retry, so the sentence says how to try
 * again rather than promising that something will. This blocks READS as well
 * as writes: the old key could probably still open rows not yet re-sealed, but
 * no re-key exists yet to say which. Whoever builds re-keying should revisit
 * this, for example by handing out a read-only key for the older generation.
 */
const REKEYING =
  "This environment is being re-keyed. Reload the page in a moment to try again.";

export async function loadEnvironmentKey(
  client: KeyQueryClient,
  request: EnvironmentKeyRequest,
): Promise<ProjectDataKeyState> {
  const { sessionToken, environmentId, listedEnvironmentUid, userUid, muk } = request;
  try {
    // In parallel: neither depends on the other, and both are needed
    // before anything can be opened.
    const [environment, grant] = await Promise.all([
      client.query(api.environments.getEnvironment, { sessionToken, environmentId }),
      client.query(api.environments.getMyPdkGrant, { sessionToken, environmentId }),
    ]);

    // THE SERVER'S ANSWERS MUST AGREE WITH EACH OTHER AND WITH THE
    // SELECTION. Each is the server's word, so agreement proves nothing
    // against a server that lies consistently (see the hook's header); what it
    // does is turn a server bug, or one answer for the wrong row, into a
    // named failure instead of a key opened for one environment and shown
    // under another. Checked before the unwrap, so a mismatch never gets
    // as far as a key.
    if (
      environment.environmentId !== environmentId ||
      grant.environmentId !== environmentId ||
      (listedEnvironmentUid !== null && environment.uid !== listedEnvironmentUid)
    ) {
      return { status: "failed", message: INCONSISTENT };
    }

    // MID RE-KEY. The grant is for one key generation and the environment
    // is at another, so a key opened from this grant would seal writes the
    // server refuses with "This environment's key changed since you opened
    // it", and a reload would fetch the same pair and loop on that
    // refusal. No key is handed out, so no form renders, and the state
    // says what is happening instead.
    if (environment.pdkVersion !== grant.pdkVersion) {
      return { status: "rekeying", message: REKEYING };
    }

    const pdk = await unwrapProjectDataKey(
      muk,
      { wrappedPDK: grant.wrappedPDK, nonce: grant.nonce },
      {
        environmentUid: environment.uid,
        pdkVersion: grant.pdkVersion,
        // The caller's OWN identity. `getMyPdkGrant` takes no grantee
        // argument, so this is the only grantee the blob can belong to,
        // and the associated data would not verify for any other.
        granteeType: "user",
        granteeId: userUid,
      },
    );
    // The uid and version this grant was wrapped for, carried with the key
    // from here on. See `pdk.ts` for what that does and does not prove.
    return {
      status: "ready",
      key: { pdk, environmentUid: environment.uid, pdkVersion: grant.pdkVersion },
    };
  } catch (cause) {
    if (cause instanceof ConvexError && typeof cause.data === "string") {
      return { status: "refused", message: cause.data };
    }
    if (cause instanceof PdkUnwrapError) {
      return { status: "failed", message: cause.message };
    }
    // Anything else is a transport failure, a malformed uid or version
    // that `pdkAssociatedData` refused before the unwrap, or a bug. It gets
    // a generic sentence: a raw error string on this surface is noise at
    // best, and the thrown value may carry ciphertext.
    return {
      status: "failed",
      message: "The key for this environment could not be fetched. Try again.",
    };
  }
}
