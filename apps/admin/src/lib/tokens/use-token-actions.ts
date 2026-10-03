import { useCallback } from "react";
import { useConvex, useMutation, useQuery } from "convex/react";
import { ConvexError } from "convex/values";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";
import { revocationKeyMatches, unwrapRevocationKey } from "@/lib/orgs/revocation-key";
import type { EnvironmentKey } from "@/lib/secrets/pdk";
import { issueToken, signTokenRevocation } from "./token-crypto";
import type { IssuedToken, TokenTarget } from "./token-crypto";

/**
 * CREATING AND REVOKING TOKENS, AND THE ORG KEY EVERY SNIPPET PINS.
 *
 * Both writes do their cryptography here, in the browser, and send the
 * server only what it is allowed to hold. Each returns a sentence for a person
 * on failure rather than throwing, so a page shows it beside the button.
 */

export type ActionResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly message: string };

function messageOf(error: unknown, fallback: string): string {
  if (error instanceof ConvexError && typeof error.data === "string") return error.data;
  if (error instanceof Error && error.message !== "") return error.message;
  return fallback;
}

/** The org's revocation public key, pinned in every snippet. `undefined` while loading. */
export function useOrgRevocationKey(): string | null | undefined {
  const { session } = useAuth();
  const { org } = useCurrentOrg();
  const row = useQuery(
    api.orgs.getOrg,
    session === null || org === null ? "skip" : { sessionToken: session.sessionToken, orgId: org.orgId },
  );
  if (row === undefined) return undefined;
  return row?.revocationPublicKey ?? null;
}

export function useCreateToken() {
  const { session } = useAuth();
  const create = useMutation(api.tokens.createServiceToken);
  return useCallback(
    async (input: {
      readonly environmentId: string;
      readonly environmentName: string;
      readonly key: EnvironmentKey;
      readonly name: string;
      readonly target: TokenTarget;
    }): Promise<ActionResult<{ token: IssuedToken; serviceTokenId: string }>> => {
      if (session === null) return { ok: false, message: "Sign in again to create a token." };
      try {
        const issued = await issueToken(input);
        const serviceTokenId = await create({
          sessionToken: session.sessionToken,
          environmentId: input.environmentId as Id<"environments">,
          ...issued.args,
        });
        return { ok: true, value: { token: issued.token, serviceTokenId } };
      } catch (error) {
        return { ok: false, message: messageOf(error, "The token could not be created. Try again.") };
      }
    },
    [session, create],
  );
}

export function useRevokeToken() {
  const { session, muk } = useAuth();
  const { org } = useCurrentOrg();
  const convex = useConvex();
  const revoke = useMutation(api.tokens.revokeServiceToken);
  return useCallback(
    async (input: { readonly tokenIdHex: string; readonly reason: string }): Promise<ActionResult<null>> => {
      if (session === null || org === null) return { ok: false, message: "Sign in again to revoke a token." };
      if (muk === null) return { ok: false, message: "Unlock with your password to revoke a token." };
      let revocationKey: Uint8Array | null = null;
      try {
        const grant = await convex.query(api.orgs.getMyRevocationGrant, {
          sessionToken: session.sessionToken,
          orgId: org.orgId,
        });
        revocationKey = await unwrapRevocationKey(muk, grant, { orgUid: grant.orgUid, granteeUid: session.userUid });
        // The one check the associated data cannot make: that this key is the
        // one every process verifies against. See `revocationKeyMatches`.
        if (!revocationKeyMatches(revocationKey, grant.revocationPublicKey)) {
          return {
            ok: false,
            message: "Your copy of the organisation's revocation key does not match the one on record, so nothing was signed.",
          };
        }
        const args = signTokenRevocation({
          revocationKey,
          tokenIdHex: input.tokenIdHex,
          reason: input.reason,
          now: Date.now(),
        });
        await revoke({ sessionToken: session.sessionToken, ...args });
        return { ok: true, value: null };
      } catch (error) {
        return { ok: false, message: messageOf(error, "The token could not be revoked. Try again.") };
      } finally {
        revocationKey?.fill(0);
      }
    },
    [session, muk, org, convex, revoke],
  );
}
