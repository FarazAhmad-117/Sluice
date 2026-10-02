import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useQuery } from "convex/react";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { messageForUser } from "@/lib/auth/auth-errors";
import { useAuth } from "@/lib/auth/auth-context";
import { convexClient } from "@/lib/convex-provider";
import { personalOrgPayload } from "./personal-org";
import { pickOrg } from "./pick-org";

/**
 * THE ORG THE DASHBOARD IS LOOKING AT, AND THE PERSONAL ORG A NEW ACCOUNT GETS.
 *
 * The selection is the org id in `localStorage["sluice.org"]` when that org is
 * still in `listMyOrgs`, else the first org. It is a convenience only: it
 * names an id the server re-checks on every call, so a stale or edited value
 * just falls back to the first org.
 *
 * A NEW ACCOUNT HAS NO ORG. When the vault is unlocked and `listMyOrgs` comes
 * back empty, a "Personal" org is created once, in the browser (its
 * revocation key is minted and wrapped here; see `personal-org.ts`). "Once" is
 * enforced by a module-level in-flight promise keyed by the account, so React
 * StrictMode's double effect, or two components mounting this, cannot create
 * two. A slug collision (32 random bits, so rare) is retried once with a fresh
 * payload; any other failure is shown with a retry.
 *
 * The state is held by ONE provider (the app layout) and read with
 * {@link useCurrentOrg}, so the header's switcher and the page agree.
 */

export const ORG_STORAGE_KEY = "sluice.org";

export interface OrgRow {
  readonly orgId: Id<"orgs">;
  readonly uid: string;
  readonly name: string;
  readonly slug: string;
}

export type CurrentOrgStatus = "loading" | "creating" | "failed" | "ready";

export interface CurrentOrg {
  readonly org: OrgRow | null;
  readonly orgs: readonly OrgRow[] | undefined;
  setOrg(orgId: Id<"orgs">): void;
  readonly status: CurrentOrgStatus;
  /** Why creating the personal org failed, for a person. Only with `failed`. */
  readonly error: string | null;
  retry(): void;
}

function readStored(): string | null {
  try {
    return localStorage.getItem(ORG_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStored(orgId: string): void {
  try {
    localStorage.setItem(ORG_STORAGE_KEY, orgId);
  } catch {
    // Not remembered across reloads, and nothing else changes.
  }
}

/** One creation per account per page load. Cleared on failure so a retry can run. */
let inFlight: { readonly userUid: string; readonly promise: Promise<void> } | null = null;

export const CurrentOrgContext = createContext<CurrentOrg | null>(null);

export function useCurrentOrg(): CurrentOrg {
  const value = useContext(CurrentOrgContext);
  if (value === null) throw new Error("useCurrentOrg must be used inside the app layout");
  return value;
}

/** The state behind {@link CurrentOrgContext}. Call it once, in the layout. */
export function useCurrentOrgState(): CurrentOrg {
  const { session, muk } = useAuth();
  const sessionToken = session?.sessionToken ?? null;
  const userUid = session?.userUid ?? null;

  const orgs = useQuery(api.orgs.listMyOrgs, sessionToken === null ? "skip" : { sessionToken });
  const [storedId, setStoredId] = useState<string | null>(readStored);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  const empty = orgs !== undefined && orgs.length === 0;

  useEffect(() => {
    if (!empty || sessionToken === null || userUid === null || muk === null) return;
    if (convexClient === null) return;
    if (inFlight !== null && inFlight.userUid === userUid) return;
    const client = convexClient;

    const create = async () => {
      for (let tries = 0; ; tries += 1) {
        try {
          const payload = await personalOrgPayload(muk, userUid);
          const orgId = await client.mutation(api.orgs.createOrg, { sessionToken, ...payload });
          writeStored(orgId);
          setStoredId(orgId);
          return;
        } catch (cause) {
          // A second try mints a new uid, keypair and slug, so a collision on
          // any of them cannot repeat.
          if (tries === 0) continue;
          throw cause;
        }
      }
    };

    const promise = create().catch((cause: unknown) => {
      inFlight = null;
      setError(messageForUser(cause));
    });
    inFlight = { userUid, promise };
    // Not cancelled on unmount: the mutation is already on its way, and the
    // in-flight guard is what stops a second one.
  }, [empty, sessionToken, userUid, muk, attempt]);

  const setOrg = useCallback((orgId: Id<"orgs">) => {
    writeStored(orgId);
    setStoredId(orgId);
  }, []);

  const retry = useCallback(() => {
    setError(null);
    setAttempt((value) => value + 1);
  }, []);

  const status: CurrentOrgStatus =
    orgs === undefined ? "loading" : orgs.length > 0 ? "ready" : error !== null ? "failed" : "creating";

  return {
    org: orgs === undefined ? null : pickOrg(orgs, storedId),
    orgs,
    setOrg,
    status,
    error: status === "failed" ? error : null,
    retry,
  };
}
