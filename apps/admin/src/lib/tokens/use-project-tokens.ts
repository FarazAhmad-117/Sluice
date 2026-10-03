import { useEffect, useMemo, useState } from "react";
import { useQueries } from "convex/react";
import type { RequestForQueries } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import { useProjectScope } from "@/lib/projects/project-context";
import { openTokenMeta } from "./token-crypto";
import type { TokenTarget } from "./token-crypto";

/**
 * A PROJECT'S SERVICE TOKENS, WITH THEIR NAMES OPENED IN THIS BROWSER.
 *
 * `tokens.listProjectTokens` returns each token's name and id sealed under its
 * environment's key; the shell already holds those keys (the project scope),
 * so they are opened here and never fetched twice. A token whose details do
 * not open, or that predates them, is listed with `name: null` and cannot be
 * revoked from here, because revoking needs its id.
 *
 * `undefined` while loading, `null` when the listing failed.
 */

type Listed = FunctionReturnType<typeof api.tokens.listProjectTokens>[number];

export interface TokenRow {
  readonly serviceTokenId: string;
  readonly environmentId: string;
  readonly environmentName: string;
  readonly target: TokenTarget | null;
  readonly status: "active" | "revoked";
  readonly createdAt: number;
  readonly lastSeenAt: number | null;
  readonly expiresAt: number | null;
  readonly revokedAt: number | null;
  readonly createdByIsYou: boolean;
  readonly createdByEmail: string | null;
  /** `undefined` while opening, `null` when it cannot be opened. */
  readonly name: string | null | undefined;
  readonly tokenIdHex: string | null | undefined;
}

export function useProjectTokens(): readonly TokenRow[] | null | undefined {
  const { session } = useAuth();
  const scope = useProjectScope();
  const data = scope?.data.status === "ready" ? scope.data : null;
  const sessionToken = session?.sessionToken ?? null;
  const projectId = data?.project.projectId ?? null;

  const queries = useMemo((): RequestForQueries => {
    if (sessionToken === null || projectId === null) return {};
    return {
      tokens: { query: api.tokens.listProjectTokens, args: { sessionToken, projectId: projectId as Id<"projects"> } },
    };
  }, [sessionToken, projectId]);
  const result: unknown = useQueries(queries).tokens;
  const listed = Array.isArray(result) ? (result as Listed[]) : null;

  // Opened names and ids by token id. A sealed blob never changes for a given
  // token, so an opened entry stays valid for as long as the page lives.
  const [opened, setOpened] = useState<ReadonlyMap<string, { name: string; tokenIdHex: string } | null>>(new Map());
  const keys = data?.keys;

  useEffect(() => {
    if (listed === null || keys === undefined) return;
    let cancelled = false;
    const pending = listed.filter((row) => !opened.has(row.serviceTokenId));
    if (pending.length === 0) return;
    void (async () => {
      const next = new Map(opened);
      let changed = false;
      for (const row of pending) {
        if (row.sealed === null) {
          next.set(row.serviceTokenId, null);
          changed = true;
          continue;
        }
        const keyState = keys.get(row.environmentId);
        // Not ready yet: left for the next run, when the key arrives.
        if (keyState === undefined || keyState.status === "loading" || keyState.status === "idle") continue;
        if (keyState.status !== "ready") {
          next.set(row.serviceTokenId, null);
          changed = true;
          continue;
        }
        try {
          next.set(row.serviceTokenId, await openTokenMeta(keyState.key, row.sealed));
        } catch {
          next.set(row.serviceTokenId, null);
        }
        changed = true;
      }
      if (!cancelled && changed) setOpened(next);
    })();
    return () => {
      cancelled = true;
    };
  }, [listed, keys, opened]);

  const environments = data?.environments;
  const environmentNames = useMemo(
    () => new Map((environments ?? []).map((environment) => [environment.environmentId as string, environment.name])),
    [environments],
  );

  return useMemo(() => {
    if (result instanceof Error) return null;
    if (listed === null) return undefined;
    return listed.map((row): TokenRow => {
      const meta = opened.get(row.serviceTokenId);
      return {
        serviceTokenId: row.serviceTokenId,
        environmentId: row.environmentId,
        environmentName: environmentNames.get(row.environmentId) ?? "an environment",
        target: row.target,
        status: row.status,
        createdAt: row.createdAt,
        lastSeenAt: row.lastSeenAt,
        expiresAt: row.expiresAt,
        revokedAt: row.revokedAt,
        createdByIsYou: row.createdByIsYou,
        createdByEmail: row.createdByEmail,
        name: meta === undefined ? undefined : meta === null ? null : meta.name,
        tokenIdHex: meta === undefined ? undefined : meta === null ? null : meta.tokenIdHex,
      };
    });
  }, [result, listed, opened, environmentNames]);
}
