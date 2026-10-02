import { useMutation } from "convex/react";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import type { AddRequest } from "@/lib/projects/project-context";
import { newSecretSlot, sealSecret } from "@/lib/secrets/seal";
import { sealSharedSecret } from "@/lib/secrets/shared";
import type { SharedSecretEnvironment } from "@/lib/secrets/shared";
import type { ProjectSecrets } from "@/lib/secrets/use-project-secrets";
import { AddSecretDrawer } from "./add-secret-drawer";
import type { AddSecretPlan } from "./add-secret-drawer";

type Ready = Extract<ProjectSecrets, { status: "ready" }>;

export interface Added {
  readonly name: string;
  readonly secretIds: readonly string[];
}

/**
 * THE ADD-SECRET DRAWER, WIRED TO THE TWO CREATE MUTATIONS.
 *
 * "All environments" seals once per environment under each one's own key and
 * writes every row in one `createSharedSecret`; "Only <env>" seals one row
 * with `createSecret`. Rendered once by the app shell, so Overview, Secrets
 * and Compare all open the same drawer.
 */
export function AddSecretFlow({
  data,
  request,
  onClose,
}: {
  readonly data: Ready;
  readonly request: AddRequest;
  readonly onClose: (added?: Added) => void;
}) {
  const { session } = useAuth();
  const createSecret = useMutation(api.secrets.createSecret);
  const createSharedSecret = useMutation(api.secrets.createSharedSecret);

  const current =
    data.environments.find((environment) => environment.environmentId === request.environmentId) ??
    data.environment;
  if (current === null) return null;

  const save = async (plan: AddSecretPlan): Promise<Added> => {
    if (session === null) throw new Error("Not ready.");
    const sessionToken = session.sessionToken;
    const keyOf = (environmentId: string) => {
      const state = data.keys.get(environmentId);
      if (state?.status !== "ready") throw new Error("A key is not open.");
      return state.key;
    };
    if (plan.scope === "all") {
      const payload = await sealSharedSecret({
        name: plan.name,
        value: plan.value,
        environments: data.environments.map((environment): SharedSecretEnvironment => {
          const own = plan.overrides.get(environment.environmentId);
          const key = keyOf(environment.environmentId);
          return own === undefined
            ? { environmentId: environment.environmentId, key }
            : { environmentId: environment.environmentId, key, override: own };
        }),
      });
      const rows = await createSharedSecret({
        sessionToken,
        projectId: data.project.projectId,
        shareUid: payload.shareUid,
        rows: payload.rows.map((row) => ({ ...row, environmentId: row.environmentId as Id<"environments"> })),
      });
      return { name: plan.name, secretIds: rows.map((row) => row.secretId) };
    }
    const key = keyOf(current.environmentId);
    const slot = newSecretSlot();
    const sealed = await sealSecret(key, { ...slot, name: plan.name, value: plan.value });
    const created = await createSecret({
      sessionToken,
      environmentId: current.environmentId,
      secretUid: slot.secretUid,
      version: slot.version,
      pdkVersion: key.pdkVersion,
      ...sealed,
    });
    return { name: plan.name, secretIds: [created.secretId] };
  };

  return (
    <AddSecretDrawer
      environments={data.environments}
      current={current}
      keys={data.keys}
      namesByEnvironment={data.namesByEnvironment}
      onSave={save}
      onClose={onClose}
      {...(request.name === undefined ? {} : { initialName: request.name, initialScope: "only" as const })}
    />
  );
}
