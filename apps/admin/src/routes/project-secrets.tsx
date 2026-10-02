import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useMutation } from "convex/react";
import { AddSecretDrawer } from "@/components/secrets/add-secret-drawer";
import type { AddSecretPlan } from "@/components/secrets/add-secret-drawer";
import { PageHeader } from "@/components/shell/page-header";
import { api } from "@convex/_generated/api";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Callout, Skeleton } from "@/components/ui/feedback";
import { IconCopy, IconEye, IconEyeOff, IconMore, IconPlus, IconSearch } from "@/components/ui/icons";
import { Menu, MenuItem } from "@/components/ui/menu";
import { ScopePill } from "@/components/ui/pill";
import { Segmented } from "@/components/ui/segmented";
import { focusRing, pageGutter } from "@/components/ui/styles";
import { useAuth } from "@/lib/auth/auth-context";
import { useProject } from "@/lib/projects/project-context";
import { useShell } from "@/lib/shell/shell-context";
import { VALUE_MASK, openSecretValue } from "@/lib/secrets/decrypt";
import type { ProjectDataKeyState } from "@/lib/secrets/environment-key";
import type { LabelledRow } from "@/lib/secrets/project-secrets";
import { countScopes } from "@/lib/secrets/scope";
import type { SecretScope } from "@/lib/secrets/scope";
import type { EnvironmentRow, ListedSecret, ProjectSecrets } from "@/lib/secrets/use-project-secrets";
import { newSecretSlot, sealSecret } from "@/lib/secrets/seal";
import { sealSharedSecret } from "@/lib/secrets/shared";
import type { SharedSecretEnvironment } from "@/lib/secrets/shared";
import { describeWriteFailure } from "@/lib/secrets/write-errors";
import { listOf } from "@/lib/list-of";
import type { Id } from "@convex/_generated/dataModel";

/**
 * ONE PROJECT'S SECRETS, ONE ENVIRONMENT AT A TIME.
 *
 * Names are shown; a value is opened only when somebody presses its eye, and
 * masked again on a second press or after 30 seconds. The mask is a fixed
 * width, so it does not publish a value's length.
 *
 * Every row says where it applies. The label is computed from the row's whole
 * group across the project (see `lib/secrets/scope.ts`), not from the row:
 * "All environments" is only said when every environment has the secret.
 *
 * Deleting a row of a shared secret deletes the whole secret from every
 * environment (`deleteSharedSecret`); the confirmation says so.
 */

const REVEAL_MS = 30_000;

/** Revealed plaintext for one environment, by secret id. */
interface Revealed {
  readonly environmentId: string;
  readonly values: ReadonlyMap<string, string>;
  readonly failed: ReadonlySet<string>;
}

const EMPTY_VALUES: ReadonlyMap<string, string> = new Map();
const EMPTY_FAILED: ReadonlySet<string> = new Set();
/** How long a just-added row stays marked. */
const HIGHLIGHT_MS = 4_000;

type Ready = Extract<ProjectSecrets, { status: "ready" }>;
type Filter = "all" | SecretScope;

export default function ProjectSecretsRoute() {
  const { slug: projectSlug, data } = useProject();
  const { announce } = useShell();
  const { session } = useAuth();
  const deleteSecret = useMutation(api.secrets.deleteSecret);
  const deleteSharedSecret = useMutation(api.secrets.deleteSharedSecret);
  const createSecret = useMutation(api.secrets.createSecret);
  const createSharedSecret = useMutation(api.secrets.createSharedSecret);

  const reveal = async (secret: ListedSecret) => {
    if (data.status !== "ready" || data.keyState.status !== "ready") {
      throw new Error("No key for this environment.");
    }
    return openSecretValue(data.keyState.key, secret);
  };

  const remove = async (row: LabelledRow<ListedSecret>) => {
    if (session === null || data.status !== "ready") return;
    const sessionToken = session.sessionToken;
    // A row with a share id is one row of a secret that lives in every
    // environment, so it is deleted everywhere; `deleteSecret` refuses such a
    // row on the server.
    if (row.secret.shareUid !== undefined) {
      await deleteSharedSecret({ sessionToken, projectId: data.project.projectId, shareUid: row.secret.shareUid });
    } else {
      await deleteSecret({ sessionToken, secretId: row.secret.secretId });
    }
  };

  const [adding, setAdding] = useState(false);
  const [highlight, setHighlight] = useState<ReadonlySet<string>>(new Set());
  useEffect(() => {
    if (highlight.size === 0) return;
    const timer = setTimeout(() => setHighlight(new Set()), HIGHLIGHT_MS);
    return () => clearTimeout(timer);
  }, [highlight]);

  const save = async (plan: AddSecretPlan) => {
    if (session === null || data.status !== "ready" || data.environment === null) {
      throw new Error("Not ready.");
    }
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
    const environmentId = data.environment.environmentId;
    const key = keyOf(environmentId);
    const slot = newSecretSlot();
    const sealed = await sealSecret(key, { ...slot, name: plan.name, value: plan.value });
    const created = await createSecret({
      sessionToken,
      environmentId,
      secretUid: slot.secretUid,
      version: slot.version,
      pdkVersion: key.pdkVersion,
      ...sealed,
    });
    return { name: plan.name, secretIds: [created.secretId] };
  };

  const ready = data.status === "ready" && data.environment !== null ? data : null;

  return (
    <>
      <PageHeader
        title="Secrets"
        crumbs={[{ label: data.status === "ready" ? data.project.name : projectSlug, to: `/projects/${projectSlug}` }]}
      />
      <div className={pageGutter}>
        <ProjectSecretsView
          slug={projectSlug}
          data={data}
          onReveal={reveal}
          onDelete={remove}
          onAnnounce={announce}
          highlight={highlight}
          toolbarAction={
            ready === null ? undefined : (
              <Button icon={<IconPlus className="size-3.5" />} onClick={() => setAdding(true)}>
                Add secret
              </Button>
            )
          }
        />
      </div>
      {adding && ready !== null && ready.environment !== null ? (
        <AddSecretDrawer
          environments={ready.environments}
          current={ready.environment}
          keys={ready.keys}
          namesByEnvironment={ready.namesByEnvironment}
          onSave={save}
          onClose={(saved) => {
            setAdding(false);
            if (saved !== undefined) {
              setHighlight(new Set(saved.secretIds));
              announce(`Added ${saved.name}.`);
            }
          }}
        />
      ) : null}
    </>
  );
}

/** The page from its data and actions, with no queries of its own. */
export function ProjectSecretsView({
  slug,
  data,
  onReveal,
  onDelete,
  onAnnounce,
  toolbarAction,
  highlight,
}: {
  readonly slug: string;
  readonly data: ProjectSecrets;
  readonly onReveal: (secret: ListedSecret) => Promise<string>;
  readonly onDelete: (row: LabelledRow<ListedSecret>) => Promise<void>;
  /** Says a result out loud, through the page's one live region. */
  readonly onAnnounce: (message: string) => void;
  /** The page's primary action, beside the environment switcher. */
  readonly toolbarAction?: ReactNode | undefined;
  /** Secret ids to mark as just added. */
  readonly highlight?: ReadonlySet<string> | undefined;
}) {
  if (data.status === "loading") return <LoadingPage />;
  if (data.status === "not-found") {
    return (
      <div className="py-10">
        <div className="flex flex-col items-center gap-5 rounded-card border border-dashed border-hairline-strong px-6 py-16 text-center">
          <div className="flex flex-col gap-2">
            <h1 className="m-0 text-xl font-semibold text-text-primary">No project called “{slug}”</h1>
            <p className="m-0 text-sm text-text-muted">It may have been renamed, or it belongs to another organisation.</p>
          </div>
          <Button to="/projects" variant="secondary">
            Back to projects
          </Button>
        </div>
      </div>
    );
  }
  return (
    <ReadyPage
      data={data}
      onReveal={onReveal}
      onDelete={onDelete}
      onAnnounce={onAnnounce}
      toolbarAction={toolbarAction}
      highlight={highlight}
    />
  );
}

function LoadingPage() {
  return (
    <div role="status" aria-label="Loading secrets" className="flex flex-col gap-[18px] py-6 sm:py-8">
      <div className="flex items-center justify-between gap-4">
        <Skeleton className="h-[54px] w-full max-w-[360px] rounded-[10px]" />
      </div>
      <SkeletonRows />
    </div>
  );
}

function SkeletonRows() {
  return (
    <div aria-hidden="true" className="overflow-hidden rounded-card border border-hairline">
      <div className="hidden h-10 bg-surface-panel md:block" />
      {[0, 1, 2, 3, 4].map((index) => (
        <div key={index} className="flex items-center gap-6 border-t border-hairline px-4 py-4 first:border-t-0 md:px-[18px] md:first:border-t">
          <Skeleton className="h-3.5 w-40" />
          <Skeleton className="hidden h-3.5 w-28 md:block" />
          <Skeleton className="ml-auto h-[26px] w-32 rounded-full" />
        </div>
      ))}
    </div>
  );
}

function keyProblem(keyState: ProjectDataKeyState, environmentName: string): { title: string; body: string } | null {
  switch (keyState.status) {
    case "refused":
      return { title: `You don't hold the key for ${environmentName}`, body: keyState.message };
    case "rekeying":
      return { title: `${environmentName} is being re-keyed`, body: keyState.message };
    case "failed":
      return { title: `The key for ${environmentName} could not be opened`, body: keyState.message };
    default:
      return null;
  }
}

function ReadyPage({
  data,
  onReveal,
  onDelete,
  onAnnounce,
  toolbarAction,
  highlight,
}: {
  readonly data: Ready;
  readonly onReveal: (secret: ListedSecret) => Promise<string>;
  readonly onDelete: (row: LabelledRow<ListedSecret>) => Promise<void>;
  readonly onAnnounce: (message: string) => void;
  readonly toolbarAction?: ReactNode | undefined;
  readonly highlight?: ReadonlySet<string> | undefined;
}) {
  const { environment, environments, rows, keyState, counts } = data;
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  /**
   * REVEALED PLAINTEXT, AND THE ONLY PLACE ANY OF IT LIVES: held here, keyed
   * by secret id, and TAGGED with the environment it was opened in. The tag is
   * checked during render, so switching environment shows every row masked at
   * once (no frame of the old environment's values, and no row that thinks it
   * is already revealed), and a reveal that resolves after a switch is dropped.
   */
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [pending, setPending] = useState<LabelledRow<ListedSecret> | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const list = useRef<HTMLDivElement>(null);
  /** The environment on screen now, for a reveal that resolves after a switch. */
  const shownEnvironment = useRef<string | null>(null);
  useEffect(() => {
    shownEnvironment.current = data.environment?.environmentId ?? null;
  });

  if (environment === null) {
    return (
      <div className="py-8">
        <Callout title="This project has no environments">Secrets live in an environment, and this project has none.</Callout>
      </div>
    );
  }

  const envName = environment.name;
  const environmentId = environment.environmentId;
  const current = revealed !== null && revealed.environmentId === environmentId ? revealed : null;
  const values = current?.values ?? EMPTY_VALUES;
  const failed = current?.failed ?? EMPTY_FAILED;

  const update = (change: (values: Map<string, string>, failed: Set<string>) => void) =>
    setRevealed((previous) => {
      const base = previous !== null && previous.environmentId === environmentId ? previous : null;
      const nextValues = new Map(base?.values ?? []);
      const nextFailed = new Set(base?.failed ?? []);
      change(nextValues, nextFailed);
      return { environmentId, values: nextValues, failed: nextFailed };
    });

  const hide = (secretId: string) => update((v) => v.delete(secretId));
  const reveal = async (secret: ListedSecret) => {
    try {
      const value = await onReveal(secret);
      if (shownEnvironment.current !== environmentId) return;
      update((v, f) => {
        v.set(secret.secretId, value);
        f.delete(secret.secretId);
      });
    } catch {
      update((_v, f) => f.add(secret.secretId));
    }
  };
  const problem = keyProblem(keyState, envName);
  const scopeCounts = rows === undefined ? null : countScopes(rows.map((row) => ({ ...row.secret, partial: row.scope === "partial" })), (row) => !row.partial);
  const needle = query.trim().toLowerCase();
  const shown =
    rows?.filter(
      (row) =>
        (filter === "all" || row.scope === filter) &&
        (needle === "" || (row.name ?? "").toLowerCase().includes(needle)),
    ) ?? [];

  const chips: { value: Filter; label: string; count: number }[] =
    scopeCounts === null
      ? []
      : [
          { value: "all" as const, label: "All", count: scopeCounts.all },
          { value: "shared" as const, label: "Shared", count: scopeCounts.shared },
          { value: "overridden" as const, label: "Overridden here", count: scopeCounts.overridden },
          { value: "only" as const, label: `Only ${envName}`, count: scopeCounts.only },
          { value: "partial" as const, label: "Missing somewhere", count: scopeCounts.partial },
        ].filter((chip) => chip.value === "all" || chip.count > 0);

  const confirmDelete = async () => {
    if (pending === null) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await onDelete(pending);
      const name = pending.name ?? "The secret";
      onAnnounce(
        pending.secret.shareUid === undefined ? `Deleted ${name} from ${envName}.` : `Deleted ${name} from all environments.`,
      );
      setPending(null);
      list.current?.focus();
    } catch (cause) {
      setDeleteError(describeWriteFailure(cause).message);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="flex flex-col gap-[18px] py-6 sm:py-8">
      <h1 className="sr-only">Secrets in {envName}</h1>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <Segmented
          label="Environment"
          value={environment.name}
          onChange={(name) => {
            data.selectEnvironment(name);
            setFilter("all");
          }}
          options={environments.map((row: EnvironmentRow) => {
            const count = counts.get(row.environmentId);
            return typeof count === "number"
              ? { value: row.name, label: row.name, count }
              : { value: row.name, label: row.name };
          })}
        />
        {toolbarAction}
      </div>

      {data.failedListings.length > 0 ? (
        <Callout tone="warning" title={`Secrets in ${data.failedListings.join(", ")} could not be listed`}>
          Shared secrets show as missing there until the page can check. Reload to try again.
        </Callout>
      ) : null}

      {problem !== null ? (
        <Callout tone="warning" title={problem.title}>
          {problem.body}
        </Callout>
      ) : rows === undefined ? (
        <div role="status" aria-label={`Loading secrets in ${envName}`}>
          <SkeletonRows />
        </div>
      ) : rows.length === 0 ? (
        <div className="flex flex-col items-center gap-5 rounded-card border border-dashed border-hairline-strong px-6 py-14 text-center">
          <div className="flex flex-col gap-2">
            <h2 className="m-0 text-lg font-semibold text-text-primary">No secrets in {envName} yet</h2>
            <p className="m-0 text-sm text-text-muted">Add one here, or set it for every environment at once.</p>
          </div>
          {toolbarAction}
        </div>
      ) : (
        <>
          <div className="flex flex-col-reverse gap-3 md:flex-row md:items-center md:justify-between">
            <div role="group" aria-label="Show" className="flex gap-2 overflow-x-auto pb-0.5">
              {chips.map((chip) => {
                const on = filter === chip.value;
                return (
                  <button
                    key={chip.value}
                    type="button"
                    aria-pressed={on}
                    onClick={() => setFilter(chip.value)}
                    className={`inline-flex min-h-11 shrink-0 cursor-pointer items-center md:min-h-0 ${focusRing} rounded-full`}
                  >
                    <span
                      className={`inline-flex h-[30px] items-center gap-1.5 rounded-full px-3 text-[13px] whitespace-nowrap transition-colors ${
                        on
                          ? "bg-text-primary font-medium text-surface-base"
                          : "border border-hairline-strong text-text-primary hover:bg-surface-card"
                      }`}
                    >
                      {chip.label} <span className={on ? "" : "text-text-muted"}>{chip.count}</span>
                    </span>
                  </button>
                );
              })}
            </div>
            <label className="flex h-11 w-full items-center gap-2 rounded-input border border-hairline-strong bg-surface-panel px-3 text-text-muted transition-colors focus-within:border-brand md:h-9 md:w-[260px]">
              <IconSearch className="size-3.5 shrink-0" />
              <span className="sr-only">Filter by key</span>
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Filter by key"
                className="h-full min-w-0 grow bg-transparent text-base text-text-primary outline-none placeholder:text-text-muted md:text-sm"
              />
            </label>
          </div>

          <div ref={list} tabIndex={-1} className="overflow-hidden rounded-card border border-hairline outline-none">
            <div
              aria-hidden="true"
              className="hidden h-10 grid-cols-[minmax(0,260px)_minmax(0,1fr)_minmax(0,230px)_44px] items-center gap-4 bg-surface-panel px-[18px] text-[13px] text-text-muted md:grid"
            >
              <span>Key</span>
              <span>Value</span>
              <span>Applies to</span>
              <span />
            </div>
            {shown.length === 0 ? (
              <div className="flex flex-col items-center gap-3 border-t border-hairline px-6 py-10 text-center first:border-t-0 md:first:border-t">
                <p className="m-0 text-sm text-text-primary">No secrets match.</p>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setQuery("");
                    setFilter("all");
                  }}
                >
                  Show all
                </Button>
              </div>
            ) : (
              <ul aria-label={`Secrets in ${envName}`} className="m-0 list-none p-0">
                {shown.map((row) => (
                  <SecretItem
                    key={row.secret.secretId}
                    row={row}
                    environmentName={envName}
                    highlighted={highlight?.has(row.secret.secretId) === true}
                    value={values.get(row.secret.secretId) ?? null}
                    failed={failed.has(row.secret.secretId)}
                    onShow={() => reveal(row.secret)}
                    onHide={() => hide(row.secret.secretId)}
                    onCopy={async () => {
                      const label = row.name ?? "the secret";
                      try {
                        await navigator.clipboard.writeText(await onReveal(row.secret));
                        onAnnounce(`Copied the value of ${label}.`);
                      } catch {
                        onAnnounce(`The value of ${label} could not be copied.`);
                      }
                    }}
                    onDelete={() => {
                      setDeleteError(null);
                      setPending(row);
                    }}
                  />
                ))}
              </ul>
            )}
          </div>
          {/* Only where it explains something on screen. */}
          {rows.some((row) => row.secret.shareUid !== undefined) ? (
            <p className="m-0 text-[13px] text-text-muted">
              Shared secrets have one value in every environment. Override one to give {envName} its own value; the
              others keep the shared one.
            </p>
          ) : null}
        </>
      )}

      <ConfirmDialog
        open={pending !== null}
        title={
          pending?.secret.shareUid === undefined
            ? `Delete ${pending?.name ?? "this secret"} from ${envName}?`
            : "Delete from all environments?"
        }
        confirmLabel="Delete"
        busy={deleting}
        error={deleteError}
        onConfirm={() => void confirmDelete()}
        onClose={() => setPending(null)}
      >
        {pending?.secret.shareUid === undefined ? (
          "Anything that reads it from this environment stops getting it. This cannot be undone."
        ) : (
          <>
            <span className="font-mono text-text-primary">{pending.name ?? "This secret"}</span> is shared, so it
            is removed from {listOf(environments.map((row) => row.name))}, including any overridden values. This
            cannot be undone.
          </>
        )}
      </ConfirmDialog>
    </div>
  );
}

function SecretItem({
  row,
  environmentName,
  highlighted,
  value,
  failed,
  onShow,
  onHide,
  onCopy,
  onDelete,
}: {
  readonly row: LabelledRow<ListedSecret>;
  readonly environmentName: string;
  readonly highlighted: boolean;
  /** The revealed plaintext, or `null` while masked. Held by the page, not here. */
  readonly value: string | null;
  readonly failed: boolean;
  readonly onShow: () => Promise<void>;
  readonly onHide: () => void;
  readonly onCopy: () => Promise<void>;
  readonly onDelete: () => void;
}) {
  const sealed = row.name === undefined;
  const label = row.name ?? "sealed secret";

  // Masks again on its own after 30 seconds.
  const revealedNow = value !== null;
  const hideLatest = useRef(onHide);
  useEffect(() => {
    hideLatest.current = onHide;
  });
  useEffect(() => {
    if (!revealedNow) return;
    const timer = setTimeout(() => hideLatest.current(), REVEAL_MS);
    return () => clearTimeout(timer);
  }, [revealedNow]);

  return (
    <li
      className={`grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 border-t border-hairline py-1.5 pr-2 pl-4 transition-colors first:border-t-0 md:min-h-[52px] md:grid-cols-[minmax(0,260px)_minmax(0,1fr)_minmax(0,230px)_44px] md:gap-x-4 md:pl-[18px] md:first:border-t ${
        highlighted ? "bg-brand-subtle" : ""
      }`}
    >
      {/* Phone: key and actions on line one; value, reveal and scope on line two. */}
      <span
        className={`min-w-0 truncate font-mono text-[13px] ${sealed ? "text-text-muted italic" : "text-text-primary"}`}
        title={row.name}
      >
        {row.name ?? `sealed ${row.secret.secretUid.slice(0, 12)}`}
      </span>

      <span className="col-start-1 row-start-2 flex min-w-0 items-center gap-1 md:col-start-2 md:row-start-1">
        <span
          className={`min-w-0 font-mono text-[13px] ${
            value === null
              ? "truncate tracking-[0.12em] text-text-muted"
              : value === ""
                ? "text-text-muted"
                : "break-all text-text-primary"
          }`}
        >
          {/* A revealed empty string would otherwise render as nothing, which looks broken. */}
          {value === "" ? "Empty value" : (value ?? (failed ? "Could not be opened" : VALUE_MASK))}
        </span>
        <button
          type="button"
          aria-label={value === null ? `Show value of ${label}` : `Hide value of ${label}`}
          aria-pressed={value !== null}
          disabled={sealed}
          onClick={() => (value === null ? void onShow() : onHide())}
          className={`inline-flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-input text-text-muted transition-colors hover:bg-surface-card hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40 ${focusRing}`}
        >
          {value === null ? <IconEye className="size-[15px]" /> : <IconEyeOff className="size-[15px]" />}
        </button>
      </span>

      <span className="col-start-2 row-start-2 flex min-w-0 justify-end md:col-start-3 md:row-start-1 md:justify-start">
        <ScopePill scope={row.scope} environmentName={environmentName} missingIn={row.missingIn} />
      </span>

      <span className="col-start-2 row-start-1 flex justify-end md:col-start-4">
        <Menu
          label={`Actions for ${label}`}
          align="end"
          triggerClassName="inline-flex size-11 cursor-pointer items-center justify-center rounded-input text-text-muted transition-colors hover:bg-surface-card hover:text-text-primary"
          trigger={<IconMore className="size-4" />}
        >
          {sealed ? null : (
            <MenuItem onSelect={() => void onCopy()}>
              <IconCopy className="size-4 text-text-muted" />
              Copy value
            </MenuItem>
          )}
          <MenuItem tone="danger" onSelect={onDelete}>
            {row.secret.shareUid === undefined ? "Delete" : "Delete from all environments"}
          </MenuItem>
        </Menu>
      </span>
    </li>
  );
}
