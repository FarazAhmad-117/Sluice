import { useId, useMemo, useRef, useState } from "react";
import type { MouseEvent } from "react";
import { useMutation } from "convex/react";
import { Link, useSearchParams } from "react-router";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { EnvironmentChip } from "@/components/secrets/coverage";
import { EditSecretDrawer } from "@/components/secrets/edit-secret-drawer";
import type { EditChoice } from "@/components/secrets/edit-secret-drawer";
import { SecretDetailAside, SecretDetailSheet } from "@/components/secrets/secret-detail";
import type { DetailProps } from "@/components/secrets/secret-detail";
import { PageHeader, PhoneActionBar } from "@/components/shell/page-header";
import { NoEnvironments, ProjectNotFound } from "@/components/shell/project-states";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Drawer } from "@/components/ui/drawer";
import { Callout, Skeleton } from "@/components/ui/feedback";
import { IconCopy, IconEye, IconEyeOff, IconMore, IconPlus, IconSearch } from "@/components/ui/icons";
import { Menu, MenuDivider, MenuItem } from "@/components/ui/menu";
import { ScopePill } from "@/components/ui/pill";
import { Segmented } from "@/components/ui/segmented";
import { compactHeight, focusRing, pageGutter } from "@/components/ui/styles";
import { useAuth } from "@/lib/auth/auth-context";
import { formatDateTime, timeAgo } from "@/lib/format/time";
import { useNow } from "@/lib/format/use-now";
import { listOf } from "@/lib/list-of";
import { useProject, useProjectActions } from "@/lib/projects/project-context";
import { runCommand } from "@/lib/projects/run-command";
import { buildMatrix, rowFor } from "@/lib/secrets/compare";
import type { CompareCell, CompareRow } from "@/lib/secrets/compare";
import { VALUE_MASK, openSecretValue } from "@/lib/secrets/decrypt";
import { EditRefusal, editSecret } from "@/lib/secrets/edit-secret";
import type { EditOutcome, EditRequest } from "@/lib/secrets/edit-secret";
import type { ProjectDataKeyState } from "@/lib/secrets/environment-key";
import type { LabelledRow } from "@/lib/secrets/project-secrets";
import { countScopes } from "@/lib/secrets/scope";
import type { SecretScope } from "@/lib/secrets/scope";
import { useReveals } from "@/lib/secrets/use-reveals";
import type { Reveals } from "@/lib/secrets/use-reveals";
import type { EnvironmentRow, ListedSecret, ProjectSecrets } from "@/lib/secrets/use-project-secrets";
import { describeWriteFailure } from "@/lib/secrets/write-errors";
import { useShell } from "@/lib/shell/shell-context";
import { WIDE, useMediaQuery } from "@/lib/use-media-query";

/**
 * ONE PROJECT'S SECRETS, ONE ENVIRONMENT AT A TIME, WITH A DETAIL PANEL.
 *
 * Names are shown; a value is opened only when somebody presses its eye, and
 * masked again on a second press, after 30 seconds, or when the environment or
 * the selected key changes (`use-reveals.ts`). The mask is a fixed width, so
 * it does not publish a value's length.
 *
 * Every row says where it applies (its scope, computed from its whole group;
 * see `lib/secrets/scope.ts`) and where else the key exists (one chip per
 * environment, from the same matrix the Compare page draws).
 *
 * Selecting a row (`?key=<name>`) opens the detail panel: a column beside the
 * list at 1280px and up, a sheet below. Editing goes through
 * `lib/secrets/edit-secret.ts`; deleting a shared secret deletes it from every
 * environment, and the confirmation says so.
 */

type Ready = Extract<ProjectSecrets, { status: "ready" }>;
type Filter = "all" | SecretScope;
type Row = LabelledRow<ListedSecret>;

export default function ProjectSecretsRoute() {
  const { slug, data } = useProject();
  if (data.status === "not-found") return <ProjectNotFound slug={slug} title="Secrets" />;
  if (data.status === "loading") {
    return (
      <>
        <PageHeader title="Secrets" crumbs={[{ label: slug, to: `/projects/${slug}` }]} />
        <div role="status" aria-label="Loading secrets" className={`flex flex-col gap-4 py-6 ${pageGutter}`}>
          <Skeleton className="h-7 w-40" />
          <Skeleton className="h-4 w-80 max-w-full" />
          <Skeleton className="mt-2 h-10 w-72 max-w-full" />
          <SkeletonRows />
        </div>
      </>
    );
  }
  return <SecretsPage slug={slug} data={data} />;
}

function SkeletonRows() {
  return (
    <div aria-hidden="true" className="overflow-hidden rounded-card border border-hairline">
      <div className="hidden h-[38px] bg-surface-panel md:block" />
      {[0, 1, 2, 3, 4].map((index) => (
        <div key={index} className="flex items-center gap-6 border-t border-hairline px-4 py-4 first:border-t-0 md:first:border-t">
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

function capitalise(text: string): string {
  return text.slice(0, 1).toUpperCase() + text.slice(1);
}

/** The edit drawer's choices for a key: the shared value, and each environment's own. */
function editChoicesFor(row: CompareRow<ListedSecret>): { choices: EditChoice[]; byCell: Map<string, string> } {
  const choices: EditChoice[] = [];
  const byCell = new Map<string, string>();
  const shared = row.cells.filter((cell) => cell.kind === "shared");
  const own = row.cells.filter((cell) => cell.kind === "own");
  if (shared.length > 0) {
    choices.push({
      id: "shared",
      label: "Shared value",
      description:
        own.length === 0
          ? `Changes it in ${listOf(shared.map((cell) => cell.environmentName))}.`
          : `Changes it in ${listOf(shared.map((cell) => cell.environmentName))}. ${capitalise(listOf(own.map((cell) => cell.environmentName)))} ${own.length === 1 ? "keeps its" : "keep their"} own value.`,
    });
    for (const cell of shared) byCell.set(cell.environmentId, "shared");
  }
  for (const cell of row.cells) {
    if ((cell.kind === "own" || cell.kind === "set") && cell.secret !== undefined) {
      const id = `row:${cell.secret.secretId}`;
      choices.push({
        id,
        label: cell.kind === "own" ? `Own value in ${cell.environmentName}` : `Value in ${cell.environmentName}`,
        description: `Changes it in ${cell.environmentName} only.`,
      });
      byCell.set(cell.environmentId, id);
    }
  }
  return { choices, byCell };
}

function SecretsPage({ slug, data }: { readonly slug: string; readonly data: Ready }) {
  const { session } = useAuth();
  const { announce } = useShell();
  const { openAdd, highlight } = useProjectActions();
  const deleteSecret = useMutation(api.secrets.deleteSecret);
  const deleteSharedSecret = useMutation(api.secrets.deleteSharedSecret);
  const updateSecret = useMutation(api.secrets.updateSecret);
  const updateSharedSecret = useMutation(api.secrets.updateSharedSecret);
  const [params, setParams] = useSearchParams();
  const wide = useMediaQuery(WIDE);
  const now = useNow();
  const panelId = useId();

  const { environment, environments, rows, keyState, counts } = data;
  const selectedName = params.get("key");
  const matrix = useMemo(() => buildMatrix(data.listings, data.namesByEnvironment), [data.listings, data.namesByEnvironment]);
  const reveals = useReveals(`${environment?.environmentId ?? ""}|${selectedName ?? ""}`);

  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [pending, setPending] = useState<Row | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const keyButtons = useRef(new Map<string, HTMLButtonElement>());
  const closeButton = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);

  const addButton = (
    <Button size="sm" icon={<IconPlus className="size-3.5" />} onClick={() => openAdd()}>
      Add secret
    </Button>
  );
  const header = (
    <PageHeader
      title="Secrets"
      crumbs={[{ label: data.project.name, to: `/projects/${slug}` }]}
      actions={environment === null ? undefined : addButton}
    />
  );

  if (environment === null) {
    return (
      <>
        {header}
        <div className={`py-6 ${pageGutter}`}>
          <NoEnvironments />
        </div>
      </>
    );
  }

  const envName = environment.name;
  const select = (name: string | null) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (name === null) next.delete("key");
        else next.set("key", name);
        return next;
      },
      { replace: true },
    );
  const closeDetail = () => {
    const name = selectedName;
    select(null);
    if (name !== null) requestAnimationFrame(() => keyButtons.current.get(name)?.focus());
  };

  const keyOf = (environmentId: string) => {
    const state = data.keys.get(environmentId);
    return state?.status === "ready" ? state.key : null;
  };
  const openValue = async (secret: ListedSecret) => {
    const key = keyOf(secret.environmentId);
    if (key === null) throw new Error("No key for this environment.");
    return openSecretValue(key, secret);
  };

  const remove = async (row: Row) => {
    if (session === null) throw new Error("Your session is not ready. Reload the page.");
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
  const confirmDelete = async () => {
    if (pending === null) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await remove(pending);
      const name = pending.name ?? "The secret";
      announce(pending.secret.shareUid === undefined ? `Deleted ${name} from ${envName}.` : `Deleted ${name} from all environments.`);
      if (pending.name !== undefined && pending.name === selectedName) select(null);
      setPending(null);
      list.current?.focus();
    } catch (cause) {
      setDeleteError(describeWriteFailure(cause).message);
    } finally {
      setDeleting(false);
    }
  };

  const saveEdit = async (name: string, choiceId: string, value: string): Promise<EditOutcome> => {
    const matrixRow = rowFor(matrix, name);
    if (matrixRow === undefined) return { ok: false, message: "This key changed. Reload to see it.", reload: true };
    let request: EditRequest;
    if (choiceId === "shared") {
      const sharedCell = matrixRow.cells.find((cell) => cell.kind === "shared");
      const shareUid = sharedCell?.secret?.shareUid;
      if (shareUid === undefined) return { ok: false, message: "This key has no shared value any more.", reload: true };
      request = {
        kind: "shared",
        projectId: data.project.projectId,
        shareUid,
        name,
        value,
        rows: matrixRow.cells
          .filter((cell) => cell.secret?.shareUid === shareUid)
          .map((cell) => ({ row: cell.secret!, environmentName: cell.environmentName, key: keyOf(cell.environmentId) })),
      };
    } else {
      const cell = matrixRow.cells.find((candidate) => `row:${candidate.secret?.secretId}` === choiceId);
      if (cell?.secret === undefined) return { ok: false, message: "This value changed. Reload to see it.", reload: true };
      const key = keyOf(cell.environmentId);
      if (key === null) return { ok: false, message: `The key for ${cell.environmentName} is not open.`, reload: false };
      request = { kind: "row", key, row: cell.secret, name, value };
    }
    return editSecret(request, {
      updateSecret: (args) => {
        if (session === null) throw new EditRefusal("Your session is not ready. Reload the page.");
        return updateSecret({ sessionToken: session.sessionToken, ...args, secretId: args.secretId as Id<"secrets"> });
      },
      updateSharedSecret: (args) => {
        if (session === null) throw new EditRefusal("Your session is not ready. Reload the page.");
        return updateSharedSecret({
          sessionToken: session.sessionToken,
          projectId: args.projectId as Id<"projects">,
          shareUid: args.shareUid,
          rows: args.rows.map((edit) => ({ ...edit, secretId: edit.secretId as Id<"secrets"> })),
        });
      },
    });
  };

  const problem = keyProblem(keyState, envName);
  const scopeCounts =
    rows === undefined
      ? null
      : countScopes(rows.map((row) => ({ ...row.secret, partial: row.scope === "partial" })), (row) => !row.partial);
  const needle = query.trim().toLowerCase();
  const shown =
    rows?.filter(
      (row) => (filter === "all" || row.scope === filter) && (needle === "" || (row.name ?? "").toLowerCase().includes(needle)),
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

  const others = environments.filter((row) => row.environmentId !== environment.environmentId).map((row) => row.name);
  const sharedHere = rows?.filter((row) => row.secret.shareUid !== undefined).length ?? 0;
  const summary = [
    rows === undefined ? null : `${rows.length} in ${envName}`,
    rows === undefined || sharedHere === 0 || others.length === 0 ? null : `${sharedHere} shared with ${listOf(others)}`,
    "values open only in this browser",
  ].filter((part): part is string => part !== null);

  // The detail panel's data, for the selected key.
  const selected = rowFor(matrix, selectedName ?? undefined);
  const currentCell = selected?.cells.find((cell) => cell.environmentId === environment.environmentId);
  const currentRow = selected === undefined ? undefined : rows?.find((row) => row.name === selected.name);
  const reference = currentCell?.secret ?? selected?.cells.find((cell) => cell.secret !== undefined)?.secret;
  // `updatedAt` is the current row's creation time: an edit inserts a new row.
  const changedAt = reference?.updatedAt;
  const detail: DetailProps | null =
    selected === undefined
      ? null
      : {
          name: selected.name,
          scope: currentRow === undefined ? null : { scope: currentRow.scope, environmentName: envName, missingIn: currentRow.missingIn },
          cells: selected.cells,
          reveals,
          openValue: (cell: CompareCell<ListedSecret>) => openValue(cell.secret!),
          canOpen: (environmentId) => keyOf(environmentId) !== null,
          onAnnounce: announce,
          version: reference?.version ?? null,
          lastChanged: changedAt === undefined ? null : { label: timeAgo(changedAt, now), title: formatDateTime(changedAt) },
          secretUid: reference === undefined ? null : (reference.shareUid ?? reference.secretUid),
          onEdit: () => setEditing(selected.name),
          onDelete:
            currentRow === undefined
              ? null
              : () => {
                  setDeleteError(null);
                  setPending(currentRow);
                },
          deleteLabel: currentRow?.secret.shareUid === undefined ? "Delete" : "Delete everywhere",
          onAddHere: (environmentId) => openAdd({ environmentId, name: selected.name }),
          runCommand: runCommand(slug, envName),
          runEnvironment: envName,
        };
  const editingRow = editing === null ? undefined : rowFor(matrix, editing);
  const editing$ = editingRow === undefined ? null : editChoicesFor(editingRow);

  const letters = environments.map((row) => row.name.slice(0, 1).toUpperCase());

  return (
    <>
      {header}
      <div className="flex min-h-0 grow">
        <div className={`flex min-w-0 grow flex-col gap-4 py-6 ${pageGutter}`}>
          <div className="flex flex-col gap-1">
            <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">Secrets</h1>
            <p className="m-0 text-text-muted">{summary.join(" · ")}</p>
          </div>

          <Segmented
            variant="underline"
            label="Environment"
            value={envName}
            onChange={(name) => {
              data.selectEnvironment(name);
              setFilter("all");
            }}
            options={environments.map((row: EnvironmentRow) => {
              const count = counts.get(row.environmentId);
              return typeof count === "number" ? { value: row.name, label: row.name, count } : { value: row.name, label: row.name };
            })}
          />

          {data.failedListings.length > 0 ? (
            <Callout tone="warning" title={`Secrets in ${listOf(data.failedListings)} could not be listed`}>
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
              <Button icon={<IconPlus className="size-3.5" />} onClick={() => openAdd()}>
                Add secret
              </Button>
            </div>
          ) : (
            <>
              <Toolbar
                slug={slug}
                envName={envName}
                query={query}
                onQuery={setQuery}
                chips={chips}
                filter={filter}
                onFilter={setFilter}
              />
              <div ref={list} tabIndex={-1} className="relative overflow-hidden rounded-card border border-hairline outline-none">
                <TableHead environmentCount={environments.length} />
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
                      <SecretRow
                        key={row.secret.secretId}
                        row={row}
                        environmentName={envName}
                        environmentCount={environments.length}
                        coverage={row.name === undefined ? undefined : rowFor(matrix, row.name)}
                        selected={row.name !== undefined && row.name === selectedName}
                        highlighted={highlight.has(row.secret.secretId)}
                        panelId={panelId}
                        reveals={reveals}
                        onOpen={() => openValue(row.secret)}
                        canOpen={keyOf(environment.environmentId) !== null}
                        onSelect={() => {
                          if (row.name === undefined) return;
                          select(row.name === selectedName ? null : row.name);
                          if (wide) requestAnimationFrame(() => closeButton.current?.focus({ preventScroll: true }));
                        }}
                        keyButton={(element) => {
                          if (row.name === undefined) return;
                          if (element === null) keyButtons.current.delete(row.name);
                          else keyButtons.current.set(row.name, element);
                        }}
                        onCopy={async () => {
                          const label = row.name ?? "the secret";
                          try {
                            await navigator.clipboard.writeText(await openValue(row.secret));
                            announce(`Copied the value of ${label}.`);
                          } catch {
                            announce(`The value of ${label} could not be copied.`);
                          }
                        }}
                        onEdit={row.name === undefined ? null : () => setEditing(row.name!)}
                        onDelete={() => {
                          setDeleteError(null);
                          setPending(row);
                        }}
                      />
                    ))}
                  </ul>
                )}
              </div>
              <p className="m-0 text-[13px] text-text-muted">
                {listOf(letters)} show where each key exists: filled is the value that environment uses, amber is
                an own value, dashed means the environment does not have it.
              </p>
            </>
          )}
        </div>

        {wide && detail !== null ? (
          <SecretDetailAside props={detail} panelId={panelId} onClose={closeDetail} closeRef={closeButton} />
        ) : null}
      </div>

      <PhoneActionBar>
        <Button size="lg" icon={<IconPlus className="size-4" />} className="w-full" onClick={() => openAdd()}>
          Add secret
        </Button>
      </PhoneActionBar>

      {!wide && detail !== null ? (
        <Drawer open title={<span className="font-mono break-all">{detail.name}</span>} onClose={closeDetail}>
          <SecretDetailSheet props={detail} />
        </Drawer>
      ) : null}

      {editing !== null && editingRow !== undefined && editing$ !== null && editing$.choices.length > 0 ? (
        <EditSecretDrawer
          name={editing}
          choices={editing$.choices}
          initialChoice={editing$.byCell.get(environment.environmentId) ?? editing$.choices[0]!.id}
          onSave={(choiceId, value) => saveEdit(editing, choiceId, value)}
          onClose={(saved) => {
            setEditing(null);
            if (saved !== undefined) announce(`Saved a new value for ${editing}: ${saved.label.toLowerCase()}.`);
          }}
        />
      ) : null}

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
            <span className="font-mono text-text-primary">{pending.name ?? "This secret"}</span> is shared, so it is
            removed from {listOf(environments.map((row) => row.name))}, including any overridden values. This cannot be
            undone.
          </>
        )}
      </ConfirmDialog>
    </>
  );
}

function Toolbar({
  slug,
  envName,
  query,
  onQuery,
  chips,
  filter,
  onFilter,
}: {
  readonly slug: string;
  readonly envName: string;
  readonly query: string;
  readonly onQuery: (query: string) => void;
  readonly chips: readonly { value: Filter; label: string; count: number }[];
  readonly filter: Filter;
  readonly onFilter: (filter: Filter) => void;
}) {
  return (
    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <div className="flex min-w-0 flex-col gap-2 md:flex-row md:items-center">
        <label
          className={`flex ${compactHeight} w-full shrink-0 items-center gap-2 rounded-input border border-hairline-strong bg-surface-panel px-2.5 text-text-muted transition-colors focus-within:border-brand md:w-[260px]`}
        >
          <IconSearch className="size-3.5 shrink-0" />
          <span className="sr-only">Filter by key</span>
          <input
            type="search"
            value={query}
            onChange={(event) => onQuery(event.target.value)}
            placeholder="Filter by key"
            className="h-full min-w-0 grow bg-transparent text-base text-text-primary outline-none placeholder:text-text-muted md:text-[13px]"
          />
        </label>
        <div role="group" aria-label="Show" className="flex gap-2 overflow-x-auto pb-0.5 md:pb-0">
          {chips.map((chip) => {
            const on = filter === chip.value;
            return (
              <button
                key={chip.value}
                type="button"
                aria-pressed={on}
                onClick={() => onFilter(chip.value)}
                className={`inline-flex min-h-11 shrink-0 cursor-pointer items-center rounded-full lg:min-h-0 lg:pointer-coarse:min-h-11 ${focusRing}`}
              >
                <span
                  className={`inline-flex h-[30px] items-center gap-1.5 rounded-full px-[11px] text-[13px] whitespace-nowrap transition-colors ${
                    on ? "bg-text-primary font-medium text-surface-base" : "border border-hairline-strong text-text-primary hover:bg-surface-card"
                  }`}
                >
                  {chip.label} <span className={on ? "" : "text-text-muted"}>{chip.count}</span>
                </span>
              </button>
            );
          })}
        </div>
      </div>
      <nav aria-label="View" className="hidden shrink-0 gap-0.5 self-start rounded-input border border-hairline bg-surface-panel p-[3px] text-[13px] md:flex md:self-auto">
        <span aria-current="page" className="flex h-[26px] items-center rounded-[6px] bg-surface-card px-2.5 text-text-primary">
          List
        </span>
        <Link
          to={`/projects/${slug}/compare`}
          className={`flex h-[26px] items-center rounded-[6px] px-2.5 text-text-muted no-underline transition-colors hover:text-text-primary ${focusRing}`}
        >
          Compare
          <span className="sr-only"> {envName} with the other environments</span>
        </Link>
      </nav>
    </div>
  );
}

/** Key · Value · Applies to · Environments · Version · actions. */
function gridColumns(environmentCount: number): string {
  const chips = Math.max(110, environmentCount * 24 + 8);
  return `minmax(0,1.3fr) minmax(0,1fr) 190px ${chips}px 56px 44px`;
}

function TableHead({ environmentCount }: { readonly environmentCount: number }) {
  return (
    <div
      aria-hidden="true"
      style={{ gridTemplateColumns: gridColumns(environmentCount) }}
      className="hidden h-[38px] items-center gap-3 bg-surface-panel pr-2 pl-4 text-xs font-medium text-text-muted md:grid"
    >
      <span>Key</span>
      <span>Value</span>
      <span>Applies to</span>
      <span>Environments</span>
      <span>Version</span>
      <span />
    </div>
  );
}

/** Clicks on a row's own controls are theirs; any other click on the row selects it. */
function fromControl(event: MouseEvent): boolean {
  return event.target instanceof Element && event.target.closest("button, a, input, [role='menu']") !== null;
}

function SecretRow({
  row,
  environmentName,
  environmentCount,
  coverage,
  selected,
  highlighted,
  panelId,
  reveals,
  onOpen,
  canOpen,
  onSelect,
  keyButton,
  onCopy,
  onEdit,
  onDelete,
}: {
  readonly row: Row;
  readonly environmentName: string;
  readonly environmentCount: number;
  readonly coverage: CompareRow<ListedSecret> | undefined;
  readonly selected: boolean;
  readonly highlighted: boolean;
  readonly panelId: string;
  readonly reveals: Reveals;
  readonly onOpen: () => Promise<string>;
  readonly canOpen: boolean;
  readonly onSelect: () => void;
  readonly keyButton: (element: HTMLButtonElement | null) => void;
  readonly onCopy: () => Promise<void>;
  readonly onEdit: (() => void) | null;
  readonly onDelete: () => void;
}) {
  const sealed = row.name === undefined;
  const label = row.name ?? "sealed secret";
  const value = reveals.value(row.secret.secretId);
  const failed = reveals.failed(row.secret.secretId);

  const keyLabel = (
    <span className={`min-w-0 truncate font-mono text-[13px] ${sealed ? "text-text-muted italic" : "text-text-primary"}`}>
      {row.name ?? `sealed ${row.secret.secretUid.slice(0, 12)}`}
    </span>
  );
  const keyControl = sealed ? (
    <span className="flex min-h-11 min-w-0 items-center">{keyLabel}</span>
  ) : (
    <button
      ref={keyButton}
      type="button"
      aria-expanded={selected}
      aria-controls={selected ? panelId : undefined}
      onClick={onSelect}
      title={row.name}
      className={`-ml-1 flex min-h-11 min-w-0 cursor-pointer items-center rounded-input bg-transparent px-1 text-left md:min-h-9 lg:pointer-coarse:min-h-11 ${focusRing}`}
    >
      {keyLabel}
    </button>
  );
  const menu = (
    <Menu
      label={`Actions for ${label}`}
      align="end"
      triggerClassName="inline-flex size-11 cursor-pointer items-center justify-center rounded-input text-text-muted transition-colors hover:bg-surface-card hover:text-text-primary md:size-9 lg:pointer-coarse:size-11"
      trigger={<IconMore className="size-4" />}
    >
      {sealed || !canOpen ? null : (
        <MenuItem onSelect={() => void onCopy()}>
          <IconCopy className="size-4 text-text-muted" />
          Copy value
        </MenuItem>
      )}
      {onEdit === null || !canOpen ? null : <MenuItem onSelect={onEdit}>Edit value</MenuItem>}
      {sealed || !canOpen ? null : <MenuDivider />}
      <MenuItem tone="danger" onSelect={onDelete}>
        {row.secret.shareUid === undefined ? "Delete" : "Delete from all environments"}
      </MenuItem>
    </Menu>
  );
  const pill = <ScopePill scope={row.scope} environmentName={environmentName} missingIn={row.missingIn} />;

  return (
    <li
      onClick={(event) => {
        if (!fromControl(event) && !sealed) onSelect();
      }}
      className={`border-t border-hairline transition-colors first:border-t-0 md:first:border-t ${
        selected ? "bg-brand/8" : highlighted ? "bg-brand-subtle" : "hover:bg-surface-panel"
      } ${sealed ? "" : "cursor-pointer"}`}
    >
      {/* Phone: key and actions on line one; the mask and where it applies on line two. */}
      <div className="flex flex-col gap-1 py-2 pr-1 pl-4 md:hidden">
        <div className="flex items-center justify-between gap-2">
          {keyControl}
          {menu}
        </div>
        <div className="flex items-center justify-between gap-3 pr-3 pb-1">
          <span className="truncate font-mono text-[13px] tracking-[0.12em] text-text-muted">{VALUE_MASK}</span>
          {pill}
        </div>
      </div>

      <div
        style={{ gridTemplateColumns: gridColumns(environmentCount) }}
        className="hidden min-h-[50px] items-center gap-3 py-1 pr-2 pl-4 md:grid"
      >
        {keyControl}
        <span className="flex min-w-0 items-center gap-1">
          <span
            className={`min-w-0 font-mono text-[13px] ${
              value === undefined ? "overflow-hidden text-clip whitespace-nowrap tracking-[0.12em] text-text-muted" : value === "" ? "text-text-muted" : "break-all text-text-primary"
            }`}
          >
            {value === "" ? "Empty value" : (value ?? (failed ? "Could not be opened" : VALUE_MASK))}
          </span>
          <button
            type="button"
            aria-label={value === undefined ? `Show value of ${label}` : `Hide value of ${label}`}
            aria-pressed={value !== undefined}
            disabled={sealed || !canOpen}
            onClick={() => (value === undefined ? void reveals.reveal(row.secret.secretId, onOpen) : reveals.hide(row.secret.secretId))}
            className={`inline-flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-input text-text-muted transition-colors hover:bg-surface-card hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40 lg:pointer-coarse:size-11 ${focusRing}`}
          >
            {value === undefined ? <IconEye className="size-[15px]" /> : <IconEyeOff className="size-[15px]" />}
          </button>
        </span>
        <span className="flex min-w-0">{pill}</span>
        <span className="flex gap-1">
          {coverage?.cells.map((cell) => (
            <EnvironmentChip key={cell.environmentId} kind={cell.kind} environmentName={cell.environmentName} />
          )) ?? null}
        </span>
        <span className="font-mono text-xs text-text-muted">v{row.secret.version}</span>
        <span className="flex justify-end">{menu}</span>
      </div>
    </li>
  );
}
