import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { useQuery } from "convex/react";
import { useNavigate } from "react-router";
import { api } from "@convex/_generated/api";
import { IconActivity, IconColumns, IconFolder, IconKey, IconLayers, IconOverview, IconPlus, IconSearch } from "@/components/ui/icons";
import { useAuth } from "@/lib/auth/auth-context";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";
import type { ProjectScope } from "@/lib/projects/project-context";
import { buildMatrix } from "@/lib/secrets/compare";
import { linkForRow } from "@/lib/secrets/links";
import { rank } from "@/lib/search/rank";

/**
 * ⌘K / CTRL+K: JUMP ANYWHERE.
 *
 * A native `<dialog>` opened with `showModal()`, so the page behind is inert,
 * focus is held, and Escape closes it for free. The input is an ARIA combobox
 * over a listbox: the arrow keys move the active option
 * (`aria-activedescendant`), Enter goes there, and focus never leaves the
 * input.
 *
 * What it finds: the current project's pages and environments, its secret
 * KEYS (names this browser opened; never a value), the org's projects, and
 * "New project". Ranking is `lib/search/rank.ts`.
 */

interface Result {
  readonly id: string;
  readonly group: "Pages" | "Environments" | "Secrets" | "Projects";
  readonly label: string;
  readonly keywords?: readonly string[];
  readonly hint?: string;
  readonly icon: ReactNode;
  readonly to: string;
}

const GROUP_LIMIT = 6;
const ICON = "size-4 shrink-0 text-text-muted";

export function CommandPalette({
  open,
  onClose,
  scope,
}: {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly scope: ProjectScope | null;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  const navigate = useNavigate();
  const { session } = useAuth();
  const { org } = useCurrentOrg();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  const projects = useQuery(
    api.projects.listProjects,
    !open || session === null || org === null ? "skip" : { sessionToken: session.sessionToken, orgId: org.orgId },
  );

  useEffect(() => {
    const element = dialog.current;
    if (element === null) return;
    if (open && !element.open) {
      element.showModal();
      input.current?.focus();
    } else if (!open && element.open) {
      element.close();
    }
  }, [open]);

  const data = scope?.data.status === "ready" ? scope.data : null;
  const all = useMemo((): Result[] => {
    const out: Result[] = [];
    if (scope !== null) {
      const base = `/projects/${scope.slug}`;
      const name = data?.project.name ?? scope.slug;
      out.push(
        { id: "page-overview", group: "Pages", label: "Overview", hint: name, icon: <IconOverview className={ICON} />, to: base, keywords: ["home", "checklist"] },
        { id: "page-secrets", group: "Pages", label: "Secrets", hint: name, icon: <IconKey className={ICON} />, to: `${base}/secrets`, keywords: ["keys", "values", "env"] },
        { id: "page-compare", group: "Pages", label: "Compare", hint: name, icon: <IconColumns className={ICON} />, to: `${base}/compare`, keywords: ["matrix", "missing", "diff"] },
        { id: "page-activity", group: "Pages", label: "Activity", hint: name, icon: <IconActivity className={ICON} />, to: `${base}/activity`, keywords: ["audit", "log", "history"] },
      );
      for (const environment of data?.environments ?? []) {
        out.push({
          id: `env-${environment.environmentId}`,
          group: "Environments",
          label: environment.name,
          hint: "Secrets",
          icon: <IconLayers className={ICON} />,
          to: `${base}/secrets?env=${encodeURIComponent(environment.name)}`,
        });
      }
      if (data !== null) {
        for (const row of buildMatrix(data.listings, data.namesByEnvironment).rows) {
          out.push({
            id: `key-${row.name}`,
            group: "Secrets",
            label: row.name,
            hint: row.cells.filter((cell) => cell.secret !== undefined).map((cell) => cell.environmentName).join(", "),
            icon: <IconKey className={ICON} />,
            // By opaque id: a name never goes into a URL.
            to: linkForRow(scope.slug, row),
          });
        }
      }
    }
    for (const project of projects ?? []) {
      out.push({
        id: `project-${project.projectId}`,
        group: "Projects",
        label: project.name,
        icon: <IconFolder className={ICON} />,
        to: `/projects/${project.slug}`,
      });
    }
    out.push(
      { id: "all-projects", group: "Projects", label: "All projects", icon: <IconFolder className={ICON} />, to: "/projects" },
      { id: "new-project", group: "Projects", label: "New project", keywords: ["create"], icon: <IconPlus className={ICON} />, to: "/projects/new" },
    );
    return out;
  }, [scope, data, projects]);

  const results = useMemo(() => {
    const ranked = rank(all, query);
    // With nothing typed, a few of each; typed, the best of everything, grouped.
    const limit = query.trim() === "" ? 4 : GROUP_LIMIT;
    const counts = new Map<string, number>();
    const kept = ranked.filter((result) => {
      const count = counts.get(result.group) ?? 0;
      counts.set(result.group, count + 1);
      return count < limit;
    });
    const order = ["Pages", "Secrets", "Environments", "Projects"];
    return [...kept].sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group));
  }, [all, query]);
  const current = Math.min(active, Math.max(results.length - 1, 0));
  useEffect(() => {
    document.getElementById(`${listId}-option-${current}`)?.scrollIntoView({ block: "nearest" });
  }, [current, listId]);

  const go = (result: Result | undefined) => {
    if (result === undefined) return;
    onClose();
    void navigate(result.to);
  };

  const groups: { name: string; items: { result: Result; index: number }[] }[] = [];
  results.forEach((result, index) => {
    const last = groups[groups.length - 1];
    if (last?.name === result.group) last.items.push({ result, index });
    else groups.push({ name: result.group, items: [{ result, index }] });
  });
  const optionId = (index: number) => `${listId}-option-${index}`;

  return createPortal(
    <dialog
      ref={dialog}
      aria-label="Search"
      onClose={() => {
        setQuery("");
        setActive(0);
        if (open) onClose();
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
      className="mx-auto mt-[12vh] w-[min(560px,calc(100vw-32px))] overflow-hidden rounded-modal border border-hairline-strong bg-surface-panel p-0 text-text-body backdrop:bg-surface-base/70 light:backdrop:bg-text-primary/40"
    >
      <div className="flex items-center gap-2.5 border-b border-hairline px-4">
        <IconSearch className="size-4 shrink-0 text-text-muted" />
        <input
          ref={input}
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={results.length === 0 ? undefined : optionId(current)}
          aria-label="Search pages, projects, environments and keys"
          placeholder="Search pages, projects, environments and keys"
          autoComplete="off"
          spellCheck={false}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(0);
          }}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault();
              setActive(results.length === 0 ? 0 : (current + 1) % results.length);
            } else if (event.key === "ArrowUp") {
              event.preventDefault();
              setActive(results.length === 0 ? 0 : (current - 1 + results.length) % results.length);
            } else if (event.key === "Enter") {
              event.preventDefault();
              go(results[current]);
            }
          }}
          className="h-14 min-w-0 grow bg-transparent text-base text-text-primary outline-none placeholder:text-text-muted"
        />
        <kbd className="hidden shrink-0 rounded-[5px] border border-hairline px-1.5 py-0.5 font-mono text-[11px] text-text-faint sm:block">
          Esc
        </kbd>
      </div>
      <div id={listId} role="listbox" aria-label="Results" className="max-h-[min(420px,60vh)] overflow-y-auto p-1.5">
        {results.length === 0 ? (
          <p className="m-0 px-3 py-6 text-center text-sm text-text-muted">Nothing matches “{query.trim()}”.</p>
        ) : (
          groups.map((group) => (
            <div key={group.name} role="group" aria-labelledby={`${listId}-${group.name}`}>
              <div id={`${listId}-${group.name}`} role="presentation" className="px-3 pt-2.5 pb-1 text-xs font-medium text-text-muted">
                {group.name}
              </div>
              {group.items.map(({ result, index }) => (
                <div
                  key={result.id}
                  id={optionId(index)}
                  role="option"
                  aria-selected={index === current}
                  onMouseMove={() => setActive(index)}
                  onClick={() => go(result)}
                  className={`flex min-h-11 cursor-pointer items-center gap-2.5 rounded-input px-3 text-sm lg:min-h-9 lg:pointer-coarse:min-h-11 ${
                    index === current ? "bg-surface-card text-text-primary" : "text-text-body"
                  }`}
                >
                  {result.icon}
                  <span className={`min-w-0 truncate ${result.group === "Secrets" ? "font-mono text-[13px]" : ""}`}>
                    {result.label}
                  </span>
                  {result.hint === undefined ? null : (
                    <span className="ml-auto shrink-0 truncate pl-3 text-xs text-text-muted">{result.hint}</span>
                  )}
                </div>
              ))}
            </div>
          ))
        )}
      </div>
      <p role="status" className="sr-only">
        {open ? `${results.length} ${results.length === 1 ? "result" : "results"}` : ""}
      </p>
    </dialog>,
    document.body,
  );
}
