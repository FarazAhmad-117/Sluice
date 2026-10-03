# Dashboard Round 3: sidebar app — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Rebuild the dashboard into the approved Round 3 design: a sidebar app with a project Overview, a richer Secrets page (environment coverage per row, a detail panel with every environment's value, editing), a Compare view, a project Activity feed, and a phone layout with the sidebar as a drawer.

**Architecture:** Three backend additions (an `updatedAt` on listed secrets, a project activity query, and `updateSharedSecret` for editing a shared value everywhere at once), then a new app shell (sidebar + header with a page-actions slot) that every signed-in page renders inside, then four project pages. All numbers and labels come from real data; secret names in activity are decrypted in the browser from rows it already holds.

**Tech Stack:** as slice 1 (Convex + convex-test, React 19, react-router 7, Tailwind v4 tokens, Geist, Vitest).

**Builds on:** `docs/plans/2026-10-02-dashboard-projects-secrets.md` (slice 1, merged). Read its "Read this first": the commands, commit trailer, token map and product rules all still apply.

---

## The approved design

Mock files (static HTML; match structure, copy, hierarchy, spacing; tokens only, never hex):

```
C:\Users\Dell\AppData\Local\Temp\claude\e--Courses-Web-Development-Indepth-Solution-Sluice\3d8da39b-d3d0-44e1-ae66-3fe18063f339\scratchpad\sluice-directions\project\
  R3-Overview.dc.html   project overview
  R3-Secrets.dc.html    secrets + detail panel
  R3-Compare.dc.html    compare environments
  R3-Light.dc.html      secrets, light theme (proves the tokens)
  R3-Mobile.dc.html     phone: list, and the sidebar as a drawer
```

**Decisions already made**
- Sidebar items not built yet (Environments, Tokens, project Settings, org Activity/Members/Settings, Add environment) render with a small "Soon" badge, `aria-disabled="true"`, muted, not links. No dead routes.
- Overview checklist: "Create the project" and "Add your secrets" are detected from data. "Run your app with these secrets" expands inline to show the run command with Copy, and has a "Mark as done" link stored in localStorage per project (the user's own claim). "Connect production" shows "Soon". The counter reads "N of 4 done" honestly.
- No drop shadows (app.css rule). Popovers are separated by a border.
- The selected-row highlight is a background tint, never a colored left border.

---

## Backend

### Task B1: `updatedAt` on listed secrets, `createdAt` on projects
- `convex/secrets.ts`: `secretShape` gains `updatedAt: v.number()` = the current row's `_creationTime` (an update inserts a new row, so this is "last changed"). Add to `view()`. Test: after `updateSecret`, the listed row's `updatedAt` is ≥ the original's.
- `convex/projects.ts`: `getProject`/`listProjects` views gain `createdAt` (`_creationTime`). Test it.
- Update surface allowlist tests with a reason comment for each new field.

### Task B2: project activity query
- Read `convex/lib/audit.ts` and the `auditLog` schema first. Add `convex/activity.ts` with query `listProjectActivity({ sessionToken, projectId, limit? })` (default 30, max 100): `requireProject`; the newest audit events whose target belongs to this project (secrets via their environment's project; environments; the project itself), newest first, shaped `{ at: number, action: string, actorIsYou: boolean, actorEmail: string | null, targetKind: "secret" | "environment" | "project", targetId: string, environmentId: Id<"environments"> | null }`. Never return ciphertext. If no index makes this efficient, add one (e.g. by org + time) and filter by project in the handler, bounded reads. Tests: only this project's events; newest first; limit honoured; non-member refused; another org's events never appear. Add the function to `convex/unauthenticated.test.ts` and any "exports exactly" list.

### Task B3: `updateSharedSecret`
- `convex/secrets.ts`: mutation `updateSharedSecret({ sessionToken, projectId, shareUid, rows: [{ secretId, version, pdkVersion, nameCiphertext, nameNonce, valueCiphertext, valueNonce }] })` edits the SHARED value: `rows` must be exactly the group's current rows with `overridden === false` (else `SHARED_ROWS_MISMATCH`); per row: authorisation as in `createSharedSecret`, `version === current + 1` else the existing stale-version error, `pdkVersion` current, `assertSealed`, the nonce-reuse check `updateSecret` does; insert new versions copying `shareUid`/`overridden`, mark old superseded, all in one transaction. One `secret.update` event per row. Overridden rows keep using plain `updateSecret`. Tests: all shared rows advance together; an overridden row is untouched; missing/extra row → mismatch; stale version refused; cross-project refused.

---

## Frontend

### Task F1: app shell with sidebar
**Create** `components/shell/{app-shell,sidebar,org-switcher,project-switcher,account-menu,page-header}.tsx`; replace the header in `components/layout/app-layout.tsx` with the shell. Match the R3 mocks:
- Sidebar 240px, `bg-surface-panel`, right hairline. Top to bottom: org switcher (brand tile + name + chevrons → existing org menu); Search button with ⌘K hint (opens Task F6); "Project" label + project switcher (project routes only); nav (icon + label; active = `bg-surface-card` + text-primary + medium weight; counts right-aligned muted): Overview, Secrets, Compare, Environments (Soon), Tokens (Soon), Activity, Settings (Soon); "Environments" label + one row per environment (small square marker, name, count; links to that environment's secrets) + "Add environment" (Soon); spacer; Docs (link to the repo README until docs exist); account row (avatar initial, email, menu with theme + Sign out).
- Org-level routes (`/projects`, `/projects/new`) show org nav: Projects, Activity (Soon), Members (Soon), Settings (Soon).
- `PageHeader`: 56px bar, breadcrumb left, actions slot right.
- Below 1024px: no sidebar; a top bar with a menu button (opens the sidebar as a 300px left drawer: backdrop, focus trap, Escape), the page title, and a search button; 44px targets. Add `side="left"` to `components/ui/drawer.tsx`.
- The unlock gate covers the content area.

### Task F2: Overview page
**Create** `routes/project-overview.tsx`; `/projects/:slug` renders it (no longer redirects). Match `R3-Overview.dc.html`: project tile + name + "N environments · N secrets · created <relative>"; the checklist per "Decisions"; environment cards (secrets, shared, own value, and for non-development environments "missing vs development"; development shows "only here"); "Run locally" card with Copy; "Recent activity" (5 newest from F5, "View all" → Activity). Pure logic (checklist state, per-environment counts) in `lib/projects/overview.ts` with tests.

### Task F3: Secrets page v2 + detail panel
Rework `routes/project-secrets.tsx` to match `R3-Secrets.dc.html`:
- Title + computed one-line summary.
- Environment tabs as an underline tablist with count bubbles.
- Toolbar: filter by key, chips, List / Compare segmented link.
- Columns: Key (mono) · Value (mask + reveal) · Applies to (pill) · Environments (one chip per environment, letter = first letter uppercased; filled brand = shared value, amber = own value, dashed = missing; `title` + sr-only text give the meaning) · Version (`v<n>`) · actions menu. Help line under the table explains the chips.
- Clicking a row (or Enter) selects it and opens the **detail panel**: 380px right panel at ≥1280px, a full-height sheet below. Per mock: key + pill + close; "Value in each environment": one block per environment that has the key ("Shared value" / "Own value" / env name for only-rows), masked with reveal + copy; environments without it listed as "Not in <env>" with **Add here** (opens the add drawer prefilled for that env only); Version, Last changed (relative from `updatedAt`), Secret id (`shareUid` or `secretUid`, middle-truncated, copy); **Edit value** and **Delete**; "Run with <env> secrets" command block.
- **Edit value** opens the drawer in edit mode for a chosen value: key read-only; only/overridden row → `nextSecretSlot` + `sealSecret` + `api.secrets.updateSecret`; the shared value → seal version+1 into every non-overridden row with each environment's key → `api.secrets.updateSharedSecret`. Payload building in `lib/secrets/edit-secret.ts` with real-crypto tests (each row opens with its own env key at version+1; overridden rows absent). Stale errors show the existing reload message.
- The add drawer's duplicate-name check refuses only when a TARGET environment already has the key. Update its tests.

### Task F4: Compare page
**Create** `routes/project-compare.tsx` at `/projects/:slug/compare`. Match `R3-Compare.dc.html`: title + one line; summary tiles (keys across the project; one "missing in <env>" tile per environment with missing > 0, danger tint; own values, warning tint); matrix: Key column + one per environment; cells "Set here" (brand tint), "Shared value" (hairline), "Own value" (warning tint), "Missing · Add" (dashed danger, a real button opening the add drawer for that env). Rows sorted by key; clicking a key opens Secrets with its detail panel (`?env=<first env that has it>&key=<name>`). Values never shown. Matrix building in `lib/secrets/compare.ts` with tests (grouping by decrypted name across environments, classification, partial groups).

### Task F5: Activity
**Create** `lib/activity/describe.ts` (pure, tested: maps events to sentences using names decrypted from current rows; a secret no longer present is "a secret"; collapses the per-row events of one shared create/update/delete within 2 s into "… to all environments"; "You" when `actorIsYou`, else the email), `lib/activity/use-project-activity.ts` (wraps B2), and `routes/project-activity.tsx` at `/projects/:slug/activity`: list grouped by day ("Today", "Yesterday", date), avatar initial + sentence + relative time with an absolute `title`.

### Task F6: Command palette (⌘K)
**Create** `components/shell/command-palette.tsx`: ⌘K/Ctrl+K and the Search button open it; native `<dialog>`; input + results: current project's pages, projects in the org, environments, the current project's secret keys (decrypted names); arrow keys + Enter; Escape closes. Ranking in `lib/search/rank.ts` with tests (prefix beats substring, case-insensitive).

### Task F7: Projects home in the shell + mobile pass
Move `routes/projects.tsx` and `routes/new-project.tsx` into the shell (org nav), content unchanged, spacing adjusted (28px desktop, 16px phone). At 390px: no horizontal overflow, drawer works, detail panel is a sheet, the matrix scrolls inside its own container with a sticky Key column.

### Task F8: Verification (main session)
All tests, admin build + lint, `npx convex dev --once`, browser pass at 1440×900 and 390×844 in dark and light: Overview → Secrets (select, reveal, edit shared value, edit an override, Add here) → Compare (add a missing key) → Activity → ⌘K → phone drawer. Impeccable detector once. Fix, then report with screenshots.
