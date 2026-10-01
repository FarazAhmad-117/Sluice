# Dashboard slice 1: projects and secrets — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Replace the three-pane admin dashboard with the approved "Round 2" design for its first slice: a projects home, create-project (development always created), a per-environment secrets list with a scope label on every row, and an add-secret drawer that sets a secret for all environments or one, with per-environment overrides.

**Architecture:** Two backend additions and a new frontend. Backend: (1) secrets gain an optional `shareUid` (a new `shr_` id kind) and `overridden` flag, plus `createSharedSecret` / `deleteSharedSecret` mutations that write or delete one sealed row per environment atomically; (2) `createProjectWithEnvironments` creates a project and its environments (each with its key grant) in one mutation. Every environment keeps its own key, so a shared secret is N independently sealed rows linked by `shareUid`; the server checks only that the set of rows matches the project's environments. Frontend: URL routes per page, a header + tab layout, small UI primitives, and pure tested helpers for everything with logic (scope labels, sealing a shared secret, sealing project environments, parsing a .env, the personal org).

**Tech Stack:** Convex (+ convex-test), React 19, react-router 7, Tailwind v4 with the existing tokens in `apps/admin/src/app.css`, Geist via `@fontsource-variable`, `@sluice/crypto`, Vitest.

---

## Read this first

**The approved design.** Every screen below has a static HTML mock. Match it in structure, copy, spacing and color; the mocks use inline styles, the build uses Tailwind utilities mapped to the existing tokens (`bg-surface-panel`, `text-text-muted`, `border-hairline`, ...). Mock files (read them, do not copy inline styles verbatim):

```
C:\Users\Dell\AppData\Local\Temp\claude\e--Courses-Web-Development-Indepth-Solution-Sluice\3d8da39b-d3d0-44e1-ae66-3fe18063f339\scratchpad\sluice-directions\project\
  R2-Projects.dc.html      projects home
  R2-NewProject.dc.html    create a project
  R2-Secrets.dc.html       secrets list
  R2-AddSecret.dc.html     add-secret drawer
  R2-M-Projects.dc.html    phone: projects
```

Mock color → token map: `#050608` surface-base, `#0a0c10` surface-panel, `#12151c` surface-card, `#07080b` surface-deep, `rgba(255,255,255,.08)` hairline, `.14` hairline-strong, `#eceef3` text-primary, `rgba(236,238,243,.88)` text-body, `#8a91a3` text-muted, `#5c6374` text-faint, `#2d7ff9` brand, `#fcfdff` control-solid (primary button, black text = text-on-control-solid), `#ef4444` status-danger, `#f59e0b` status-warning, `#10b981` status-healthy. Light theme already exists via `[data-theme="light"]`; use tokens only, never hex, so both themes work.

**Product rules** (from `apps/admin/PRODUCT.md`): never claim the server can recover an account; secret values decrypt only in the browser and only on demand; WCAG 2.2 AA; touch targets ≥ 44px; no eyebrow labels above headings; no emoji icons.

**Commands.**
- Backend tests: `pnpm test` (root, runs `convex/**/*.test.ts`).
- Crypto tests: `pnpm --filter @sluice/crypto test`.
- Admin tests: `pnpm --filter ./apps/admin test`.
- Admin typecheck + build: `pnpm --filter ./apps/admin build`.
- `pnpm -r` stops at the first failing package; use `pnpm -r --no-bail test` for a full picture.

**Commits** end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. One commit per task.

**Comment style.** This codebase explains *why* in comments, at length, where a choice is load-bearing. Match it on security-relevant code; keep UI code lightly commented.

---

## Task 1: the `shr_` id kind

**Files:**
- Modify: `packages/crypto/src/ids.ts`
- Test: the existing ids test under `packages/crypto/test/`

**Step 1: failing tests.** Add:

```ts
it("mints and accepts shr ids", () => {
  const id = newId("shr");
  expect(id).toMatch(/^shr_[0-9a-f]{32}$/);
  expect(assertId("shr", "shareUid", id)).toBe(id);
});
it("refuses a sec id where a shr id is expected", () => {
  expect(() => assertId("shr", "shareUid", newId("sec"))).toThrow(
    "shareUid must be a well-formed shr id",
  );
});
```

Also update any existing test that pins the "kind must be org, usr, env or sec" message.

**Step 2:** run `pnpm --filter @sluice/crypto test` → FAIL.

**Step 3:** `IdKind = "org" | "usr" | "env" | "sec" | "shr"`, add `shr: pattern("shr")` to `PATTERNS`, change the error to `"kind must be org, usr, env, sec or shr"`. Add one paragraph to the header comment: a `shr_` id links the per-environment rows of one shared secret; it is never part of any associated data, so the server could relabel which rows belong together, which changes how the dashboard groups and labels rows but cannot make any ciphertext open under the wrong environment, secret or version.

**Step 4:** tests pass. **Step 5:** commit "Add the shr id kind for shared secrets".

---

## Task 2: schema and list shape for shared secrets

**Files:**
- Modify: `convex/schema.ts` (secrets table, ~line 225)
- Modify: `convex/secrets.ts` (`secretShape` ~310, `view` ~332, `updateSecret`)
- Modify: `convex/repo/secrets.ts` (`insertSecret` input type, add `listCurrentByShareUid`, `shareUidTaken`)
- Test: `convex/secrets.test.ts`

**Step 1: test** in `convex/secrets.test.ts`: create a secret with `createSecret` and assert the `listSecrets` row has no `shareUid` and no `overridden` property (`expect(row).not.toHaveProperty("shareUid")`). This pins that plain secrets are unchanged; Task 3 tests the shared shape.

**Step 2:** schema, on `secrets`:

```ts
// Links the per-environment rows of ONE shared secret ("All environments").
// Absent on a secret that lives in one environment only. Plaintext metadata,
// bound into nothing: see packages/crypto/src/ids.ts on `shr_`.
shareUid: v.optional(v.string()),
// On a shared row: true when this environment keeps its own value instead of
// the shared one. Absent on non-shared rows.
overridden: v.optional(v.boolean()),
```

and the index `.index("by_share", ["shareUid"])`.

Add `shareUid: v.optional(v.string())` and `overridden: v.optional(v.boolean())` to `secretShape`, and in `view()` spread them only when defined (same pattern as `supersededAt`). Extend `insertSecret`'s input with the two optional fields. In `repo/secrets.ts` add:

```ts
export async function shareUidTaken(ctx: QueryCtx, shareUid: string): Promise<boolean>
// any row, any state, via by_share — same reasoning as secretUidTaken
export async function listCurrentByShareUid(ctx: QueryCtx, shareUid: string): Promise<Doc<"secrets">[]>
// by_share, filtered to supersededAt === undefined && deletedAt === undefined
```

`updateSecret` must copy `shareUid` and `overridden` from the row it supersedes onto the new row.

**Step 3:** `pnpm test` all green. **Step 4:** commit "Carry a share id and override flag on secret rows".

---

## Task 3: `createSharedSecret` and `deleteSharedSecret`

**Files:**
- Modify: `convex/secrets.ts`
- Modify: `convex/lib/errors.ts` (new messages)
- Test: `convex/secrets.shared.test.ts` (new)

**`createSharedSecret`.** Args: `sessionToken`, `projectId: v.id("projects")`, `shareUid: v.string()`, `rows: v.array(v.object({ environmentId: v.id("environments"), secretUid: v.string(), version: v.number(), pdkVersion: v.number(), overridden: v.boolean(), nameCiphertext: v.string(), nameNonce: v.string(), valueCiphertext: v.string(), valueNonce: v.string() }))`. Returns `v.array(v.object({ secretId: v.id("secrets"), secretUid: v.string(), environmentId: v.id("environments") }))`.

Handler, in this order:
1. `requireProject(ctx, args.sessionToken, args.projectId)` → `{ org, project, user }`.
2. Load every environment of the project (the same repo call `listEnvironments` uses).
3. The rows' `environmentId`s must be exactly that set: same size, no duplicates, no extras. Otherwise `ConvexError(SHARED_ROWS_MISMATCH)`.
4. For each row, with its environment: `assertOrgLink(environment.orgId, org)`; `await requirePDKGrant(ctx, environment._id, user.uid)`.
5. `requireId("shr", "shareUid", ...)`; for each row `requireId("sec", "secretUid", ...)`, `version === INITIAL_SECRET_VERSION` else `NEW_SECRET_VERSION`, `assertSealed(row)`, `pdkVersion === environment.pdkVersion` else `STALE_PDK_VERSION`.
6. At least one row has `overridden === false`, else `ConvexError(SHARED_NEEDS_SHARED_ROW)`.
7. Secret uids distinct within the call, and none taken (`secretUidTaken`), else `DUPLICATE_SECRET_UID`. `shareUidTaken` else `DUPLICATE_SHARE_UID`.
8. Insert each row with `shareUid`, `overridden`, `orgId: environment.orgId`, `version: 1`. One `recordUserEvent` per row, action `"secret.create"`.

Add to `convex/lib/errors.ts`:

```ts
export const SHARED_ROWS_MISMATCH =
  "This project's environments changed since you opened it. Reload and try again.";
export const SHARED_NEEDS_SHARED_ROW =
  "A secret for all environments needs at least one environment using the shared value.";
export const DUPLICATE_SHARE_UID = "That shared secret id is already in use.";
```

**`deleteSharedSecret`.** Args `sessionToken`, `projectId`, `shareUid`. `requireProject`; rows = `listCurrentByShareUid`; refuse (the not-found error this file already uses) if empty or if any row's environment is not in this project; `requirePDKGrant` for each; set `deletedAt: Date.now()` on every row; one `"secret.delete"` event per row. Returns `null`.

**Step 1: failing tests** (`convex/secrets.shared.test.ts`; copy the setup helpers from `convex/secrets.test.ts` / `convex/bundle.contract.test.ts` for a user, org, project and environments created through the real mutations; the sealed fields may be fixed valid-shaped hex because the server never opens them):
- creates one row per environment, all carrying the shareUid; `listSecrets` for each environment returns its row with `shareUid` and `overridden`;
- rejects a row set missing an environment → `SHARED_ROWS_MISMATCH`;
- rejects an extra environment from another project → `SHARED_ROWS_MISMATCH`;
- rejects duplicate environment ids → `SHARED_ROWS_MISMATCH`;
- rejects all-overridden → `SHARED_NEEDS_SHARED_ROW`;
- rejects a reused secretUid inside the call and a taken one → `DUPLICATE_SECRET_UID`;
- rejects a reused shareUid → `DUPLICATE_SHARE_UID`;
- rejects a stale pdkVersion → `STALE_PDK_VERSION`;
- rejects a caller who is not a member of the org;
- `deleteSharedSecret` removes every row from every environment's `listSecrets`;
- a later `updateSecret` on one shared row keeps `shareUid` and `overridden` (covers Task 2's copy).

**Step 2:** `pnpm test` → FAIL. **Step 3:** implement. **Step 4:** green. **Step 5:** commit "Write and delete a shared secret across every environment at once".

---

## Task 4: `createProjectWithEnvironments`

**Files:**
- Modify: `convex/environments.ts` (extract the validated insert + grant into a helper)
- Modify: `convex/projects.ts`
- Test: `convex/projects.test.ts`

**Step 1: refactor, no behaviour change.** In `environments.ts` export a helper used by `createEnvironment`:

```ts
// Validates one environment's client-supplied fields and inserts the
// environment AND its creator's key grant. The only code that inserts into
// `environments`; both creation paths go through it, so an environment can
// never exist without the grant that makes its secrets readable. (The comment
// above insertPDKGrant in createEnvironment moves here with the code.)
export async function insertEnvironmentWithGrant(
  ctx: MutationCtx,
  scope: { org: Doc<"orgs">; project: Doc<"projects">; user: Doc<"users"> },
  input: { environmentUid: string; name: string; wrappedPDK: string; pdkNonce: string; pdkVersion: number },
): Promise<Id<"environments">>
```

containing everything in `createEnvironment`'s handler after `requireProject` (uid/name/nonce/ciphertext/version checks, duplicate name and uid checks, insert, grant, audit event). `createEnvironment` becomes `requireProject` + this helper. Run `pnpm test` → still green.

**Step 2: failing tests** in `convex/projects.test.ts` for `api.projects.createProjectWithEnvironments`:
- args `{ sessionToken, orgId, name, slug, environments: [{ environmentUid, name, wrappedPDK, pdkNonce, pdkVersion }] }` returns `{ projectId, environmentIds }`; `listEnvironments` returns them with grants (`getMyPdkGrant` works for each);
- refuses when no environment is named `development` → `PROJECT_NEEDS_DEVELOPMENT`;
- refuses duplicate environment names inside the call → existing `DUPLICATE_NAME`;
- refuses more than 10 environments → `TOO_MANY_ENVIRONMENTS`;
- refuses a duplicate project slug → existing duplicate-slug error, and nothing is inserted;
- when the second environment has a malformed nonce, the project does not exist afterwards (atomicity);
- a non-member cannot create in the org.

Add to `lib/errors.ts`: `PROJECT_NEEDS_DEVELOPMENT = "Every project starts with a development environment."` and `TOO_MANY_ENVIRONMENTS = "A project can start with at most 10 environments."`.

**Step 3: implement** in `projects.ts`: reuse `createProject`'s validation/insert (extract a local `insertProject` helper), then `insertEnvironmentWithGrant` for each environment in order.

**Step 4:** green. **Step 5:** commit "Create a project and its environments in one mutation".

---

## Task 5: scope labels (pure)

**Files:** Create `apps/admin/src/lib/secrets/scope.ts`; Test `apps/admin/test/scope.test.ts`

```ts
export type SecretScope = "shared" | "overridden" | "only";
export interface ScopedRow { readonly shareUid?: string; readonly overridden?: boolean }
export function scopeOf(row: ScopedRow): SecretScope // no shareUid → only; overridden → overridden; else shared
export function scopeLabel(scope: SecretScope, environmentName: string): string
// shared → "All environments"; overridden → `Overridden in ${env}`; only → `Only ${env}`
export function countScopes(rows: readonly ScopedRow[]): Record<SecretScope | "all", number>
```

Tests: each mapping, labels, counts including empty input. Commit "Label a secret's scope from its row".

---

## Task 6: seal a shared secret (pure + crypto)

**Files:** Create `apps/admin/src/lib/secrets/shared.ts`; Test `apps/admin/test/shared-secret.test.ts`

```ts
export interface SharedSecretInput {
  readonly name: string;
  readonly value: string; // the shared value
  readonly environments: readonly { environmentId: string; key: EnvironmentKey; override?: string }[];
}
export interface SharedSecretPayload {
  readonly shareUid: string;
  readonly rows: readonly {
    environmentId: string; secretUid: string; version: 1; pdkVersion: number; overridden: boolean;
    nameCiphertext: string; nameNonce: string; valueCiphertext: string; valueNonce: string;
  }[];
}
export async function sealSharedSecret(input: SharedSecretInput): Promise<SharedSecretPayload>
```

`shareUid = newId("shr")`; per environment `newSecretSlot()`, value = `override ?? value`, `overridden = override !== undefined`, `sealSecret(key, {...slot, name, value})`. Throws if `environments` is empty or every environment has an override.

Tests (real crypto, keys from `createProjectDataKey()` with distinct `env_` uids): one row per environment with distinct secretUids and one shareUid; each row opens with ITS environment's key via `openSecret` to the right name/value (override where given); a row does NOT open with another environment's key (`SecretOpenError`); empty and all-override inputs throw. Commit "Seal one secret into every environment of a project".

---

## Task 7: seal a new project's environments (pure + crypto)

**Files:** Create `apps/admin/src/lib/projects/create-project.ts`; Test `apps/admin/test/create-project.test.ts`

```ts
export const OPTIONAL_ENVIRONMENTS = ["production", "staging"] as const;
export function slugFromName(name: string): string
// lowercase, runs of non [a-z0-9] → "-", trim "-", cut to MAX_SLUG_LENGTH (lib/naming.ts) without a trailing "-"; "" if nothing usable
export function environmentNames(extra: readonly ("production" | "staging")[]): string[]
// ["development", ...extra in OPTIONAL_ENVIRONMENTS order, deduped]
export async function sealProjectEnvironments(muk: MasterUnlockKey, userUid: string, names: readonly string[]):
  Promise<{ payload: { environmentUid: string; name: string; wrappedPDK: string; pdkNonce: string; pdkVersion: 1 }[];
            keys: EnvironmentKey[] }>
```

`sealProjectEnvironments` does per name what `NewEnvironmentForm` does today (`create-forms.tsx:392-408`): `newId("env")`, `createProjectDataKey()`, `wrapProjectDataKey(muk, pdk, { environmentUid, pdkVersion: 1, granteeType: "user", granteeId: userUid })`. Returns the keys so the import step can seal secrets without a round trip.

Tests: `slugFromName("Storefront API!")` = `"storefront-api"`, empty/symbol-only → `""`, long input capped; `environmentNames(["staging","production","staging"])` = `["development","production","staging"]`; each wrapped key unwraps with `unwrapProjectDataKey` under the matching grantee to the returned key bytes, and fails under another environment's uid (see `apps/admin/test/secrets.test.ts` for building a `MasterUnlockKey` in tests). Commit "Seal a new project's environment keys in one step".

---

## Task 8: parse a .env file (pure)

**Files:** Create `apps/admin/src/lib/dotenv.ts`; Test `apps/admin/test/dotenv.test.ts`

```ts
export interface DotenvEntry { readonly name: string; readonly value: string; readonly line: number }
export interface DotenvResult { readonly entries: DotenvEntry[]; readonly errors: { line: number; message: string }[] }
export function parseDotenv(text: string): DotenvResult
```

Rules: `\r\n` and `\n`; skip blank lines and lines starting with `#`; optional leading `export `; name must match `^[A-Za-z_][A-Za-z0-9_]*$` else an error for that line (never echo the value in any message); value after the first `=`, trimmed; `"..."` values keep inner `#` and support `\n` `\"` `\\` escapes; `'...'` values are literal; unquoted values end at ` #` (inline comment); a later duplicate name replaces the earlier entry and adds the error `"NAME is set twice; the later value is used"`; at most 1,000 entries, then an error. Tests for each rule. Commit "Parse a .env file for import".

---

## Task 9: the personal org

**Files:** Create `apps/admin/src/lib/orgs/personal-org.ts`; Test `apps/admin/test/personal-org.test.ts`

```ts
export async function personalOrgPayload(muk: MasterUnlockKey, userUid: string): Promise<{
  orgUid: string; name: "Personal"; slug: string; revocationPublicKey: string; wrappedRevocationKey: string; revocationKeyNonce: string;
}>
```

Same crypto as `NewOrgForm` (`create-forms.tsx:184-197`); slug `personal-` + 8 lowercase hex from `crypto.getRandomValues` (must pass `isSlug`). Test: slug shape, the wrapped key unwraps with `unwrapRevocationKey` and `revocationKeyMatches` the public key. Commit "Mint a personal org for a new account".

---

## Task 10: environment keys for a whole project (hook)

**Files:** Create `apps/admin/src/lib/secrets/use-environment-keys.ts`; Modify `apps/admin/src/lib/secrets/use-project-data-key.ts` (export the single-environment loader it already contains so both hooks share it; no behaviour change)

```ts
export function useEnvironmentKeys(
  environments: readonly { environmentId: Id<"environments">; uid: string }[] | undefined,
): ReadonlyMap<string /* environmentId */, ProjectDataKeyState>
```

Loads each environment's key with the same steps and consistency checks `useProjectDataKey` performs, re-running when the list or the vault changes. If the loader is extracted as a pure async function, add a test that a grant whose `pdkVersion` disagrees with the environment is reported exactly as before. Admin tests and build green. Commit "Load every environment key in a project".

---

## Task 11: UI primitives and icons

**Files (create):**
- `apps/admin/src/components/ui/icons.tsx` — inline stroke SVG components, 24×24 viewBox, `stroke="currentColor"`, `strokeWidth={1.7}`, `aria-hidden`: `IconSearch, IconPlus, IconChevronUpDown, IconChevronDown, IconChevronLeft, IconEye, IconEyeOff, IconCopy, IconMore, IconClose, IconUpload, IconCheck`. Paths from the mocks.
- `apps/admin/src/components/ui/styles.ts` — move `focusRing` and `inputControl` here from `components/app/controls.tsx` (re-export from controls.tsx until Task 18).
- `apps/admin/src/components/ui/button.tsx` — `Button` with `variant: "primary" | "secondary" | "ghost" | "danger"`, `size: "md" | "lg"`; renders `<button>` or, with `to`, a react-router `<Link>`. primary = `bg-control-solid text-text-on-control-solid`; secondary = `border border-hairline-strong text-text-primary`; danger = `bg-status-danger text-surface-base`. Disabled and loading (spinner + `aria-busy`).
- `apps/admin/src/components/ui/field.tsx` — `TextField` (label above, hint and error below, `aria-describedby`), `TextArea`, `Checkbox`, `RadioCard` (selected = brand border + `bg-brand-subtle`).
- `apps/admin/src/components/ui/pill.tsx` — `ScopePill({ scope, environmentName })` from Task 5 (shared = hairline border, overridden = warning tint, only = brand tint) and `EnvPill({ name })`.
- `apps/admin/src/components/ui/segmented.tsx` — `Segmented` tablist with arrow-key navigation, `role="tablist"/"tab"`, `aria-selected`.
- `apps/admin/src/components/ui/drawer.tsx` — right drawer ≥ 768px, bottom sheet below; `role="dialog" aria-modal`, focus trap, Escape and backdrop close, focus returns to the opener, `prefers-reduced-motion` respected.

Add `::selection` from the brand token in `app.css`. Build passes. Commit "Add the dashboard's UI primitives".

---

## Task 12: layout, routes, unlock gate

**Files (create):**
- `apps/admin/src/components/layout/app-header.tsx` — as the mock header: `sluice` wordmark (link to `/projects`), `/`, org switcher (menu of `listMyOrgs`), and on project routes `/` + project switcher (menu of `listProjects`). Right: account button (initial of the email) → menu with email, theme (system/light/dark via `useTheme`) and Sign out.
- `apps/admin/src/components/layout/project-tabs.tsx` — tab bar under the header for project routes: only **Secrets** in this slice (no dead tabs).
- `apps/admin/src/components/layout/unlock-gate.tsx` — when `useAuth().locked`, a centered card instead of the page: "Unlock Sluice", "Your session is still signed in. Enter your password to open your keys in this browser.", password field, Unlock button with `DerivationProgress`, errors via `messageForUser`, secondary "Sign out".
- `apps/admin/src/components/layout/app-layout.tsx` — header + `<UnlockGate><Outlet/></UnlockGate>`, max-width 1120px container, 24px gutter (16px under 640px).
- `apps/admin/src/lib/orgs/use-current-org.ts` — the selected org (`listMyOrgs` + `localStorage["sluice.org"]`, default first). When unlocked and `listMyOrgs` returns `[]`, create the personal org with `api.orgs.createOrg(await personalOrgPayload(...))` exactly once (module-level in-flight promise + ref, so StrictMode's double effect cannot create two). Returns `{ org, orgs, setOrg, status: "loading" | "ready" | "creating" }`.

**Modify:** `apps/admin/src/routes.tsx` — inside `RequireSession`, an `AppLayout` route: `projects`, `projects/new`, `projects/:projectSlug` → redirect to `secrets`, `projects/:projectSlug/secrets`. Index and `/app` redirect to `/projects`. Keep `login`, `signup`, `dev/argon2`, `*`. Update `lib/redirect.ts` if it hardcodes `/app`.

Build passes. Commit "Lay out the dashboard around projects".

---

## Task 13: projects home

**Files:** Create `apps/admin/src/routes/projects.tsx`, `apps/admin/src/lib/projects/use-project-overview.ts` (current org's `listProjects`; per project `listEnvironments` and secret counts from `listSecrets` per environment, shared rows counted once by `shareUid`).

Match `R2-Projects.dc.html`, and under 640px `R2-M-Projects.dc.html`: search filtering by name; **New project** primary (→ `/projects/new`); card grid 3/2/1 columns with initial tile, name, "N secrets", environment pills. Slice 1 has no connection data: no dots, no "connected" footer (never invent counts). Empty state: "Create your first project" / "A project holds the secrets for one app. It starts with a development environment." / **New project** + secondary **Import a .env**. The "Moving off .env files?" banner only when at least one project exists. Loading: three skeleton cards. Commit "Show projects as cards on the home page".

---

## Task 14: create a project

**Files:** Create `apps/admin/src/routes/new-project.tsx`

Match `R2-NewProject.dc.html`. **Project name** with live `slugFromName` preview ("You'll use it in commands: `sluice run --project <slug>`"), error when the slug is empty. **Environments**: development checked + disabled ("Always created"), production (checked by default), staging (unchecked). **Start with**: "No secrets yet" / "Import a .env file"; on import a drop zone + picker (`.env`/text, ≤ 256 KB) parsed by Task 8, showing "N secrets found" and line-numbered errors (never values).

Submit: `sealProjectEnvironments` → `api.projects.createProjectWithEnvironments({ sessionToken, orgId, name: slug, slug, environments })`; then, if importing, seal each entry into **development only** with the returned development key (`newSecretSlot` + `sealSecret` + `api.secrets.createSecret`, sequentially, "Importing 3 of 12…"); then navigate to `/projects/<slug>/secrets?env=development`. Errors under the form; button disabled with progress while working. Footer: "Encrypted in this browser before anything is saved." Commit "Create a project with its environments".

---

## Task 15: secrets page

**Files:** Create `apps/admin/src/routes/project-secrets.tsx`, `apps/admin/src/lib/secrets/use-project-secrets.ts` (project by slug from the current org's `listProjects`, its environments, `useEnvironmentKeys`, `listSecrets` per environment, selected environment from `?env=` default `development`; returns rows for the selected environment with decrypted names via `useSecretNames`, their scope, and per-environment counts).

Match `R2-Secrets.dc.html`: environment `Segmented` with counts; **Add secret** primary (omit Import .env on this page in this slice); filter chips "All N · Shared N · Overridden here N · Only <env> N" (hide zero chips except All); filter-by-key search; table: Key (mono), Value (mask + eye toggle calling `openSecretValue`, re-masks on second press or after 30 s), Applies to (`ScopePill`), row menu with **Copy value** and **Delete** (only-rows: `api.secrets.deleteSecret`; shared or overridden rows: confirm "Delete from all environments?" → `api.secrets.deleteSharedSecret`). Under 768px the table becomes a stacked list. Footer note from the mock. States: keys loading → skeleton rows; `refused`/`rekeying`/`failed` → its message in a callout; empty → "No secrets in <env> yet" + **Add secret**. Omit the "Updated" column (the list has no timestamp). Commit "List a project's secrets per environment with their scope".

---

## Task 16: add-secret drawer

**Files:** Create `apps/admin/src/components/secrets/add-secret-drawer.tsx`; Modify `apps/admin/src/routes/project-secrets.tsx`

Match `R2-AddSecret.dc.html`. Key (mono, `^[A-Za-z_][A-Za-z0-9_]*$`); Value (textarea, mono, hidden-by-default toggle); **Where does it apply?**: "All environments" ("One shared value for <list>. Any of them can override it.") and "Only <current env>". With all environments, **Different value somewhere? Optional** lists every environment: "Uses the shared value" or an "Own value" switch revealing an input. Duplicate-name check before sealing: if any environment already has a current row with this decrypted name, show "<NAME> already exists in <env>." and refuse. Save: all → `sealSharedSecret` with every environment's key (if any key is not `ready`, say which environment is unavailable and disable Save) → `api.secrets.createSharedSecret`; only → `newSecretSlot` + `sealSecret` + `api.secrets.createSecret`. Footer: "Encrypted in this browser before it's saved" + Cancel / **Save secret**. On success close and briefly highlight the new row. Commit "Add a secret for one environment or all of them".

---

## Task 17: sign-in and sign-up in the new look

**Files:** Modify `apps/admin/src/components/auth/auth-shell.tsx`, `apps/admin/src/routes/login.tsx`, `apps/admin/src/routes/signup.tsx`

Keep every behaviour and the no-recovery acknowledgement checkbox. Presentation: centered 400px card on surface-base, `sluice` wordmark top-left, heading ("Sign in" / "Create your account"), one line "Your password never leaves this browser.", fields, full-width primary button, derivation progress inline. Remove the "ZERO KNOWLEDGE" eyebrow; the password-meter caveat becomes "A rough strength check, done in this browser."; the no-recovery warning: "If you forget this password, your secrets cannot be recovered by anyone, including us. Save it in a password manager before you continue." After signup or login go to `/projects`. Commit "Bring sign-in and sign-up into the new design".

---

## Task 18: remove the old shell

**Files:** Delete `apps/admin/src/components/app/shell.tsx`, `left-nav.tsx`, `right-panel.tsx`, `secrets-pane.tsx`, `create-forms.tsx`, `controls.tsx` (after moving anything still used into `components/ui/`), `apps/admin/src/routes/dashboard.tsx`. Modify everything that imported them, and `apps/admin/README.md` (new routes and folders).

Admin build and tests green; `rg "components/app/" apps/admin/src` returns nothing. Commit "Remove the three-pane dashboard".

---

## Task 19: SECURITY.md

Under the section on what the bindings protect and do not: shared secrets are one independently sealed row per environment; `shareUid` and `overridden` are plaintext metadata bound into no ciphertext, so a malicious server can mislabel a row's scope, regroup rows, or hide one environment's row; it cannot make a row open under another environment, secret or version. Commit "Say what a shared secret's link does and does not protect".

---

## Task 20: verification

1. `pnpm -r --no-bail test` and root `pnpm test`: all green; record counts.
2. `pnpm --filter ./apps/admin build`: green.
3. `npx convex dev --once` pushes schema and functions to the dev deployment.
4. In a browser at 1440×900 and 390×844, dark and light: sign up → Projects with a Personal org → New project (production ticked, import a 3-line .env) → 3 secrets "Only development" → Add secret "All environments" with a production override → production shows "Overridden in production" and reveals the override → delete a shared secret: gone from both environments → reload: unlock gate, unlock, everything decrypts.
5. Run `C:/Users/Dell/.claude/plugins/cache/impeccable/impeccable/4.3.1/skills/impeccable/scripts/impeccable.cmd detect --json apps/admin/src` once; fix mechanical findings.
6. Screenshots to `.impeccable/review/` (desktop, mobile, light variants) for the finish review.
