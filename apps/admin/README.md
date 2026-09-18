# `apps/admin` — the Sluice admin panel

The authenticated product surface: sign up, sign in, and the three-pane
dashboard over organisations, projects, environments and secrets. It is a Vite
single-page application, separate from the marketing site in `apps/web`.

## Running it

From the repository root, `pnpm dev` starts this and the marketing site together
in one terminal, each in its own Turborepo pane:

```sh
pnpm dev                       # web on :3000, admin on :5180
pnpm dev -- --filter=admin     # just this one
```

Or drive this package on its own:

```sh
pnpm --filter admin dev        # http://localhost:5180
pnpm --filter admin build      # tsc --noEmit, then a production bundle in dist/
pnpm --filter admin test       # 85 tests: derivation, identity, sealing, naming
pnpm --filter admin lint
pnpm --filter admin typecheck
```

It needs a Convex deployment, and `pnpm dev` does NOT start one -- `convex dev`
wants to prompt on first run and writes to the repository root, so it gets its
own terminal:

```sh
pnpm dev:backend               # npx convex dev
```

That writes `CONVEX_URL` into the root `.env.local`, and `vite.config.ts` finds
it there. Nothing else has to be configured for a local checkout.

## Why it is a separate application

The dashboard used to be a route group inside the Next marketing site. Three
things pushed it out:

- **They have opposite rendering needs.** The landing page is static marketing
  content that wants to be server-rendered, crawled and cached. This surface
  derives keys in the browser, holds a session that only exists in one tab, and
  cannot be server-rendered at all — there is no server-visible credential to
  render it with. Everything that made this half work under Next was a way of
  opting out of Next: `"use client"` on nearly every file, a route group whose
  only job was to keep the providers away from the landing page, and a hydration
  flag on the session so guards would not redirect during the server render.
- **They have opposite theme rules.** The landing page is dark-locked for brand
  reasons. This is dual-theme because people live in it.
- **They have different blast radii.** This one holds an authenticated session
  and decrypted secret names. Its dependency list is worth keeping short and
  worth reviewing on its own.

The split is not free. The design tokens now exist in two stylesheets that must
stay in agreement, and the focus ring is declared twice. Both are noted in the
files that carry them.

## Environment

| Variable | Required | What it does |
| --- | --- | --- |
| `VITE_CONVEX_URL` | no | The Convex deployment URL. Falls back to `CONVEX_URL` from this directory's env files, then the repository root's. Missing renders an actionable message rather than a crash. |
| `VITE_SITE_URL` | no | The marketing site's origin, for the "sluice" wordmark. Defaults to `http://localhost:3000`, where `next dev` serves it. |

Both are inlined into the bundle at build time, so changing either needs a
restart. Neither is secret: a Convex deployment URL is the public address every
browser dials.

The marketing site has the matching variable in the other direction —
`NEXT_PUBLIC_ADMIN_URL`, which its "Sign in" and "Get started" links point at.
Set both in a deployment, or the two applications will link at each other's
localhost ports.

## Layout

```
src/
  main.tsx              mounts the router
  routes.tsx            the route table, the guard boundary, the dev-only branch
  app.css               design tokens, mirrored from apps/web
  routes/               one file per screen
  components/
    app/                the dashboard shell and its panes
    auth/               the sign-in and sign-up frame
    providers.tsx       theme, Convex and auth, in that order
    require-session.tsx the route guard
  lib/
    auth/               session, identity, password strength, email normalisation
    crypto/             Argon2id, the WASM backend and the derivation worker
    secrets/            project data keys, sealing and decryption
    orgs/               revocation key handling
test/                   node tests, by relative path, no alias resolution
```

## Things worth knowing before changing something

- **The route guard is not the access control.** Every Convex query behind it
  refuses without a valid session token, and `requireSession` on the server is
  what protects the data. The guard exists so an unauthenticated visitor sees a
  sign-in page instead of three empty panes. Do not add a check here that the
  server does not also make.
- **The session token is a Convex function argument**, not a cookie, so it has
  to be readable by the JavaScript that builds the call. `src/lib/auth/session-store.ts`
  explains what that exposes it to and why an `httpOnly` cookie is
  architecturally unavailable rather than merely unimplemented.
- **A refresh leaves you signed in and locked.** The session survives in
  `sessionStorage`; the master unlock key never leaves memory, so it does not.
  That is the intended consequence of never persisting the key.
- **The pre-paint theme script is injected by `vite.config.ts`**, from the same
  constant `lib/theme.tsx` reads. Do not paste a copy into `index.html`.
- **`/dev/argon2` is absent from production builds**, not hidden in them. It is
  reached only through a dynamic import inside an `import.meta.env.DEV` branch,
  which Rollup folds away. A static import anywhere would put it back.
- **A single-page build needs history fallback.** The host must rewrite unknown
  paths to `index.html`, or a refresh on `/app` 404s. `vite preview` does this;
  a static host has to be told to.
