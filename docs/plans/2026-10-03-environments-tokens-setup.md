# Environments, tokens and guided setup: Implementation Plan

**Goal:** make Sluice usable outside the test suite. From the dashboard a person can add an environment, connect a place to it (their computer, a server, CI, Docker) with its own service token, watch it connect, and revoke it with a signed notice.

**Builds on:** `2026-10-02-dashboard-round-3-sidebar.md` (merged). Same commands, commit trailer, token map and product rules. Work happens in the main session, no subagents (the user asked).

**Design:** the approved Round 2 flows `R2-Environments`, `R2-SetupLocal`, `R2-SetupServer` (canvas page r2), drawn in the Round 3 sidebar shell. Two honest departures:
- "My computer" also gets a service token. `sluice login` does not exist yet.
- A connection shows Live / Idle / Never connected / Revoked from `lastSeenAt`. Nothing measures process counts, so none are shown.

---

## Why the token id must be stored, sealed

`revokeServiceToken` verifies a notice signed over the PLAINTEXT token id. The server keeps only `tokenIdHash`, by design: a database reader must not be able to enumerate ids. So a browser that did not create the token cannot revoke it today.

Fix: `serviceTokens` also stores the id and a person-given name, each sealed under the environment's project data key. The associated data binds both to the environment uid and the token's hash, so a sealed id cannot be moved onto another row. The server still never holds either in plaintext. Any member with the environment key can open them and revoke.

---

## Backend

### B1: sealed token metadata
- `@sluice/crypto/protocol.ts`: `tokenMetaAssociatedData({ environmentUid, tokenIdHash, field: "name" | "tokenId", pdkVersion })`, with a test that it differs per field, environment, hash and version.
- `schema.ts` `serviceTokens`, all fields optional so existing rows still validate:
  - `nameCiphertext`, `nameNonce`, `tokenIdCiphertext`, `tokenIdNonce`, `metaPdkVersion`;
  - `target: "computer" | "server" | "ci" | "docker"`;
  - `createdBy: Id<"users">`.
- `createServiceToken` requires them for new tokens:
  - hex and size checks (name ≤ 64 bytes; plaintext id = 16 bytes, so ciphertext = 32 bytes);
  - `target` from the union;
  - `createdBy` set from the session, never from the caller.
- Tests: missing fields refused; the stored row carries them; the grant is still written.

### B2: list tokens
- `convex/tokens.ts` `listProjectTokens({ sessionToken, projectId })`: every token in the project's environments, newest first, bounded at 200. Each row:
  - `serviceTokenId`, `environmentId`, `target`, `status`;
  - `createdAt`, `lastSeenAt | null`, `expiresAt | null`, `revokedAt | null`;
  - `createdByIsYou`, `createdByEmail` (current members only, as in activity);
  - the sealed name, the sealed id and `metaPdkVersion`.
- Tests:
  - only this project, newest first;
  - non-member refused;
  - another org's tokens never appear;
  - `tokenIdHash` and `publicKey` are never returned;
  - added to `unauthenticated.test.ts`.

### B3: the add-environment path
`createEnvironment` exists. Check that it does what "Add environment" needs (name rules, grant to the creator, `MAX` per project) and add a test if anything is missing.

---

## Frontend

### F1: crypto helpers (`lib/tokens/`)
- `issue-token.ts`: `issueToken({ environment, pdk, name, target })` →
  - `mintToken`;
  - wrap the PDK to the token's unwrap key, under the grant associated data the bundle uses (copy `bundle.contract.test.ts`);
  - seal the name and id;
  - return `{ token, args }`, with the token string kept in a `MintedToken`-style wrapper.
  - Real-crypto test: a bundle opened with the minted token's unwrap key recovers the PDK.
- `open-token.ts`: open the name and id with the environment key. Tested.
- `revoke-token.ts`:
  - unwrap the org revocation key (`getMyRevocationGrant` + MUK);
  - sign `{ tokenId, epoch: 1, revokedAt: now, reason }` and call `revokeServiceToken`.
  - Test: the signature verifies under the org public key.
- `connection.ts`: Live (seen in the last 2 min), Idle, Never connected, Revoked, Expired. Tested.

### F2: Environments page (`/projects/:slug/environments`)
- Matches `R2-Environments` in the shell: one card per environment with its name, secret count and connection count.
- Each card has "Connect" (or "Set up <env>" when nothing is connected) and its connections: name, target, status chip, last seen, Revoke.
- "Add environment" opens a small drawer that calls `createEnvironment`.
- Sidebar: Environments and Add environment go live.

### F3: Setup flow (`/projects/:slug/environments/:env/setup`)
1. Pick a target: My computer, A server, CI pipeline, Docker.
2. Name it, with a sensible default per target.
3. Create the token. It is shown ONCE, with Copy and the line "Shown once. Sluice never stored it."
4. Install the CLI, reusing the install tabs.
5. Start through Sluice. The snippet depends on the target:
   - computer: `export` lines;
   - server: Command / systemd / PM2;
   - CI: GitHub Actions secrets + a workflow step;
   - Docker: `docker run -e` / compose.
   - Every snippet sets `SLUICE_TOKEN`, `SLUICE_ORG_REVOCATION_PUBLIC_KEY` and `SLUICE_CONVEX_URL`.
6. "Waiting for the first connection…" turns into "<name> is connected" when `lastSeenAt` appears.
- Snippet building in `lib/tokens/snippets.ts`, tested. The token itself is never put in a URL, storage or logs.

### F4: Tokens page (`/projects/:slug/tokens`)
- Every token in the project: name, environment, target, created by, created, last seen, status.
- Revoke opens a confirm dialog with an optional reason (the dialog warns that the reason is broadcast) and signs in the browser.
- Filter by environment and status.

### F5: wire the rest
- Overview step 4, "Connect production", goes live and links to Setup for production. It is done when any non-development token has connected.
- The run command becomes `sluice run -- npm run dev`, because the token carries project and environment.
- The install guide's step 2 becomes "Create a token for this computer" and links to Setup → My computer. `sluice login` is no longer shown.
- Palette entries for Environments and Tokens.

### F6: verification
- All tests, build, lint, `convex dev --once`.
- Headless browser pass at 1440×900 and 390×844, dark and light.
- Then an end-to-end run: create a token in the dashboard, run the real `packages/cli` with it against dev, see "connected", revoke it, and watch the child process stop.
