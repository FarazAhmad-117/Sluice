# Releasing the CLI

One tag publishes the `sluice` CLI everywhere:

| Channel | What a user runs | What the release does |
|---|---|---|
| GitHub Releases | (downloads) | Attaches the five archives and `SHA256SUMS` to the `cli-v<version>` release |
| npm | `npm install -g @getsluice/cli` | Publishes `packages/cli` with provenance |
| Install scripts | `curl -fsSL https://raw.githubusercontent.com/FarazAhmad-117/Sluice/HEAD/install.sh \| sh` and `irm …/install.ps1 \| iex` | Nothing to publish: they download the latest release and check its checksum |
| Homebrew | `brew install FarazAhmad-117/sluice/sluice` | Commits `Formula/sluice.rb` to `FarazAhmad-117/homebrew-sluice` |
| Scoop | `scoop bucket add sluice https://github.com/FarazAhmad-117/scoop-sluice` then `scoop install sluice` | Commits `bucket/sluice.json` to `FarazAhmad-117/scoop-sluice` |
| winget | `winget install Sluice.Sluice` | Opens a pull request on `microsoft/winget-pkgs`; Microsoft reviews it, usually in a day or two |

Everything except npm installs a standalone executable compiled with Bun, so users do not need Node.

## One-time setup

Each publishing step checks for its secret and skips with a warning when it is missing, so these can be done one at a time.

1. **npm.** Create the free organisation `getsluice` on npmjs.com (the `sluice` and `sluicehq` scopes belong to other people). Create a granular access token that can publish to `@getsluice` and add it to this repository as the Actions secret `NPM_TOKEN`.
2. **Homebrew.** Create the public repository `FarazAhmad-117/homebrew-sluice`. The name must start with `homebrew-` for `brew install FarazAhmad-117/sluice/sluice` to find it. Create a fine-grained token with Contents read/write on that repository only, and add it as `HOMEBREW_TAP_TOKEN`.
3. **Scoop.** Create the public repository `FarazAhmad-117/scoop-sluice`, a token scoped to it, and the secret `SCOOP_BUCKET_TOKEN`.
4. **winget.** Create a classic token with `public_repo` scope (wingetcreate forks `microsoft/winget-pkgs` and opens the pull request from that fork), and add it as `WINGET_TOKEN`. The first submission of a new package gets a human review; later versions are usually merged automatically once validation passes.

## Cutting a release

1. Set the version in `packages/cli/package.json` (for example `0.1.0`) and commit it.
2. Optional dry run: run the **Release CLI** workflow by hand from the Actions tab. It tests, builds every executable, renders the manifests and smoke-tests the installers on Linux (x64, arm64), macOS (Intel, Apple Silicon) and Windows, but publishes nothing.
3. Tag and push:

   ```sh
   git tag cli-v0.1.0
   git push origin cli-v0.1.0
   ```

   The workflow refuses a tag that does not match `package.json`. A version with a hyphen (`0.2.0-rc.1`) is published as a GitHub pre-release and to npm under the `next` tag, and is not sent to Homebrew, Scoop or winget.
4. After the first release is live, set `CLI_RELEASED = true` in `apps/admin/src/lib/projects/install.ts` so the dashboard shows the install commands with Copy buttons.

## Building locally

```sh
node scripts/release/build-binaries.mjs --host   # this machine's executable only
node scripts/release/build-binaries.mjs          # every platform (needs network for Bun's cross-compile runtimes)
node scripts/release/render-manifests.mjs        # Homebrew, Scoop and winget files from the last build
```

Output goes to `packages/cli/release/` (ignored by git). Test an installer against a local build without publishing anything:

```sh
SLUICE_DOWNLOAD_BASE="file://$PWD/packages/cli/release" SLUICE_INSTALL=/tmp/sluice sh install.sh
```

## On Windows and npm scripts

The CLI starts your command without a shell, on purpose. With the standalone executable (winget, Scoop, the PowerShell installer), `sluice run -- npm run dev` works, because Bun resolves npm's `.cmd` script itself. With the npm-installed CLI, which runs on Node, it does not: Node refuses to start a `.cmd` file without a shell. Start `node` directly there, for example `sluice run -- node server.js`.
