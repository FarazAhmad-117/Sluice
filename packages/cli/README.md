# @getsluice/cli

Run any command with your secrets from [Sluice](https://github.com/FarazAhmad-117/Sluice), with no `.env` file on disk, and stop it the moment its token is revoked.

```sh
sluice run -- npm start
```

`sluice run` fetches the environment's secrets, decrypts them on this machine with a key the Sluice server has never held, starts your command with them in its environment, and supervises it. When someone revokes the token in the dashboard, every process using it receives a signed notice and is shut down within seconds.

## Install

| Where | Command |
|---|---|
| npm (Node 20+) | `npm install -g @getsluice/cli` |
| Homebrew | `brew install FarazAhmad-117/sluice/sluice` |
| macOS / Linux | `curl -fsSL https://raw.githubusercontent.com/FarazAhmad-117/Sluice/HEAD/install.sh \| sh` |
| winget | `winget install Sluice.Sluice` |
| Scoop | `scoop bucket add sluice https://github.com/FarazAhmad-117/scoop-sluice` then `scoop install sluice` |
| Windows (PowerShell) | `irm https://raw.githubusercontent.com/FarazAhmad-117/Sluice/HEAD/install.ps1 \| iex` |

Every channel except npm installs a standalone executable, so Node is not needed. Check it with `sluice --version`.

## Configure

In the dashboard, open your project, go to **Environments** and choose **Connect**. The setup page creates a token for that one place and gives you these lines for your shell, server, CI or container:

| Variable | What it is |
|---|---|
| `SLUICE_TOKEN` | The service token, `slc_<environment>_…`. A secret: keep it in your shell profile, your server's config or your CI's secret store, never in a committed file. |
| `SLUICE_ORG_REVOCATION_PUBLIC_KEY` | Your organisation's public revocation key, 64 hex characters. Pinned by you and never fetched from Sluice, so a hostile server cannot sign its own kill notices. |
| `SLUICE_CONVEX_URL` | Your Sluice deployment's address. |

Optional: `SLUICE_DRAIN_MS` (how long your command gets to finish after a revocation, default 5s), `SLUICE_KILL_GRACE_MS`, `SLUICE_BOOT_TIMEOUT_MS`, `SLUICE_MAX_OFFLINE_MS`, `SLUICE_STATE_DIR`. Run `sluice --help` for each.

## Exit codes

`sluice run` exits with your command's own exit code. It exits `1` after a revocation, `2` when its configuration is wrong, and `70` on an internal failure.

## License

Apache-2.0
