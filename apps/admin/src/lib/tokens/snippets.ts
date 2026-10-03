import type { TokenTarget } from "./token-crypto";

/**
 * WHAT A PERSON PASTES TO START THEIR APP THROUGH SLUICE, PER PLACE IT RUNS.
 *
 * Every snippet sets the three variables `packages/cli/src/config.ts` reads:
 * the token, the org's revocation public key (pinned by the person, never
 * fetched, which is what stops a hostile server signing its own kill notices),
 * and the deployment address.
 *
 * WHERE THE TOKEN ITSELF APPEARS. On a computer or a server the person keeps
 * it in that machine's own configuration, so the snippet carries it. In CI
 * and in containers it belongs in a secret store, so those snippets name the
 * secret and never contain the value: a workflow file or a Dockerfile is
 * committed, and a token in one is a token in the repository's history.
 *
 * Docker and PM2 use exec form, so `sluice` is the process that receives the
 * stop signal a revocation depends on. A shell-form `CMD` would put `/bin/sh`
 * in between, and it does not pass SIGTERM on.
 */

export interface Snippet {
  readonly id: string;
  /** The tab's label. */
  readonly label: string;
  readonly code: string;
  /** One line under the code: where it goes, or what to do first. */
  readonly note: string;
}

const PLACEHOLDER = "<your token>";

const DEFAULT_COMMAND: Record<TokenTarget, string> = {
  computer: "npm run dev",
  server: "npm start",
  ci: "npm test",
  docker: "npm start",
};

/** `["npm", "start"]`, for exec form. Splits on whitespace; quoting is the person's to adjust. */
function execForm(command: string): string {
  return command
    .trim()
    .split(/\s+/)
    .map((part) => JSON.stringify(part))
    .join(", ");
}

export function setupSnippets(input: {
  readonly target: TokenTarget;
  /** The token string, or null before one has been created. */
  readonly token: string | null;
  readonly orgKey: string;
  readonly convexUrl: string;
  readonly command?: string;
}): readonly Snippet[] {
  const token = input.token ?? PLACEHOLDER;
  const { orgKey, convexUrl } = input;
  const command = input.command?.trim() || DEFAULT_COMMAND[input.target];

  switch (input.target) {
    case "computer":
      return [
        {
          id: "shell",
          label: "macOS / Linux",
          code: [
            `export SLUICE_TOKEN='${token}'`,
            `export SLUICE_ORG_REVOCATION_PUBLIC_KEY='${orgKey}'`,
            `export SLUICE_CONVEX_URL='${convexUrl}'`,
            "",
            `sluice run -- ${command}`,
          ].join("\n"),
          note: "Put the three export lines in your shell profile (~/.zshrc or ~/.bashrc) so every terminal has them.",
        },
        {
          id: "powershell",
          label: "Windows",
          code: [
            `$env:SLUICE_TOKEN = '${token}'`,
            `$env:SLUICE_ORG_REVOCATION_PUBLIC_KEY = '${orgKey}'`,
            `$env:SLUICE_CONVEX_URL = '${convexUrl}'`,
            "",
            `sluice run -- ${command}`,
          ].join("\n"),
          note: "For every new window, add the three lines to your PowerShell profile ($PROFILE).",
        },
      ];
    case "server":
      return [
        {
          id: "command",
          label: "Command",
          code: [
            `SLUICE_TOKEN='${token}' \\`,
            `SLUICE_ORG_REVOCATION_PUBLIC_KEY='${orgKey}' \\`,
            `SLUICE_CONVEX_URL='${convexUrl}' \\`,
            `sluice run -- ${command}`,
          ].join("\n"),
          note: "Run it from your app's folder on the server.",
        },
        {
          id: "systemd",
          label: "systemd",
          code: [
            "# /etc/systemd/system/app.service",
            "[Service]",
            `Environment=SLUICE_TOKEN=${token}`,
            `Environment=SLUICE_ORG_REVOCATION_PUBLIC_KEY=${orgKey}`,
            `Environment=SLUICE_CONVEX_URL=${convexUrl}`,
            "WorkingDirectory=/srv/app",
            `ExecStart=/usr/local/bin/sluice run -- ${command}`,
            "Restart=always",
          ].join("\n"),
          note: "Then: sudo systemctl daemon-reload && sudo systemctl enable --now app. Make the unit file readable by root only.",
        },
        {
          id: "pm2",
          label: "PM2",
          code: [
            "// ecosystem.config.js",
            "module.exports = {",
            "  apps: [{",
            '    name: "app",',
            '    script: "sluice",',
            `    args: ${JSON.stringify(`run -- ${command}`)},`,
            '    interpreter: "none",',
            "    env: {",
            `      SLUICE_TOKEN: ${JSON.stringify(token)},`,
            `      SLUICE_ORG_REVOCATION_PUBLIC_KEY: ${JSON.stringify(orgKey)},`,
            `      SLUICE_CONVEX_URL: ${JSON.stringify(convexUrl)},`,
            "    },",
            "  }],",
            "};",
          ].join("\n"),
          note: "Then: pm2 start ecosystem.config.js. Keep this file out of version control.",
        },
      ];
    case "ci":
      return [
        {
          id: "github",
          label: "GitHub Actions",
          code: [
            "- run: npm install -g @sluice/cli",
            `- run: sluice run -- ${command}`,
            "  env:",
            "    SLUICE_TOKEN: ${{ secrets.SLUICE_TOKEN }}",
            `    SLUICE_ORG_REVOCATION_PUBLIC_KEY: ${orgKey}`,
            `    SLUICE_CONVEX_URL: ${convexUrl}`,
          ].join("\n"),
          note: "First add the token as a repository secret named SLUICE_TOKEN (Settings → Secrets and variables → Actions).",
        },
        {
          id: "gitlab",
          label: "GitLab CI",
          code: [
            "test:",
            "  variables:",
            `    SLUICE_ORG_REVOCATION_PUBLIC_KEY: ${orgKey}`,
            `    SLUICE_CONVEX_URL: ${convexUrl}`,
            "  script:",
            "    - npm install -g @sluice/cli",
            `    - sluice run -- ${command}`,
            "# SLUICE_TOKEN comes from a masked CI/CD variable.",
          ].join("\n"),
          note: "First add the token as a masked CI/CD variable named SLUICE_TOKEN (Settings → CI/CD → Variables).",
        },
      ];
    case "docker":
      return [
        {
          id: "run",
          label: "docker run",
          code: [
            "# Dockerfile",
            "RUN npm install -g @sluice/cli",
            `CMD ["sluice", "run", "--", ${execForm(command)}]`,
            "",
            "# SLUICE_TOKEN is read from your shell or secret store, not written here.",
            "docker run \\",
            "  -e SLUICE_TOKEN \\",
            `  -e SLUICE_ORG_REVOCATION_PUBLIC_KEY=${orgKey} \\`,
            `  -e SLUICE_CONVEX_URL=${convexUrl} \\`,
            "  your-image",
          ].join("\n"),
          note: "Set SLUICE_TOKEN in the shell or secret store that runs the container.",
        },
        {
          id: "compose",
          label: "Compose",
          code: [
            "# Dockerfile",
            "RUN npm install -g @sluice/cli",
            `CMD ["sluice", "run", "--", ${execForm(command)}]`,
            "",
            "# compose.yaml",
            "services:",
            "  app:",
            "    build: .",
            "    environment:",
            "      SLUICE_TOKEN: ${SLUICE_TOKEN}",
            `      SLUICE_ORG_REVOCATION_PUBLIC_KEY: ${orgKey}`,
            `      SLUICE_CONVEX_URL: ${convexUrl}`,
          ].join("\n"),
          note: "Compose reads SLUICE_TOKEN from your shell or an .env file kept out of version control.",
        },
      ];
  }
}
