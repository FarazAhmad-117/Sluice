import { describe, expect, it } from "vitest";
import { setupSnippets } from "../src/lib/tokens/snippets";
import type { TokenTarget } from "../src/lib/tokens/token-crypto";

const TOKEN = `slc_production_${"ab".repeat(16)}.${"cd".repeat(32)}`;
const ORG_KEY = "ef".repeat(32);
const CONVEX_URL = "https://hearty-butterfly-862.convex.cloud";
const base = { token: TOKEN, orgKey: ORG_KEY, convexUrl: CONVEX_URL };

describe("setupSnippets", () => {
  it("gives every target at least one way to start, each naming all three variables", () => {
    for (const target of ["computer", "server", "ci", "docker"] as TokenTarget[]) {
      const snippets = setupSnippets({ ...base, target });
      expect(snippets.length).toBeGreaterThan(0);
      for (const snippet of snippets) {
        for (const name of ["SLUICE_TOKEN", "SLUICE_ORG_REVOCATION_PUBLIC_KEY", "SLUICE_CONVEX_URL"]) {
          expect(snippet.code, `${target}/${snippet.id} names ${name}`).toContain(name);
        }
        // As a shell line, or split into exec form for Docker and PM2.
        expect(snippet.code).toMatch(/sluice run --|"sluice", "run", "--"|script: "sluice"/);
      }
    }
  });

  it("puts the token itself only where the person keeps it on that machine", () => {
    const inline = (target: TokenTarget) =>
      setupSnippets({ ...base, target }).filter((snippet) => snippet.code.includes(TOKEN)).map((snippet) => snippet.id);
    expect(inline("computer")).toEqual(["shell", "powershell"]);
    expect(inline("server")).toEqual(["command", "systemd", "pm2"]);
    // CI and containers read it from a secret store, never from a file in the repo.
    expect(inline("ci")).toEqual([]);
    expect(inline("docker")).toEqual([]);
  });

  it("references the CI secret by name instead", () => {
    const [actions] = setupSnippets({ ...base, target: "ci" });
    expect(actions?.code).toContain("${{ secrets.SLUICE_TOKEN }}");
    expect(actions?.code).toContain(ORG_KEY);
  });

  it("uses the person's command when given, and a sensible default per target otherwise", () => {
    expect(setupSnippets({ ...base, target: "computer" })[0]?.code).toContain("sluice run -- npm run dev");
    expect(setupSnippets({ ...base, target: "server" })[0]?.code).toContain("sluice run -- npm start");
    expect(setupSnippets({ ...base, target: "server", command: "python app.py" })[0]?.code).toContain(
      "sluice run -- python app.py",
    );
  });

  it("shows a placeholder, not a token, before one exists", () => {
    const [shell] = setupSnippets({ ...base, token: null, target: "computer" });
    expect(shell?.code).toContain("<your token>");
  });
});
