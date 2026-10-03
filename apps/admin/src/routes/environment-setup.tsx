import { useId, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode, RefObject } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { InstallCliTabs } from "@/components/projects/cli-setup-guide";
import { PageHeader } from "@/components/shell/page-header";
import { ProjectNotFound } from "@/components/shell/project-states";
import { ConnectionChip } from "@/components/tokens/token-list";
import { Button } from "@/components/ui/button";
import { CommandBlock } from "@/components/ui/copy-button";
import { Callout, Skeleton } from "@/components/ui/feedback";
import { RadioCard, TextField } from "@/components/ui/field";
import { IconCheck } from "@/components/ui/icons";
import { Segmented } from "@/components/ui/segmented";
import { focusRing, pageGutter } from "@/components/ui/styles";
import { CONVEX_URL } from "@/lib/convex-url";
import { CLI_RELEASED } from "@/lib/projects/install";
import { timeAgo } from "@/lib/format/time";
import { useNow } from "@/lib/format/use-now";
import { useProject } from "@/lib/projects/project-context";
import type { ProjectDataKeyState } from "@/lib/secrets/environment-key";
import { useShell } from "@/lib/shell/shell-context";
import { connectionState } from "@/lib/tokens/connection";
import { setupSnippets } from "@/lib/tokens/snippets";
import { TOKEN_NAME_MAX_BYTES, tokenNameProblem } from "@/lib/tokens/token-crypto";
import type { IssuedToken, TokenTarget } from "@/lib/tokens/token-crypto";
import { useProjectTokens } from "@/lib/tokens/use-project-tokens";
import { useCreateToken, useOrgRevocationKey } from "@/lib/tokens/use-token-actions";

/**
 * CONNECT ONE PLACE TO AN ENVIRONMENT: PICK WHERE, NAME IT, GET ITS TOKEN,
 * INSTALL, START, AND WATCH IT CONNECT.
 *
 * The approved Round 2 setup screens, in one flow. Each place gets its own
 * token, so it can be revoked without touching anything else. The token is
 * minted in this browser, shown once, and held only in this component's
 * memory: it is never put in a URL, in storage or in a log, and leaving the
 * page drops it.
 */

interface TargetOption {
  readonly value: TokenTarget;
  readonly label: string;
  readonly description: string;
  readonly defaultName: string;
}

const TARGETS: readonly TargetOption[] = [
  { value: "computer", label: "My computer", description: "Local development", defaultName: "my-laptop" },
  { value: "server", label: "A server", description: "VPS or bare metal", defaultName: "server-1" },
  { value: "ci", label: "CI pipeline", description: "GitHub Actions and others", defaultName: "ci" },
  { value: "docker", label: "Docker", description: "Containers", defaultName: "container" },
];

function isTarget(value: string | null): value is TokenTarget {
  return TARGETS.some((option) => option.value === value);
}

function defaultNameFor(target: TokenTarget): string {
  return TARGETS.find((option) => option.value === target)?.defaultName ?? "";
}

export default function EnvironmentSetupRoute() {
  const { slug, data } = useProject();
  const params = useParams();
  const environmentName = params["environmentName"] ?? "";

  if (data.status === "not-found") return <ProjectNotFound slug={slug} title="Set up" />;
  if (data.status === "loading") {
    return (
      <>
        <PageHeader title="Set up" crumbs={[{ label: slug, to: `/projects/${slug}` }]} />
        <div className={`flex max-w-[760px] flex-col gap-4 py-6 ${pageGutter}`}>
          <Skeleton className="h-8 w-72" />
          <Skeleton className="h-40 rounded-card" />
        </div>
      </>
    );
  }
  const environment = data.environments.find((candidate) => candidate.name === environmentName);
  if (environment === undefined) {
    return (
      <>
        <PageHeader title="Set up" crumbs={[{ label: data.project.name, to: `/projects/${slug}` }]} />
        <div className={`max-w-[760px] py-6 ${pageGutter}`}>
          <Callout
            tone="neutral"
            title={`This project has no environment called ${environmentName}`}
            action={<Button to={`/projects/${slug}/environments`}>See environments</Button>}
          >
            It may have been renamed, or the link is wrong.
          </Callout>
        </div>
      </>
    );
  }
  return (
    <SetupFlow
      // A fresh flow, and no token carried over, when the environment changes.
      key={environment.environmentId}
      slug={slug}
      projectName={data.project.name}
      environmentId={environment.environmentId}
      environmentName={environment.name}
      keyState={data.keys.get(environment.environmentId)}
    />
  );
}

function SetupFlow({
  slug,
  projectName,
  environmentId,
  environmentName,
  keyState,
}: {
  readonly slug: string;
  readonly projectName: string;
  readonly environmentId: string;
  readonly environmentName: string;
  readonly keyState: ProjectDataKeyState | undefined;
}) {
  const [search] = useSearchParams();
  const requested = search.get("target");
  const initialTarget: TokenTarget = isTarget(requested)
    ? requested
    : environmentName === "development"
      ? "computer"
      : "server";
  const [target, setTarget] = useState<TokenTarget>(initialTarget);
  const [name, setName] = useState(() => defaultNameFor(initialTarget));
  const [nameEdited, setNameEdited] = useState(false);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ token: IssuedToken; serviceTokenId: string; name: string } | null>(null);
  const create = useCreateToken();
  const { announce } = useShell();
  const tokenHeading = useRef<HTMLHeadingElement>(null);

  const problem = tokenNameProblem(name);
  const key = keyState?.status === "ready" ? keyState.key : null;

  const pickTarget = (next: TokenTarget) => {
    setTarget(next);
    if (!nameEdited) setName(defaultNameFor(next));
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (problem !== null || busy || issued !== null) return;
    if (key === null) {
      setError("This environment's key isn't open in this browser, so no token can be made for it here.");
      return;
    }
    setBusy(true);
    setError(null);
    const result = await create({ environmentId, environmentName, key, name, target });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setIssued({ ...result.value, name: name.trim() });
    announce(`Token created for ${name.trim()}. Copy it now: it is shown once.`);
    requestAnimationFrame(() => tokenHeading.current?.focus());
  };

  return (
    <>
      <PageHeader
        title={`Set up ${environmentName}`}
        crumbs={[
          { label: projectName, to: `/projects/${slug}` },
          { label: "Environments", to: `/projects/${slug}/environments` },
        ]}
        actions={
          <Button size="sm" variant="secondary" to={`/projects/${slug}/environments`}>
            {issued === null ? "Cancel" : "Done"}
          </Button>
        }
      />
      <div className={`flex max-w-[760px] flex-col gap-6 py-6 ${pageGutter}`}>
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">
            Connect a place to <span className="font-mono">{environmentName}</span>
          </h1>
          <p className="m-0 text-text-muted">
            It gets its own token, so you can revoke it without touching anything else.
          </p>
        </div>

        {keyState !== undefined && keyState.status !== "ready" && keyState.status !== "loading" ? (
          <Callout tone="warning" title="This environment's key isn't open here">
            You need a key for {environmentName} to create a token for it. Ask someone who has one, or unlock with
            your password.
          </Callout>
        ) : null}

        <ol className="m-0 flex list-none flex-col gap-0 p-0">
          <Step number={1} title={`Where will ${environmentName} run?`} done={issued !== null}>
            <fieldset className="m-0 grid min-w-0 gap-3 border-0 p-0 sm:grid-cols-2" disabled={issued !== null}>
              <legend className="sr-only">Where will {environmentName} run?</legend>
              {TARGETS.map((candidate) => (
                <RadioCard
                  key={candidate.value}
                  name="target"
                  value={candidate.value}
                  checked={target === candidate.value}
                  onChange={() => pickTarget(candidate.value)}
                  label={candidate.label}
                  description={candidate.description}
                />
              ))}
            </fieldset>
          </Step>

          <Step number={2} title="Name it and create its token" done={issued !== null}>
            {issued === null ? (
              <form onSubmit={(event) => void submit(event)} noValidate className="flex flex-col gap-4">
                <TextField
                  label="Name"
                  value={name}
                  maxLength={TOKEN_NAME_MAX_BYTES}
                  autoComplete="off"
                  spellCheck={false}
                  hint="So you can tell it apart in the list, and revoke the right one."
                  error={touched ? problem : null}
                  onChange={(event) => {
                    setName(event.target.value);
                    setNameEdited(true);
                  }}
                  onBlur={() => setTouched(true)}
                />
                {error === null ? null : (
                  <Callout tone="danger" role="alert" title="No token was created">
                    {error}
                  </Callout>
                )}
                <div>
                  <Button type="submit" loading={busy} loadingLabel="Creating…" disabled={key === null}>
                    Create token
                  </Button>
                </div>
              </form>
            ) : (
              <IssuedTokenBlock issued={issued} headingRef={tokenHeading} target={target} onAnnounce={announce} />
            )}
          </Step>

          <Step number={3} title="Install the CLI" done={false}>
            {CLI_RELEASED ? null : (
              <p className="m-0 rounded-input border border-status-warning/30 bg-status-warning/8 px-3 py-2.5 text-[13px] leading-relaxed text-text-body">
                <span className="font-medium text-text-primary">The CLI isn’t published yet.</span> These are the
                commands it will ship with; until then, build it from the repository
                (<code className="font-mono text-[12.5px]">pnpm --filter @getsluice/cli build</code>).
              </p>
            )}
            <InstallCliTabs onAnnounce={announce} />
          </Step>

          <Step number={4} title="Start your app through Sluice" done={false}>
            <StartSnippets target={target} token={issued?.token ?? null} onAnnounce={announce} />
          </Step>

          <Step number={5} title="Wait for it to connect" done={false} last>
            {issued === null ? (
              <p className="m-0 text-sm text-text-muted">Create the token first. This page updates when it connects.</p>
            ) : (
              <ConnectionWatch serviceTokenId={issued.serviceTokenId} name={issued.name} slug={slug} />
            )}
          </Step>
        </ol>
      </div>
    </>
  );
}

function Step({
  number,
  title,
  done,
  last = false,
  children,
}: {
  readonly number: number;
  readonly title: string;
  readonly done: boolean;
  readonly last?: boolean;
  readonly children: ReactNode;
}) {
  return (
    <li className="flex gap-4">
      <div className="flex flex-col items-center">
        {done ? (
          <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-status-healthy text-surface-base">
            <IconCheck className="size-3.5" strokeWidth={3} />
            <span className="sr-only">Done:</span>
          </span>
        ) : (
          <span className="flex size-7 shrink-0 items-center justify-center rounded-full border border-hairline-strong font-mono text-xs text-text-muted">
            {number}
          </span>
        )}
        {last ? null : <span aria-hidden className="w-px grow bg-hairline" />}
      </div>
      <div className={`flex min-w-0 grow flex-col gap-3 ${last ? "" : "pb-8"}`}>
        <h2 className="m-0 pt-0.5 text-base font-semibold text-text-primary">{title}</h2>
        {children}
      </div>
    </li>
  );
}

function IssuedTokenBlock({
  issued,
  headingRef,
  target,
  onAnnounce,
}: {
  readonly issued: { token: IssuedToken; name: string };
  readonly headingRef: RefObject<HTMLHeadingElement | null>;
  readonly target: TokenTarget;
  readonly onAnnounce: (message: string) => void;
}) {
  const where =
    target === "ci"
      ? "Add it to your CI as a secret named SLUICE_TOKEN."
      : target === "docker"
        ? "Keep it in the secret store or shell that starts your containers."
        : "It goes into the commands below.";
  return (
    <div className="flex flex-col gap-3 rounded-card border border-status-warning/30 bg-status-warning/6 p-4">
      <h3 ref={headingRef} tabIndex={-1} className="m-0 text-sm font-semibold text-text-primary outline-none">
        Token for {issued.name}
      </h3>
      <CommandBlock command={issued.token.reveal()} label="Copy the token" onDone={onAnnounce} />
      <p className="m-0 text-[13px] text-text-body">
        <span className="font-medium text-text-primary">Copy it now.</span> It is shown once: Sluice never stored it,
        so it can't show it again. {where}
      </p>
    </div>
  );
}

function StartSnippets({
  target,
  token,
  onAnnounce,
}: {
  readonly target: TokenTarget;
  readonly token: IssuedToken | null;
  readonly onAnnounce: (message: string) => void;
}) {
  const id = useId();
  const orgKey = useOrgRevocationKey();
  const [command, setCommand] = useState("");
  const [tab, setTab] = useState<string | null>(null);
  const snippets = useMemo(
    () =>
      typeof orgKey !== "string" || CONVEX_URL === undefined
        ? null
        : setupSnippets({ target, token: token?.reveal() ?? null, orgKey, convexUrl: CONVEX_URL, command }),
    [target, token, orgKey, command],
  );
  if (orgKey === undefined) return <Skeleton className="h-32 rounded-input" />;
  const current = snippets?.find((snippet) => snippet.id === tab) ?? snippets?.[0];
  if (snippets === null || current === undefined) {
    return (
      <Callout tone="danger" title="The organisation's revocation key could not be read">
        Reload to try again. Every process pins it, so the commands can't be shown without it.
      </Callout>
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <TextField
        label="Your start command"
        mono
        value={command}
        placeholder={target === "ci" ? "npm test" : target === "computer" ? "npm run dev" : "npm start"}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => setCommand(event.target.value)}
      />
      {snippets.length > 1 ? (
        <Segmented
          variant="underline"
          label="Start with"
          idPrefix={`${id}-start`}
          panelId={`${id}-start-panel`}
          options={snippets.map((snippet) => ({ value: snippet.id, label: snippet.label }))}
          value={current.id}
          onChange={setTab}
        />
      ) : null}
      <div
        id={`${id}-start-panel`}
        role={snippets.length > 1 ? "tabpanel" : undefined}
        aria-labelledby={snippets.length > 1 ? `${id}-start-${current.id}` : undefined}
        className="flex flex-col gap-2"
      >
        <pre className="m-0 rounded-input border border-hairline bg-surface-deep p-3 font-mono text-[12.5px] leading-relaxed whitespace-pre-wrap text-text-primary [overflow-wrap:anywhere]">
          <code>{current.code}</code>
        </pre>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="m-0 min-w-0 grow basis-60 text-[13px] text-text-muted">{current.note}</p>
          <CopyCode code={current.code} label={`Copy the ${current.label} snippet`} onAnnounce={onAnnounce} />
        </div>
        {token === null ? (
          <p className="m-0 text-[13px] text-text-muted">The token appears here once you create it in step 2.</p>
        ) : null}
        <p className="m-0 text-[13px] text-text-muted">
          <span className="font-medium text-text-body">SLUICE_ORG_REVOCATION_PUBLIC_KEY</span> is your organisation's
          public key. Every process checks revocations against the copy you give it, never one fetched from Sluice.
        </p>
      </div>
    </div>
  );
}

function CopyCode({
  code,
  label,
  onAnnounce,
}: {
  readonly code: string;
  readonly label: string;
  readonly onAnnounce: (message: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      variant="secondary"
      aria-label={label}
      onClick={() => {
        void navigator.clipboard.writeText(code).then(
          () => {
            setCopied(true);
            onAnnounce("Copied.");
            window.setTimeout(() => setCopied(false), 2000);
          },
          () => onAnnounce("Could not copy. Select the text and copy it instead."),
        );
      }}
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function ConnectionWatch({
  serviceTokenId,
  name,
  slug,
}: {
  readonly serviceTokenId: string;
  readonly name: string;
  readonly slug: string;
}) {
  const tokens = useProjectTokens();
  const now = useNow();
  const row = tokens?.find((candidate) => candidate.serviceTokenId === serviceTokenId);
  const state = row === undefined ? "never" : connectionState(row, now);

  if (state === "never") {
    return (
      <div role="status" className="flex items-center gap-3 rounded-card border border-dashed border-hairline-strong px-4 py-3.5">
        <span aria-hidden className="size-2 shrink-0 animate-pulse rounded-full bg-text-muted motion-reduce:animate-none" />
        <span className="text-sm text-text-body">Waiting for {name} to connect… This page updates the moment it does.</span>
      </div>
    );
  }
  return (
    <div
      role="status"
      className="flex flex-wrap items-center justify-between gap-3 rounded-card border border-status-healthy/40 bg-status-healthy/8 px-4 py-3.5"
    >
      <div className="flex flex-col gap-0.5">
        <span className="font-medium text-text-primary">
          {name} {state === "live" ? "is connected" : "has connected"}
        </span>
        {row?.lastSeenAt === null || row?.lastSeenAt === undefined ? null : (
          <span className="text-[13px] text-text-muted">Last seen {timeAgo(row.lastSeenAt, now)}</span>
        )}
      </div>
      <div className="flex items-center gap-3">
        <ConnectionChip state={state} />
        <Link
          to={`/projects/${slug}/environments`}
          className={`rounded-sm text-sm font-medium text-brand no-underline hover:text-brand-hover ${focusRing}`}
        >
          View environments
        </Link>
      </div>
    </div>
  );
}
