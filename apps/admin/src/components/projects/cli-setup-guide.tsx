import { useId, useState } from "react";
import type { ReactNode } from "react";
import { CommandBlock } from "@/components/ui/copy-button";
import { IconExternal } from "@/components/ui/icons";
import { Segmented } from "@/components/ui/segmented";
import { focusRing } from "@/components/ui/styles";
import {
  CLI_RELEASED,
  INSTALL_METHODS,
  INSTALL_METHOD_KEY,
  RELEASES_URL,
  defaultInstallMethod,
  installMethod,
  isInstallMethodId,
} from "@/lib/projects/install";
import type { InstallMethodId } from "@/lib/projects/install";

/**
 * GETTING ONE COMPUTER TO RUN AN APP THROUGH SLUICE: INSTALL, CONNECT, RUN.
 *
 * The install step offers every channel as a tab, opening on the one that
 * fits this machine and remembering the person's pick in this browser. Until
 * the CLI is published (`CLI_RELEASED`), the steps are shown as they will be,
 * under a plain note, with no Copy buttons: nobody should paste a command that
 * fails.
 */

function initialMethod(): InstallMethodId {
  try {
    const saved = localStorage.getItem(INSTALL_METHOD_KEY);
    if (isInstallMethodId(saved)) return saved;
  } catch {
    // Storage blocked: fall through to the platform guess.
  }
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return defaultInstallMethod(nav.userAgentData?.platform ?? nav.platform ?? "");
}

export function CliSetupGuide({
  runCommand,
  environmentName,
  onAnnounce,
}: {
  readonly runCommand: string;
  readonly environmentName: string;
  readonly onAnnounce?: (message: string) => void;
}) {
  const id = useId();
  const [method, setMethod] = useState<InstallMethodId>(initialMethod);
  const chosen = installMethod(method);
  const choose = (next: InstallMethodId) => {
    setMethod(next);
    try {
      localStorage.setItem(INSTALL_METHOD_KEY, next);
    } catch {
      // Not remembered; the tab still changes.
    }
  };
  const copy = { copyable: CLI_RELEASED, ...(onAnnounce === undefined ? {} : { onDone: onAnnounce }) };

  return (
    <div className="flex flex-col gap-4">
      {CLI_RELEASED ? null : (
        <p className="m-0 rounded-input border border-status-warning/30 bg-status-warning/8 px-3 py-2.5 text-[13px] leading-relaxed text-text-body">
          <span className="font-medium text-text-primary">The CLI isn’t released yet.</span> These are the steps
          it will use, so you can see what’s coming. Nothing here can be copied until it ships.{" "}
          <a
            href={RELEASES_URL}
            target="_blank"
            rel="noreferrer"
            className={`inline-flex items-center gap-1 rounded-sm font-medium text-brand no-underline hover:text-brand-hover ${focusRing}`}
          >
            Watch for the release
            <IconExternal className="size-3" />
            <span className="sr-only"> (opens in a new tab)</span>
          </a>
        </p>
      )}
      <ol className="m-0 flex list-none flex-col gap-5 p-0">
        <GuideStep number={1} title="Install the CLI">
          <Segmented
            variant="underline"
            label="Install with"
            idPrefix={`${id}-install`}
            panelId={`${id}-install-panel`}
            options={INSTALL_METHODS.map((option) => ({ value: option.id, label: option.label }))}
            value={method}
            onChange={choose}
          />
          <div
            id={`${id}-install-panel`}
            role="tabpanel"
            aria-labelledby={`${id}-install-${method}`}
            className="flex flex-col gap-2 pt-1"
          >
            <CommandBlock command={chosen.command} label={`Copy the ${chosen.label} install command`} {...copy} />
            <p className="m-0 text-[13px] text-text-muted">
              {chosen.note} Check it worked with <code className="font-mono text-[12.5px] text-text-body">sluice --version</code>.
            </p>
          </div>
        </GuideStep>
        <GuideStep number={2} title="Connect this computer">
          <CommandBlock command="sluice login" label="Copy the login command" {...copy} />
          <p className="m-0 text-[13px] text-text-muted">
            Opens your browser so you can approve this computer. Its key stays on this machine.
          </p>
        </GuideStep>
        <GuideStep number={3} title={`Run your app with ${environmentName} secrets`}>
          <CommandBlock command={runCommand} label="Copy the run command" {...copy} />
          <p className="m-0 text-[13px] text-text-muted">
            Run it from your project’s folder. Replace <code className="font-mono text-[12.5px] text-text-body">npm run dev</code>{" "}
            with any command: python, go, rails, docker. No .env file needed.
          </p>
        </GuideStep>
      </ol>
    </div>
  );
}

function GuideStep({ number, title, children }: { readonly number: number; readonly title: string; readonly children: ReactNode }) {
  return (
    <li className="flex gap-3">
      <span
        aria-hidden
        className="flex size-6 shrink-0 items-center justify-center rounded-full border border-hairline-strong font-mono text-xs text-text-muted"
      >
        {number}
      </span>
      <div className="flex min-w-0 grow flex-col gap-2">
        <h3 className="m-0 pt-0.5 text-sm font-medium text-text-primary">
          <span className="sr-only">Step {number}: </span>
          {title}
        </h3>
        {children}
      </div>
    </li>
  );
}
