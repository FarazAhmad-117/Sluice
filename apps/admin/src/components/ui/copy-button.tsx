import { useEffect, useState } from "react";
import { IconCheck, IconCopy } from "./icons";
import { focusRing } from "./styles";

/**
 * COPY TO THE CLIPBOARD, AND SAY SO.
 *
 * `text` is a value or a function that produces one, so a secret value is
 * decrypted at the moment it is copied and never sooner: nothing is shown on
 * screen to copy it. The icon turns to a check for two seconds and `onDone`
 * gets a sentence for the page's live region.
 */
export function CopyButton({
  text,
  label,
  onDone,
  className = "",
}: {
  readonly text: string | (() => Promise<string>);
  /** The accessible name: "Copy the run command", "Copy value of API_URL". */
  readonly label: string;
  readonly onDone?: (message: string) => void;
  readonly className?: string;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 2_000);
    return () => clearTimeout(timer);
  }, [copied]);

  return (
    <button
      type="button"
      aria-label={label}
      onClick={() => {
        void (async () => {
          try {
            await navigator.clipboard.writeText(typeof text === "string" ? text : await text());
            setCopied(true);
            onDone?.("Copied.");
          } catch {
            onDone?.("That could not be copied.");
          }
        })();
      }}
      className={`inline-flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-input text-text-muted transition-colors hover:bg-surface-card hover:text-text-primary lg:size-8 lg:pointer-coarse:size-11 ${focusRing} ${className}`}
    >
      {copied ? <IconCheck className="size-[15px] text-status-healthy" /> : <IconCopy className="size-[15px]" />}
    </button>
  );
}

/** A code well with the command in it and a copy button beside it. */
export function CommandBlock({
  command,
  label,
  onDone,
  copyable = true,
}: {
  readonly command: string;
  readonly label: string;
  readonly onDone?: (message: string) => void;
  /** False for a command that cannot work yet: shown, muted, with no Copy button. */
  readonly copyable?: boolean;
}) {
  return (
    <div className="flex items-start gap-1 rounded-input border border-hairline bg-surface-deep py-1 pr-1 pl-3">
      <code
        className={`min-w-0 grow py-2 font-mono text-[12.5px] leading-relaxed break-words ${
          copyable ? "text-text-primary" : "pr-2 text-text-muted"
        }`}
      >
        {command}
      </code>
      {copyable ? <CopyButton text={command} label={label} {...(onDone === undefined ? {} : { onDone })} /> : null}
    </div>
  );
}
