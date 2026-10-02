import { useTheme } from "@/lib/theme";
import type { ThemeChoice } from "@/lib/theme";

/**
 * Three states, not two. "System" is a real choice and it is the default, so it
 * has to be reachable: a two-way toggle silently converts the first click into
 * a permanent override, and the viewer can never get back to following their
 * operating system without clearing site data.
 *
 * A radio group rather than three buttons, because that is what it is: one
 * choice from a fixed set. Screen readers announce the group name and the
 * selected option, and arrow keys move between them, for free. Each option is
 * 44px tall, the touch-target floor.
 */
const OPTIONS: ReadonlyArray<{ value: ThemeChoice; label: string; title: string }> = [
  { value: "system", label: "Auto", title: "Follow the operating system preference" },
  { value: "light", label: "Light", title: "Always light" },
  { value: "dark", label: "Dark", title: "Always dark" },
];

export function ThemeToggle() {
  const { choice, setChoice } = useTheme();

  return (
    <fieldset className="m-0 flex items-center gap-1 rounded-input border border-hairline p-0.5">
      <legend className="sr-only">Colour theme</legend>
      {OPTIONS.map((option) => {
        const selected = choice === option.value;
        return (
          <label
            key={option.value}
            title={option.title}
            className={`flex min-h-10 cursor-pointer items-center rounded-[6px] px-2.5 text-[13px] transition-colors focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-brand ${
              selected ? "bg-surface-card text-text-primary" : "text-text-muted hover:text-text-primary"
            }`}
          >
            <input
              type="radio"
              name="sluice-theme"
              value={option.value}
              checked={selected}
              onChange={() => setChoice(option.value)}
              className="sr-only"
            />
            {option.label}
          </label>
        );
      })}
    </fieldset>
  );
}
