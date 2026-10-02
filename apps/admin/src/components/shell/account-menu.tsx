import { useNavigate } from "react-router";
import { IconChevronUpDown } from "@/components/ui/icons";
import { Menu, MenuDivider, MenuItem, MenuNote, MenuRadio } from "@/components/ui/menu";
import { useAuth } from "@/lib/auth/auth-context";
import { useTheme } from "@/lib/theme";
import type { ThemeChoice } from "@/lib/theme";

/**
 * THE SIDEBAR'S BOTTOM ROW: WHO IS SIGNED IN, THE THEME, AND SIGN OUT.
 *
 * The menu opens upward on its own (`placeMenu` flips it when there is no
 * room below), so it is never cut off by the bottom of the window.
 */

const THEMES: readonly { value: ThemeChoice; label: string }[] = [
  { value: "system", label: "System theme" },
  { value: "light", label: "Light theme" },
  { value: "dark", label: "Dark theme" },
];

export function Avatar({ email, size = "md" }: { readonly email: string; readonly size?: "sm" | "md" }) {
  return (
    <span
      aria-hidden="true"
      className={`flex shrink-0 items-center justify-center rounded-full border border-hairline-strong bg-surface-card font-semibold text-text-primary ${
        size === "md" ? "size-7 text-xs" : "size-6 text-[11px]"
      }`}
    >
      {email.slice(0, 1).toUpperCase() || "?"}
    </span>
  );
}

export function AccountMenu() {
  const { session, logout } = useAuth();
  const { choice, setChoice } = useTheme();
  const navigate = useNavigate();
  const email = session?.email ?? "";

  return (
    <div className="mt-1.5 border-t border-hairline pt-1.5">
      <Menu
        label={`Account: ${email}`}
        triggerClassName="flex h-12 w-full cursor-pointer items-center gap-2.5 rounded-input bg-transparent px-2 text-left text-text-primary transition-colors hover:bg-surface-card"
        trigger={
          <>
            <Avatar email={email} />
            <span className="min-w-0 grow truncate text-[13px]">{email}</span>
            <IconChevronUpDown className="size-3.5 shrink-0 text-text-muted" />
          </>
        }
      >
        <MenuNote>
          Signed in as <span className="text-text-primary">{email}</span>
        </MenuNote>
        <MenuDivider />
        {THEMES.map((theme) => (
          <MenuRadio key={theme.value} checked={choice === theme.value} onSelect={() => setChoice(theme.value)}>
            {theme.label}
          </MenuRadio>
        ))}
        <MenuDivider />
        <MenuItem
          onSelect={() => {
            void logout().then(() => navigate("/login", { replace: true }));
          }}
        >
          Sign out
        </MenuItem>
      </Menu>
    </div>
  );
}
