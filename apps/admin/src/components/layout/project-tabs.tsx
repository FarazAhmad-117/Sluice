import { NavLink } from "react-router";
import { focusRing } from "@/components/ui/styles";

/**
 * THE TAB BAR UNDER THE HEADER.
 *
 * Only the tabs that lead somewhere: this slice has the projects list at org
 * level and the secrets page at project level, so each bar has one tab. A tab
 * for a screen that does not exist yet would be a dead control. More are added
 * here as their screens land, which is why this is a bar of one rather than a
 * page heading.
 */

const TAB = `-mb-px flex h-11 items-center border-b-2 px-2.5 text-sm no-underline transition-colors ${focusRing}`;

function TabBar({ label, tabs }: { readonly label: string; readonly tabs: readonly { to: string; label: string }[] }) {
  return (
    <nav aria-label={label} className="flex gap-1 overflow-x-auto border-b border-hairline px-2 sm:px-4">
      {tabs.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          className={({ isActive }) =>
            `${TAB} ${
              isActive
                ? "border-text-primary text-text-primary"
                : "border-transparent text-text-muted hover:text-text-primary"
            }`
          }
        >
          {tab.label}
        </NavLink>
      ))}
    </nav>
  );
}

export function OrgTabs() {
  return <TabBar label="Organisation" tabs={[{ to: "/projects", label: "Projects" }]} />;
}

export function ProjectTabs({ slug }: { readonly slug: string }) {
  return <TabBar label="Project" tabs={[{ to: `/projects/${slug}/secrets`, label: "Secrets" }]} />;
}
