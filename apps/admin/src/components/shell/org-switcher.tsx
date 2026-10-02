import { useNavigate } from "react-router";
import { IconChevronUpDown } from "@/components/ui/icons";
import { Menu, MenuDivider, MenuLink, MenuNote, MenuRadio } from "@/components/ui/menu";
import { Skeleton } from "@/components/ui/feedback";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";

/**
 * THE SIDEBAR'S TOP ROW: WHICH ORGANISATION, AND A MENU TO CHANGE IT.
 *
 * The brand-filled tile is the org's initial. Choosing another org goes to its
 * projects, because the project on screen belongs to the org being left.
 */

export function OrgTile({ name, size = "md" }: { readonly name: string; readonly size?: "sm" | "md" }) {
  return (
    <span
      aria-hidden="true"
      className={`flex shrink-0 items-center justify-center bg-brand-solid font-bold text-text-on-brand-solid ${
        size === "md" ? "size-[26px] rounded-[7px] text-[13px]" : "size-5 rounded-[5px] text-[11px]"
      }`}
    >
      {name.slice(0, 1).toUpperCase()}
    </span>
  );
}

export function OrgSwitcher({ reserveEnd = false }: { readonly reserveEnd?: boolean }) {
  const { org, orgs, setOrg } = useCurrentOrg();
  const navigate = useNavigate();

  if (org === null || orgs === undefined) {
    return (
      <div aria-hidden="true" className={`flex h-11 items-center gap-2.5 px-2 ${reserveEnd ? "mr-11" : ""}`}>
        <Skeleton className="size-[26px] rounded-[7px]" />
        <Skeleton className="h-3.5 w-24" />
      </div>
    );
  }

  return (
    <div className={reserveEnd ? "mr-11" : ""}>
      <Menu
        label={`Organisation: ${org.name}`}
        triggerClassName="flex h-11 w-full cursor-pointer items-center gap-2.5 rounded-input bg-transparent px-2 text-left text-text-primary transition-colors hover:bg-surface-card"
        trigger={
          <>
            <OrgTile name={org.name} />
            <span className="min-w-0 grow truncate font-semibold">{org.name}</span>
            <IconChevronUpDown className="size-3.5 shrink-0 text-text-muted" />
          </>
        }
      >
        <MenuNote>Organisations</MenuNote>
        {orgs.map((row) => (
          <MenuRadio
            key={row.orgId}
            checked={row.orgId === org.orgId}
            onSelect={() => {
              setOrg(row.orgId);
              void navigate("/projects");
            }}
          >
            <OrgTile name={row.name} size="sm" />
            <span className="truncate">{row.name}</span>
          </MenuRadio>
        ))}
        <MenuDivider />
        <MenuLink to="/projects">All projects</MenuLink>
      </Menu>
    </div>
  );
}
