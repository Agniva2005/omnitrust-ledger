import Link from "next/link";
import { LogoutButton } from "@/components/logout-button";
import { NavLinks, type NavGroup } from "@/components/nav-links";
import { Badge } from "@/components/ui/badge";
import type { Actor } from "@/lib/auth/rbac";

const GROUPS: NavGroup[] = [
  { label: "Overview", links: [{ href: "/dashboard", label: "Dashboard" }] },
  { label: "Records", links: [{ href: "/documents", label: "Documents" }] },
  {
    label: "Trust",
    links: [
      { href: "/certificates", label: "Certificates" },
      { href: "/algorithms", label: "Algorithms" },
    ],
  },
  {
    label: "Integrity",
    links: [
      { href: "/audit", label: "Audit log" },
      { href: "/anchoring", label: "Anchoring" },
    ],
  },
  {
    label: "Evaluation",
    links: [
      { href: "/security-lab", label: "Security Lab" },
      { href: "/benchmarks", label: "Benchmarks" },
    ],
  },
];

export function AppNav({ actor }: { actor: Actor }) {
  return (
    <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-8 gap-y-3 px-6 py-3">
        <Link href="/dashboard" className="flex items-center gap-2 font-semibold tracking-tight">
          <span aria-hidden className="grid h-7 w-7 place-items-center rounded-md bg-primary text-xs text-primary-foreground">
            OT
          </span>
          OmniTrust Ledger
        </Link>
        <NavLinks groups={GROUPS} />
        <div className="ml-auto flex items-center gap-3 text-sm">
          <span className="text-muted-foreground">{actor.email}</span>
          <Badge variant="secondary">{actor.role}</Badge>
          <LogoutButton />
        </div>
      </div>
    </header>
  );
}
