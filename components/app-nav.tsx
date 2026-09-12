import Link from "next/link";
import { LogoutButton } from "@/components/logout-button";
import { Badge } from "@/components/ui/badge";
import type { Actor } from "@/lib/auth/rbac";

const LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/documents", label: "Documents" },
  { href: "/certificates", label: "Certificates" },
  { href: "/audit", label: "Audit log" },
  { href: "/benchmarks", label: "Benchmarks" },
];

export function AppNav({ actor }: { actor: Actor }) {
  return (
    <header className="border-b">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-6 py-3">
        <Link href="/dashboard" className="font-semibold tracking-tight">
          OmniTrust Ledger
        </Link>
        <nav className="flex flex-wrap gap-4 text-sm text-muted-foreground">
          {LINKS.map((link) => (
            <Link key={link.href} href={link.href} className="hover:text-foreground">
              {link.label}
            </Link>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-sm">
          <span className="text-muted-foreground">{actor.email}</span>
          <Badge variant="secondary">{actor.role}</Badge>
          <LogoutButton />
        </div>
      </div>
    </header>
  );
}
