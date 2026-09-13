"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

export type NavGroup = { label: string; links: { href: string; label: string }[] };

export function NavLinks({ groups }: { groups: NavGroup[] }) {
  const pathname = usePathname();
  const active = (href: string) => pathname === href || pathname.startsWith(`${href}/`);

  return (
    <nav aria-label="Main" className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
      {groups.map((group) => (
        <div key={group.label} className="flex items-center gap-3">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">{group.label}</span>
          {group.links.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              aria-current={active(link.href) ? "page" : undefined}
              className={cn(
                "rounded-md px-2 py-1 transition-colors hover:bg-muted hover:text-foreground",
                active(link.href) ? "bg-muted font-medium text-foreground" : "text-muted-foreground",
              )}
            >
              {link.label}
            </Link>
          ))}
        </div>
      ))}
    </nav>
  );
}
