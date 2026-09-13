import { ArrowUpRight, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";

/** A KPI tile: label, a tabular value, an optional detail line, and an optional link to the page it summarises. */
export function StatCard({
  label,
  value,
  detail,
  href,
  icon: Icon,
  tone = "primary",
}: {
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
  href?: string;
  icon?: LucideIcon;
  tone?: "primary" | "success" | "warning" | "hybrid" | "pq";
}) {
  const toneClass = {
    primary: "bg-primary/10 text-primary",
    success: "bg-success/10 text-success",
    warning: "bg-warning/10 text-warning",
    hybrid: "bg-hybrid/10 text-hybrid",
    pq: "bg-pq/10 text-pq",
  }[tone];

  const body = (
    <div className="group relative h-full rounded-xl border bg-card p-5 shadow-card transition-[box-shadow,border-color] hover:border-foreground/15 hover:shadow-elevated">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm text-muted-foreground">{label}</span>
        {Icon && (
          <span aria-hidden className={cn("grid h-8 w-8 place-items-center rounded-lg", toneClass)}>
            <Icon className="h-4 w-4" />
          </span>
        )}
      </div>
      <div className="mt-3 text-3xl font-semibold tracking-tight tabular-nums">{value}</div>
      {detail && <div className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{detail}</div>}
      {href && <ArrowUpRight aria-hidden className="absolute bottom-4 right-4 h-4 w-4 text-muted-foreground/0 transition-colors group-hover:text-muted-foreground" />}
    </div>
  );

  return href ? (
    <Link href={href} className="block h-full rounded-xl focus-visible:ring-2 focus-visible:ring-ring">
      {body}
    </Link>
  ) : (
    body
  );
}
