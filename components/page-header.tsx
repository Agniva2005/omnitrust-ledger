import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * The standard page header: an optional icon tile and eyebrow, the page title as the only h1, a
 * description, and an actions slot. The title stays plain text so the end-to-end regression's
 * heading checks keep matching.
 */
export function PageHeader({
  title,
  description,
  icon: Icon,
  eyebrow,
  actions,
  className,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: LucideIcon;
  eyebrow?: string;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-4", className)}>
      <div className="flex min-w-0 items-start gap-3.5">
        {Icon && (
          <span aria-hidden className="mt-0.5 grid h-10 w-10 shrink-0 place-items-center rounded-xl border bg-card text-primary shadow-card">
            <Icon className="h-5 w-5" />
          </span>
        )}
        <div className="min-w-0 space-y-1">
          {eyebrow && <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-primary">{eyebrow}</p>}
          <h1 className="text-balance text-2xl font-semibold tracking-tight">{title}</h1>
          {description && <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
