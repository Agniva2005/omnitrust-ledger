import { Badge } from "@/components/ui/badge";

type Entry = {
  id: string;
  seq: number;
  action: string;
  targetType: string;
  metadataJson: string;
  entryHash: string;
  createdAt: Date;
  actor: { email: string } | null;
};

const CATEGORIES: { match: RegExp; label: string; dot: string }[] = [
  { match: /FAILED|THROTTLED|REVOKED/, label: "security", dot: "bg-destructive" },
  { match: /^USER_/, label: "access", dot: "bg-sky-500" },
  { match: /^DOCUMENT_/, label: "documents", dot: "bg-primary" },
  { match: /^(CERTIFICATE|KEY|CRL|CA|TSA|TIMESTAMP)_/, label: "PKI", dot: "bg-violet-500" },
  { match: /^(AUDIT|ANCHOR)_/, label: "integrity", dot: "bg-success" },
  { match: /^SECURITY_LAB/, label: "lab", dot: "bg-amber-500" },
];

function categoryOf(action: string) {
  return CATEGORIES.find((category) => category.match.test(action)) ?? { label: "other", dot: "bg-muted-foreground" };
}

/** The audit log as a timeline grouped by day, newest first. */
export function AuditTimeline({ entries }: { entries: Entry[] }) {
  if (entries.length === 0) {
    return <p className="rounded-lg border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">No audit entries yet.</p>;
  }

  const days = new Map<string, Entry[]>();
  for (const entry of entries) {
    const day = entry.createdAt.toISOString().slice(0, 10);
    days.set(day, [...(days.get(day) ?? []), entry]);
  }

  return (
    <div className="space-y-6">
      {[...days.entries()].map(([day, dayEntries]) => (
        <section key={day}>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">{day}</h3>
          <ol className="relative space-y-3 border-l pl-6">
            {dayEntries.map((entry) => {
              const category = categoryOf(entry.action);
              return (
                <li key={entry.id} className="relative">
                  <span aria-hidden className={`absolute -left-[1.83rem] top-1.5 h-3 w-3 rounded-full ring-4 ring-background ${category.dot}`} />
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="font-mono text-xs text-muted-foreground">#{entry.seq}</span>
                    <Badge variant={category.label === "security" ? "destructive" : "secondary"}>{entry.action}</Badge>
                    <span className="text-xs text-muted-foreground">{category.label}</span>
                    <span className="text-xs text-muted-foreground">by {entry.actor?.email ?? "system"}</span>
                    <span className="ml-auto font-mono text-xs text-muted-foreground">
                      {entry.createdAt.toISOString().slice(11, 19)} · {entry.entryHash.slice(0, 12)}…
                    </span>
                  </div>
                  <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
                    {entry.targetType} {entry.metadataJson}
                  </div>
                </li>
              );
            })}
          </ol>
        </section>
      ))}
    </div>
  );
}
