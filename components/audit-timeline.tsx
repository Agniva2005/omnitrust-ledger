import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type Entry = {
  id: string;
  seq: number;
  action: string;
  targetType: string;
  metadataJson: string;
  prevHash: string;
  entryHash: string;
  /** This row's own fields hashed against its stored prevHash: what the integrity walk checks. */
  recomputedHash: string;
  createdAt: Date;
  actor: { email: string } | null;
};

const CATEGORIES: { match: RegExp; label: string; dot: string }[] = [
  { match: /FAILED|THROTTLED|REVOKED/, label: "security", dot: "bg-destructive" },
  { match: /^USER_/, label: "access", dot: "bg-info" },
  { match: /^DOCUMENT_/, label: "documents", dot: "bg-primary" },
  { match: /^(CERTIFICATE|KEY|CRL|CA|TSA|TIMESTAMP)_/, label: "PKI", dot: "bg-hybrid" },
  { match: /^(AUDIT|ANCHOR)_/, label: "integrity", dot: "bg-success" },
  { match: /^SECURITY_LAB/, label: "lab", dot: "bg-warning" },
];

function categoryOf(action: string) {
  return CATEGORIES.find((category) => category.match.test(action)) ?? { label: "other", dot: "bg-muted-foreground" };
}

function summarise(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value.length > 28 ? `${value.slice(0, 26)}…` : value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.length === 0 ? "none" : `${value.length} item${value.length === 1 ? "" : "s"}`;
  return "{…}";
}

function parseMetadata(json: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** The audit log as a timeline grouped by day, newest first. Metadata is summarised; the full JSON is one click away. */
export function AuditTimeline({ entries }: { entries: Entry[] }) {
  if (entries.length === 0) {
    return <p className="rounded-lg border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">No audit entries yet.</p>;
  }

  // Each entry stores the hash of the one before it. Where both are on screen the two can be
  // compared directly, which is the chain itself rather than a claim about it.
  const bySeq = new Map(entries.map((entry) => [entry.seq, entry]));
  const linkOf = (entry: Entry) => {
    const previous = bySeq.get(entry.seq - 1);
    if (!previous) return null;
    return { previous, matches: previous.entryHash === entry.prevHash };
  };

  const days = new Map<string, Entry[]>();
  for (const entry of entries) {
    const day = entry.createdAt.toISOString().slice(0, 10);
    days.set(day, [...(days.get(day) ?? []), entry]);
  }

  return (
    <div className="space-y-6">
      {[...days.entries()].map(([day, dayEntries]) => (
        <section key={day}>
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">{day} (UTC)</h3>
          <ol className="relative space-y-3 border-l pl-6">
            {dayEntries.map((entry) => {
              const category = categoryOf(entry.action);
              const metadata = parseMetadata(entry.metadataJson);
              const fields = metadata ? Object.entries(metadata).slice(0, 5) : [];
              return (
                <li key={entry.id} className="relative">
                  <span aria-hidden className={cn("absolute -left-[1.83rem] top-1.5 h-3 w-3 rounded-full ring-4 ring-card", category.dot)} />
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="font-mono text-xs text-muted-foreground">#{entry.seq}</span>
                    <Badge variant={category.label === "security" ? "destructive" : "secondary"}>{entry.action}</Badge>
                    <span className="text-xs text-muted-foreground">{category.label}</span>
                    <span className="text-xs text-muted-foreground">by {entry.actor?.email ?? "system"}</span>
                    <span className="ml-auto font-mono text-xs text-muted-foreground" title={entry.entryHash}>
                      {entry.createdAt.toISOString().slice(11, 19)} · {entry.entryHash.slice(0, 12)}…
                    </span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                    <span className="text-muted-foreground">{entry.targetType}</span>
                    {fields.map(([key, value]) => (
                      <span key={key} className="rounded-md border bg-muted/40 px-1.5 py-0.5 font-mono" title={typeof value === "string" ? value : JSON.stringify(value)}>
                        <span className="text-muted-foreground">{key}</span> {summarise(value)}
                      </span>
                    ))}
                  </div>
                  {(() => {
                    const link = linkOf(entry);
                    if (!link) return null;
                    return (
                      <p className={cn("mt-1 font-mono text-[10px]", link.matches ? "text-muted-foreground" : "font-semibold text-destructive")}>
                        prev {link.matches ? "=" : "≠"} #{link.previous.seq} {entry.prevHash.slice(0, 16)}…
                        {!link.matches && <span> — this entry does not follow #{link.previous.seq}</span>}
                      </p>
                    );
                  })()}
                  {entry.recomputedHash !== entry.entryHash && (
                    <p className="mt-1 font-mono text-[10px] font-semibold text-destructive">
                      contents hash to {entry.recomputedHash.slice(0, 16)}… but the row stores {entry.entryHash.slice(0, 16)}… — this entry was altered
                    </p>
                  )}
                  <details className="mt-1 text-[11px] text-muted-foreground">
                    <summary className="w-fit cursor-pointer select-none hover:text-foreground">Full metadata</summary>
                    <pre className="mt-1 overflow-x-auto rounded-md border bg-muted/40 p-2 font-mono [overflow-wrap:anywhere] whitespace-pre-wrap">
                      {metadata ? JSON.stringify(metadata, null, 2) : entry.metadataJson}
                    </pre>
                  </details>
                </li>
              );
            })}
          </ol>
        </section>
      ))}
    </div>
  );
}
