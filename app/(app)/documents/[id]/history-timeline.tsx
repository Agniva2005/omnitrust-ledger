import { CircleCheck, CircleX, Dot } from "lucide-react";
import type { DocumentEvent } from "@/lib/documents/history";
import { cn } from "@/lib/utils";

const TONE = {
  good: { ring: "border-success/40 bg-success/10 text-success", icon: CircleCheck },
  bad: { ring: "border-destructive/40 bg-destructive/10 text-destructive", icon: CircleX },
  neutral: { ring: "border-border bg-muted text-muted-foreground", icon: Dot },
} as const;

export function HistoryTimeline({ events }: { events: DocumentEvent[] }) {
  if (events.length === 0) {
    return <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">Nothing has happened to this document yet.</p>;
  }

  return (
    <ol className="relative space-y-4 pl-7">
      <span aria-hidden className="absolute bottom-3 left-[11px] top-3 w-px bg-border" />
      {events.map((event) => {
        const tone = TONE[event.tone];
        const Icon = tone.icon;
        return (
          <li key={event.seq} className="relative">
            <span aria-hidden className={cn("absolute -left-7 grid h-6 w-6 place-items-center rounded-full border", tone.ring)}>
              <Icon className="h-3.5 w-3.5" />
            </span>
            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
              <span className="text-sm font-medium">{event.headline}</span>
              {event.outcome && (
                <span
                  className={cn(
                    "rounded px-1.5 py-px font-mono text-[10px]",
                    event.outcome === "VALID" ? "bg-success/15 text-success" : event.outcome === "INVALID" ? "bg-destructive/15 text-destructive" : "bg-muted text-muted-foreground",
                  )}
                >
                  {event.outcome}
                  {event.reason ? ` / ${event.reason}` : ""}
                </span>
              )}
              <span className="font-mono text-[11px] text-muted-foreground">
                {event.at.replace("T", " ").slice(0, 19)}
                {event.actor ? ` · ${event.actor}` : ""}
              </span>
            </div>
            {event.summary && <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{event.summary}</p>}
            <p className="mt-1 font-mono text-[10px] text-muted-foreground/80 [overflow-wrap:anywhere]">
              audit #{event.seq} · {event.entryHash.slice(0, 24)}…
            </p>
          </li>
        );
      })}
    </ol>
  );
}
