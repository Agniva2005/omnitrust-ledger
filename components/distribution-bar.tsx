/**
 * A labelled bar per category, widths proportional to the largest count. The label sits above its bar so long
 * names (such as a composite algorithm) are never truncated in narrow cards.
 */
export function DistributionBars({ rows, empty }: { rows: { key: string; count: number }[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const max = Math.max(...rows.map((row) => row.count));
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  return (
    <ul className="space-y-3">
      {rows.map((row) => (
        <li key={row.key} className="text-sm">
          <div className="flex items-baseline justify-between gap-3">
            <span className="min-w-0 text-muted-foreground [overflow-wrap:anywhere]">{row.key}</span>
            <span className="shrink-0 font-mono text-xs tabular-nums">
              {row.count}
              <span className="ml-1.5 text-muted-foreground">{Math.round((row.count / total) * 100)}%</span>
            </span>
          </div>
          <span className="mt-1.5 block h-1.5 overflow-hidden rounded-full bg-muted">
            <span
              className="block h-1.5 rounded-full bg-gradient-to-r from-primary/70 to-primary"
              style={{ width: `${Math.max(3, Math.round((row.count / max) * 100))}%` }}
            />
          </span>
        </li>
      ))}
    </ul>
  );
}
