/** A labelled horizontal bar per category, widths proportional to the largest count. */
export function DistributionBars({ rows, empty }: { rows: { key: string; count: number }[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const max = Math.max(...rows.map((row) => row.count));
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  return (
    <ul className="space-y-2.5">
      {rows.map((row) => (
        <li key={row.key} className="grid grid-cols-[minmax(0,9rem)_1fr_3.5rem] items-center gap-3 text-sm">
          <span className="truncate text-muted-foreground" title={row.key}>
            {row.key}
          </span>
          <span className="h-2 overflow-hidden rounded-full bg-muted">
            <span
              className="block h-2 rounded-full bg-gradient-to-r from-primary/70 to-primary"
              style={{ width: `${Math.max(4, Math.round((row.count / max) * 100))}%` }}
            />
          </span>
          <span className="text-right font-mono text-xs tabular-nums">
            {row.count}
            <span className="ml-1 text-muted-foreground">{Math.round((row.count / total) * 100)}%</span>
          </span>
        </li>
      ))}
    </ul>
  );
}
