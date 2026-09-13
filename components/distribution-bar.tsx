/** A labelled horizontal bar per category, widths proportional to the largest count. */
export function DistributionBars({ rows, empty }: { rows: { key: string; count: number }[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const max = Math.max(...rows.map((row) => row.count));
  return (
    <ul className="space-y-2">
      {rows.map((row) => (
        <li key={row.key} className="grid grid-cols-[9rem_1fr_2.5rem] items-center gap-3 text-sm">
          <span className="truncate text-muted-foreground" title={row.key}>
            {row.key}
          </span>
          <span className="h-2 rounded bg-muted">
            <span className="block h-2 rounded bg-primary" style={{ width: `${Math.max(4, Math.round((row.count / max) * 100))}%` }} />
          </span>
          <span className="text-right font-mono text-xs">{row.count}</span>
        </li>
      ))}
    </ul>
  );
}
