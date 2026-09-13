import { Badge } from "@/components/ui/badge";

const VARIANT: Record<string, "success" | "destructive" | "outline" | "secondary"> = {
  VALID: "success",
  INVALID: "destructive",
  ERROR: "destructive",
  UNVERIFIABLE: "outline",
};

/** The four verification verdicts, never collapsed into two. */
export function VerdictBadge({ outcome }: { outcome: string }) {
  return <Badge variant={VARIANT[outcome] ?? "secondary"}>{outcome}</Badge>;
}
