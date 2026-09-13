import { CircleAlert, CircleCheck, CircleHelp, CircleX } from "lucide-react";
import { Badge } from "@/components/ui/badge";

const DISPLAY: Record<string, { variant: "success" | "destructive" | "warning" | "secondary"; icon: typeof CircleCheck }> = {
  VALID: { variant: "success", icon: CircleCheck },
  INVALID: { variant: "destructive", icon: CircleX },
  ERROR: { variant: "destructive", icon: CircleAlert },
  // Evidence could not be obtained: a warning, never a pass and never a finding of tampering.
  UNVERIFIABLE: { variant: "warning", icon: CircleHelp },
};

/** The four verification verdicts, never collapsed into two. */
export function VerdictBadge({ outcome }: { outcome: string }) {
  const display = DISPLAY[outcome] ?? { variant: "secondary" as const, icon: CircleHelp };
  const Icon = display.icon;
  return (
    <Badge variant={display.variant}>
      <Icon aria-hidden className="h-3 w-3" />
      {outcome}
    </Badge>
  );
}
