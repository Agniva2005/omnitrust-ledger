import { Atom, Layers, Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";

const DISPLAY = {
  classical: { variant: "classical", label: "classical", icon: Lock },
  "post-quantum": { variant: "pq", label: "post-quantum", icon: Atom },
  hybrid: { variant: "hybrid", label: "hybrid PQ/T", icon: Layers },
} as const;

/** Classical, post-quantum or hybrid (PQ/T composite), in one colour language across the interface. */
export function SecurityClassBadge({ securityClass }: { securityClass: string }) {
  const display = DISPLAY[securityClass as keyof typeof DISPLAY];
  if (!display) return <Badge variant="secondary">{securityClass}</Badge>;
  const Icon = display.icon;
  return (
    <Badge variant={display.variant}>
      <Icon aria-hidden className="h-3 w-3" />
      {display.label}
    </Badge>
  );
}
