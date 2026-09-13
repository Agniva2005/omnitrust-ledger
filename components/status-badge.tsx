import { Badge } from "@/components/ui/badge";

type Variant = "default" | "secondary" | "destructive" | "success" | "warning" | "info" | "outline";

const VARIANTS: Record<string, Variant> = {
  HASHED: "secondary",
  UPLOADED: "secondary",
  SIGNED: "info",
  STORED: "info",
  VERIFIED: "success",
  VERSIONED: "secondary",
  ARCHIVED: "outline",
  REVOKED: "destructive",
  ACTIVE: "success",
  EXPIRED: "warning",
  ROTATED: "secondary",
  RETIRED: "outline",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <Badge variant={VARIANTS[status] ?? "secondary"}>
      <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />
      {status}
    </Badge>
  );
}
