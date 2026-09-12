import { Badge } from "@/components/ui/badge";

const VARIANTS: Record<string, "default" | "secondary" | "destructive" | "success" | "outline"> = {
  HASHED: "secondary",
  UPLOADED: "secondary",
  SIGNED: "default",
  STORED: "default",
  VERIFIED: "success",
  VERSIONED: "secondary",
  ARCHIVED: "outline",
  REVOKED: "destructive",
  ACTIVE: "success",
  EXPIRED: "outline",
  ROTATED: "secondary",
  RETIRED: "outline",
};

export function StatusBadge({ status }: { status: string }) {
  return <Badge variant={VARIANTS[status] ?? "secondary"}>{status}</Badge>;
}
