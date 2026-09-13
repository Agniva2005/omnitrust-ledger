import { TriangleAlert } from "lucide-react";
import { cn } from "@/lib/utils";

/** The standing disclosure required by CLAUDE.md: this is a demonstrator, not a production PKI. */
export function DemoNotice({ className }: { className?: string }) {
  return (
    <p className={cn("flex items-start gap-2 text-xs leading-relaxed text-muted-foreground", className)}>
      <TriangleAlert aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" />
      <span>
        <span className="font-medium text-foreground">Demo / Not for Production Use.</span> The Certificate Authority here is
        self-signed and trusted by nothing outside this app; private keys are encrypted with a key stored in a local file
        rather than an HSM or KMS.
      </span>
    </p>
  );
}
