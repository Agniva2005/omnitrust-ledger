import { Check, ChevronRight, HelpCircle, Minus, X } from "lucide-react";
import { cn } from "@/lib/utils";

type StepStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "SKIPPED";

const LINKS: { id: string; label: string; detail: string }[] = [
  { id: "certificate-validity", label: "Certificate", detail: "chains to the CA, right profile, valid when signed" },
  { id: "revocation", label: "Revocation", detail: "CA-signed CRL, timestamp-aware policy" },
  { id: "timestamp", label: "Time-stamp", detail: "RFC 3161 proof of existence" },
  { id: "public-key", label: "Key", detail: "key material matches the records" },
  { id: "signature-verification", label: "Signature", detail: "verifies under the certificate key" },
  { id: "hash-comparison", label: "Content", detail: "bytes on disk are the bytes signed" },
];

const TONE: Record<StepStatus, { card: string; icon: string; symbol: typeof Check }> = {
  PASS: { card: "border-success/30 bg-success/[0.06]", icon: "bg-success text-success-foreground", symbol: Check },
  FAIL: { card: "border-destructive/35 bg-destructive/[0.07]", icon: "bg-destructive text-destructive-foreground", symbol: X },
  UNAVAILABLE: { card: "border-warning/35 bg-warning/[0.07]", icon: "bg-warning text-warning-foreground", symbol: HelpCircle },
  SKIPPED: { card: "border-border bg-muted/40", icon: "bg-muted-foreground/30 text-foreground", symbol: Minus },
};

/** The verification result as a chain of evidence, each link coloured by its real step status. */
export function EvidenceChain({ steps }: { steps: { id: string; status: StepStatus }[] }) {
  const statusOf = (id: string): StepStatus => steps.find((step) => step.id === id)?.status ?? "SKIPPED";
  return (
    <ol aria-label="Evidence chain" className="grid gap-2 sm:grid-cols-3 xl:grid-cols-6">
      {LINKS.map((link, index) => {
        const status = statusOf(link.id);
        const tone = TONE[status];
        const Symbol = tone.symbol;
        return (
          <li key={link.id} className={cn("relative rounded-lg border p-3", tone.card)}>
            <div className="flex items-center gap-2 text-sm font-medium">
              <span aria-hidden className={cn("grid h-5 w-5 place-items-center rounded-full", tone.icon)}>
                <Symbol className="h-3 w-3" strokeWidth={3} />
              </span>
              {link.label}
              <span className="sr-only">{status}</span>
            </div>
            <div className="mt-1.5 text-[11px] leading-snug text-muted-foreground">{link.detail}</div>
            {index < LINKS.length - 1 && (
              <ChevronRight aria-hidden className="absolute -right-2 top-1/2 hidden h-4 w-4 -translate-y-1/2 text-muted-foreground/50 xl:block" />
            )}
          </li>
        );
      })}
    </ol>
  );
}
