type StepStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "SKIPPED";

const LINKS: { id: string; label: string; detail: string }[] = [
  { id: "certificate-validity", label: "Certificate", detail: "chains to the CA, right profile, valid when signed" },
  { id: "revocation", label: "Revocation", detail: "CA-signed CRL, timestamp-aware policy" },
  { id: "timestamp", label: "Time-stamp", detail: "RFC 3161 proof of existence" },
  { id: "public-key", label: "Key", detail: "key material matches the records" },
  { id: "signature-verification", label: "Signature", detail: "verifies under the certificate key" },
  { id: "hash-comparison", label: "Content", detail: "bytes on disk are the bytes signed" },
];

const TONE: Record<StepStatus, string> = {
  PASS: "border-success/50 bg-success/10 text-success",
  FAIL: "border-destructive/50 bg-destructive/10 text-destructive",
  UNAVAILABLE: "border-amber-500/50 bg-amber-500/10 text-amber-700",
  SKIPPED: "border-border bg-muted text-muted-foreground",
};

const SYMBOL: Record<StepStatus, string> = { PASS: "✓", FAIL: "✕", UNAVAILABLE: "?", SKIPPED: "–" };

/** The verification result as a chain of evidence, each link coloured by its real step status. */
export function EvidenceChain({ steps }: { steps: { id: string; status: StepStatus }[] }) {
  const statusOf = (id: string): StepStatus => steps.find((step) => step.id === id)?.status ?? "SKIPPED";
  return (
    <ol aria-label="Evidence chain" className="grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
      {LINKS.map((link) => {
        const status = statusOf(link.id);
        return (
          <li key={link.id} className={`rounded-md border p-2 ${TONE[status]}`}>
            <div className="flex items-center gap-2 text-sm font-medium">
              <span aria-hidden className="font-mono">
                {SYMBOL[status]}
              </span>
              {link.label}
              <span className="sr-only">{status}</span>
            </div>
            <div className="mt-1 text-[11px] leading-snug opacity-80">{link.detail}</div>
          </li>
        );
      })}
    </ol>
  );
}
