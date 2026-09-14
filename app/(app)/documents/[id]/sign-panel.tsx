"use client";

import { FileSignature, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { SecurityClassBadge } from "@/components/security-class-badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type CertificateOption = {
  id: string;
  algorithm: string;
  displayName: string;
  serialNumber: string;
  expiresAt: string;
  securityClass?: string;
  signatureBytes?: string;
};

export function SignPanel({
  documentId,
  certificates,
}: {
  documentId: string;
  certificates: CertificateOption[];
}) {
  const router = useRouter();
  const [certificateId, setCertificateId] = useState(certificates[0]?.id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  if (certificates.length === 0) {
    return (
      <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
        You have no valid certificate to sign with. Issue one on the Certificates page first.
      </p>
    );
  }

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);

    const response = await fetch(`/api/documents/${documentId}/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ certificateId }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      setError(body.error ?? "Signing failed");
      setPending(false);
      return;
    }

    setPending(false);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Signing certificate</legend>
        <p className="text-xs text-muted-foreground">The certificate determines the algorithm and the key. Nothing here selects an algorithm directly.</p>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {certificates.map((certificate) => {
            const selected = certificate.id === certificateId;
            return (
              <label
                key={certificate.id}
                className={cn(
                  "relative flex cursor-pointer flex-col gap-2 rounded-lg border bg-card p-3 text-sm shadow-card transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring",
                  selected ? "border-primary/60 bg-accent/60" : "hover:border-foreground/20",
                )}
              >
                <input
                  type="radio"
                  name="certificate"
                  value={certificate.id}
                  checked={selected}
                  onChange={() => setCertificateId(certificate.id)}
                  className="sr-only"
                />
                <span className="flex items-start justify-between gap-2">
                  <span className="font-medium">{certificate.displayName}</span>
                  <span aria-hidden className={cn("mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border", selected ? "border-primary" : "border-input")}>
                    {selected && <span className="h-2 w-2 rounded-full bg-primary" />}
                  </span>
                </span>
                {certificate.securityClass && <SecurityClassBadge securityClass={certificate.securityClass} />}
                <span className="font-mono text-[11px] text-muted-foreground">
                  serial {certificate.serialNumber.slice(0, 12)}… · expires {certificate.expiresAt.slice(0, 10)}
                  {certificate.signatureBytes ? ` · ${certificate.signatureBytes} signature` : ""}
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>

      {error && (
        <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" disabled={pending}>
        {pending ? <Loader2 aria-hidden className="animate-spin" /> : <FileSignature aria-hidden />}
        {pending ? "Signing the document hash..." : "Sign document"}
      </Button>
    </form>
  );
}
