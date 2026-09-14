"use client";

import { Loader2, ShieldPlus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { SecurityClassBadge } from "@/components/security-class-badge";
import { Button } from "@/components/ui/button";
import type { AlgorithmMetadata } from "@/lib/crypto/types";
import { cn } from "@/lib/utils";

function signatureSize(metadata: AlgorithmMetadata) {
  return metadata.signature.fixedBytes === null ? `≤ ${metadata.signature.maxBytes} B` : `${metadata.signature.fixedBytes} B`;
}

export function IssueCertificateForm({ algorithms }: { algorithms: AlgorithmMetadata[] }) {
  const router = useRouter();
  const issuable = algorithms.filter((option) => option.capabilities.x509Subject);
  const [algorithm, setAlgorithm] = useState(issuable[0]?.id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const selected = issuable.find((option) => option.id === algorithm);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);

    const response = await fetch("/api/certificates", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ algorithm }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      setError(body.error ?? "Issuance failed");
      setPending(false);
      return;
    }

    setPending(false);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Algorithm</legend>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
          {issuable.map((option) => {
            const active = option.id === algorithm;
            return (
              <label
                key={option.id}
                className={cn(
                  "relative flex cursor-pointer flex-col gap-2 rounded-lg border bg-card p-3 shadow-card transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring",
                  active ? "border-primary/60 bg-accent/60" : "hover:border-foreground/20",
                )}
              >
                <input type="radio" name="algorithm" value={option.id} checked={active} onChange={() => setAlgorithm(option.id)} className="sr-only" />
                <span className="flex items-start justify-between gap-2">
                  <span className="text-sm font-medium leading-snug">{option.displayName}</span>
                  <span aria-hidden className={cn("mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border", active ? "border-primary" : "border-input")}>
                    {active && <span className="h-2 w-2 rounded-full bg-primary" />}
                  </span>
                </span>
                <SecurityClassBadge securityClass={option.securityClass} />
                <span className="grid grid-cols-2 gap-1 font-mono text-[11px] text-muted-foreground">
                  <span>key {option.keySizes.publicKeyBytes} B</span>
                  <span>sig {signatureSize(option)}</span>
                </span>
              </label>
            );
          })}
        </div>
        {selected && (
          <div className="max-w-3xl space-y-1 rounded-lg border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
            <p>{selected.description}</p>
            <p>
              {selected.family} &middot; {selected.parameters} &middot; implemented by {selected.implementation.version}
            </p>
          </div>
        )}
      </fieldset>

      {error && (
        <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" disabled={pending || !selected}>
        {pending ? <Loader2 aria-hidden className="animate-spin" /> : <ShieldPlus aria-hidden />}
        {pending ? "Generating key and signing certificate..." : "Issue certificate"}
      </Button>
    </form>
  );
}
