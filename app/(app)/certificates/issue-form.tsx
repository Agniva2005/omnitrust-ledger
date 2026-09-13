"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import type { AlgorithmMetadata } from "@/lib/crypto/types";

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
      <div className="space-y-1.5">
        <Label htmlFor="algorithm">Algorithm</Label>
        <select
          id="algorithm"
          className="flex h-9 w-full max-w-sm rounded-md border border-input bg-transparent px-3 text-sm"
          value={algorithm}
          onChange={(event) => setAlgorithm(event.target.value)}
        >
          {issuable.map((option) => (
            <option key={option.id} value={option.id}>
              {option.displayName} ({option.securityClass})
            </option>
          ))}
        </select>
        {selected && (
          <div className="max-w-prose space-y-1 text-xs text-muted-foreground">
            <p>{selected.description}</p>
            <p>
              {selected.family} &middot; {selected.parameters} &middot; implemented by{" "}
              {selected.implementation.version}
            </p>
          </div>
        )}
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" disabled={pending || !selected}>
        {pending ? "Generating key and signing certificate..." : "Issue certificate"}
      </Button>
    </form>
  );
}
