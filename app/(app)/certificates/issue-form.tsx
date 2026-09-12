"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

type AlgorithmOption = {
  algorithm: string;
  displayName: string;
  description: string;
  signatureByteLength: number | null;
};

export function IssueCertificateForm({ algorithms }: { algorithms: AlgorithmOption[] }) {
  const router = useRouter();
  const [algorithm, setAlgorithm] = useState(algorithms[0]?.algorithm ?? "");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const selected = algorithms.find((option) => option.algorithm === algorithm);

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
          {algorithms.map((option) => (
            <option key={option.algorithm} value={option.algorithm}>
              {option.displayName}
            </option>
          ))}
        </select>
        {selected && <p className="max-w-prose text-xs text-muted-foreground">{selected.description}</p>}
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" disabled={pending}>
        {pending ? "Generating key and signing certificate..." : "Issue certificate"}
      </Button>
    </form>
  );
}
