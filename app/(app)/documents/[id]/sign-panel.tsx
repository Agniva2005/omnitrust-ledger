"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

export type CertificateOption = {
  id: string;
  algorithm: string;
  displayName: string;
  serialNumber: string;
  expiresAt: string;
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
      <p className="text-sm text-muted-foreground">
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
      <div className="space-y-1.5">
        <Label htmlFor="certificate">Signing certificate</Label>
        <select
          id="certificate"
          className="flex h-9 w-full max-w-lg rounded-md border border-input bg-transparent px-3 text-sm"
          value={certificateId}
          onChange={(event) => setCertificateId(event.target.value)}
        >
          {certificates.map((certificate) => (
            <option key={certificate.id} value={certificate.id}>
              {certificate.displayName} &middot; serial {certificate.serialNumber.slice(0, 12)}...
              &middot; expires {certificate.expiresAt.slice(0, 10)}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          The certificate determines the algorithm and the key. Nothing here selects an algorithm
          directly.
        </p>
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" disabled={pending}>
        {pending ? "Signing the document hash..." : "Sign document"}
      </Button>
    </form>
  );
}
