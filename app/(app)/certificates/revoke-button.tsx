"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  COMPROMISE_REASONS,
  REVOCATION_REASONS,
  REVOCATION_REASON_DESCRIPTIONS,
  type RevocationReason,
} from "@/lib/pki/revocation";

export function RevokeButton({ certificateId }: { certificateId: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [reason, setReason] = useState<RevocationReason>("superseded");
  const [invalidityDate, setInvalidityDate] = useState("");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const compromise = COMPROMISE_REASONS.includes(reason);

  async function revoke() {
    setPending(true);
    setError(null);
    const response = await fetch(`/api/certificates/${certificateId}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        reason,
        invalidityDate: invalidityDate ? new Date(invalidityDate).toISOString() : undefined,
        comment: comment || undefined,
      }),
    });
    setPending(false);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      setError(body.error ?? "Revocation failed");
      return;
    }
    setOpen(false);
    router.refresh();
  }

  if (!open) {
    return (
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        Revoke
      </Button>
    );
  }

  return (
    <div className="w-72 space-y-2 rounded-md border p-3 text-xs">
      <label className="block space-y-1">
        <span className="font-medium">Reason (RFC 5280)</span>
        <select
          className="h-8 w-full rounded-md border border-input bg-transparent px-2"
          value={reason}
          onChange={(event) => setReason(event.target.value as RevocationReason)}
        >
          {REVOCATION_REASONS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
        <span className="block text-muted-foreground">{REVOCATION_REASON_DESCRIPTIONS[reason]}</span>
      </label>

      <label className="block space-y-1">
        <span className="font-medium">
          Invalidity date {compromise ? "(when the key was compromised)" : "(optional)"}
        </span>
        <input
          type="datetime-local"
          className="h-8 w-full rounded-md border border-input bg-transparent px-2"
          value={invalidityDate}
          onChange={(event) => setInvalidityDate(event.target.value)}
        />
        {compromise && !invalidityDate && (
          <span className="block text-amber-700">
            Without it, no signature made with this key can be shown to predate the compromise.
          </span>
        )}
      </label>

      <label className="block space-y-1">
        <span className="font-medium">Comment (optional)</span>
        <input
          className="h-8 w-full rounded-md border border-input bg-transparent px-2"
          maxLength={200}
          value={comment}
          onChange={(event) => setComment(event.target.value)}
        />
      </label>

      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}

      <div className="flex gap-2">
        <Button variant="destructive" size="sm" onClick={revoke} disabled={pending}>
          {pending ? "Revoking..." : "Confirm revocation"}
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setOpen(false)} disabled={pending}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
