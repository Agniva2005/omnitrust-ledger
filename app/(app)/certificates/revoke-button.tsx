"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { Loader2, ShieldX, TriangleAlert, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  COMPROMISE_REASONS,
  REVOCATION_REASONS,
  REVOCATION_REASON_DESCRIPTIONS,
  type RevocationReason,
} from "@/lib/pki/revocation";

const fieldClass =
  "flex h-9 w-full rounded-lg border border-input bg-card px-3 text-sm shadow-card transition-[border-color,box-shadow] focus-visible:border-primary/60 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-ring/15";

/**
 * Revocation opens in a dialog: the form used to expand inside the table cell, which clipped its labels
 * and pushed the table into horizontal scrolling. Labels are unchanged because DEMO_SCRIPT.md names them.
 */
export function RevokeButton({ certificateId, subject, algorithm, serialNumber }: { certificateId: string; subject?: string; algorithm?: string; serialNumber?: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [reason, setReason] = useState<RevocationReason>("superseded");
  const [invalidityDate, setInvalidityDate] = useState("");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const compromise = COMPROMISE_REASONS.includes(reason);

  function reset(nextOpen: boolean) {
    setOpen(nextOpen);
    if (nextOpen) {
      setReason("superseded");
      setInvalidityDate("");
      setComment("");
      setError(null);
    }
  }

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

  return (
    <Dialog.Root open={open} onOpenChange={reset}>
      <Dialog.Trigger asChild>
        <Button variant="outline" size="sm">
          Revoke
        </Button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-background/70 backdrop-blur-sm data-[state=open]:animate-fade-in" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(30rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-xl border bg-popover p-6 text-popover-foreground shadow-elevated data-[state=open]:animate-scale-in">
          <div className="flex items-start gap-3">
            <span aria-hidden className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-destructive/10 text-destructive">
              <ShieldX className="h-5 w-5" />
            </span>
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-base font-semibold tracking-tight">Revoke certificate</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-muted-foreground">
                {subject ? `${subject}${algorithm ? ` · ${algorithm}` : ""}. ` : ""}The CA publishes the revocation in a new signed CRL. This cannot be undone.
              </Dialog.Description>
              {serialNumber && <p className="mt-1 break-all font-mono text-[11px] text-muted-foreground">serial {serialNumber}</p>}
            </div>
            <Dialog.Close aria-label="Close" className="grid h-8 w-8 place-items-center rounded-md text-muted-foreground hover:bg-secondary hover:text-foreground">
              <X aria-hidden className="h-4 w-4" />
            </Dialog.Close>
          </div>

          <div className="mt-5 space-y-4 text-sm">
            <label className="block space-y-1.5">
              <span className="font-medium">Reason (RFC 5280)</span>
              <select className={fieldClass} value={reason} onChange={(event) => setReason(event.target.value as RevocationReason)}>
                {REVOCATION_REASONS.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
              <span className="block text-xs text-muted-foreground">{REVOCATION_REASON_DESCRIPTIONS[reason]}</span>
            </label>

            <label className="block space-y-1.5">
              <span className="font-medium">Invalidity date {compromise ? "(when the key was compromised)" : "(optional)"}</span>
              <input type="datetime-local" className={fieldClass} value={invalidityDate} onChange={(event) => setInvalidityDate(event.target.value)} />
              {compromise && !invalidityDate && (
                <span className="flex items-start gap-1.5 rounded-lg border border-warning/35 bg-warning/10 px-2.5 py-2 text-xs text-warning">
                  <TriangleAlert aria-hidden className="mt-px h-3.5 w-3.5 shrink-0" />
                  Without it, no signature made with this key can be shown to predate the compromise.
                </span>
              )}
            </label>

            <label className="block space-y-1.5">
              <span className="font-medium">Comment (optional)</span>
              <input className={fieldClass} maxLength={200} value={comment} onChange={(event) => setComment(event.target.value)} />
            </label>

            {error && (
              <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-destructive">
                {error}
              </p>
            )}
          </div>

          <div className="mt-6 flex justify-end gap-2">
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" disabled={pending}>
                Cancel
              </Button>
            </Dialog.Close>
            <Button variant="destructive" size="sm" onClick={revoke} disabled={pending}>
              {pending && <Loader2 aria-hidden className="animate-spin" />}
              {pending ? "Revoking..." : "Confirm revocation"}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
