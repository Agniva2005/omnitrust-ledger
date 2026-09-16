"use client";

import { FlaskConical, Loader2, RotateCcw, ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type TamperState = {
  contentAltered: boolean;
  signatureAltered: boolean;
  canRestoreContent: boolean;
  canRestoreSignature: boolean;
  signedHash: string;
  storedHash: string | null;
  storedHashError: string | null;
};

type Action = "content" | "ciphertext" | "signature" | "restore";

export function TamperPanel({
  documentId,
  hasSignature,
  initialState,
}: {
  documentId: string;
  hasSignature: boolean;
  initialState: TamperState;
}) {
  const router = useRouter();
  const [state, setState] = useState(initialState);
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<Action | null>(null);

  const altered = state.contentAltered || state.signatureAltered;

  async function run(action: Action) {
    setPending(action);
    setError(null);

    const response =
      action === "content"
        ? await (async () => {
            const body = new FormData();
            body.append("file", file!);
            return fetch(`/api/documents/${documentId}/demo-tamper`, { method: "POST", body });
          })()
        : await fetch(`/api/documents/${documentId}/demo-tamper`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action }),
          });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.error ?? "That could not be done");
      setPending(null);
      return;
    }

    setState(payload.state);
    if (action === "content") setFile(null);
    setPending(null);
    router.refresh();
  }

  return (
    <div className="space-y-4">
      <div
        className={cn(
          "rounded-lg border p-3 text-sm",
          altered ? "border-destructive/35 bg-destructive/[0.07]" : "border-success/35 bg-success/[0.07]",
        )}
      >
        <p className={cn("font-medium", altered ? "text-destructive" : "text-success")}>
          {altered ? "This document is currently altered." : "Stored bytes and signature match the records."}
        </p>
        <dl className="mt-2 grid gap-1.5 text-xs">
          <div>
            <dt className="text-muted-foreground">Hash that was signed</dt>
            <dd className="font-mono [overflow-wrap:anywhere]">{state.signedHash}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Hash of the bytes on disk now</dt>
            <dd className="font-mono [overflow-wrap:anywhere]">
              {state.storedHash ?? <span className="text-destructive">unreadable — {state.storedHashError}</span>}
            </dd>
          </div>
        </dl>
        {state.signatureAltered && (
          <p className="mt-2 text-xs text-destructive">The stored signature bytes have been altered.</p>
        )}
      </div>

      {error && <p className="rounded-lg border border-destructive/35 bg-destructive/[0.07] px-3 py-2 text-sm text-destructive">{error}</p>}

      <div className="space-y-3">
        <div className="space-y-2 rounded-lg border p-3">
          <p className="text-sm font-medium">Replace the stored bytes</p>
          <p className="text-xs text-muted-foreground">
            Writes a file of your choosing into the store, correctly encrypted, without touching the recorded hash. The
            replacement stays a perfectly valid file — edit the original in its own application and upload it here.
          </p>
          <input
            type="file"
            aria-label="Replacement file"
            className="block w-full text-xs file:mr-3 file:rounded-md file:border file:border-input file:bg-muted file:px-2.5 file:py-1.5 file:text-xs file:font-medium hover:file:bg-accent"
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
              setError(null);
            }}
          />
          <Button type="button" variant="secondary" size="sm" disabled={!file || pending !== null} onClick={() => run("content")}>
            {pending === "content" ? <Loader2 aria-hidden className="animate-spin" /> : <ShieldAlert aria-hidden />}
            Replace stored bytes
          </Button>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="secondary" size="sm" disabled={pending !== null} onClick={() => run("ciphertext")}>
            {pending === "ciphertext" ? <Loader2 aria-hidden className="animate-spin" /> : <ShieldAlert aria-hidden />}
            Flip a ciphertext bit
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={pending !== null || !hasSignature}
            onClick={() => run("signature")}
          >
            {pending === "signature" ? <Loader2 aria-hidden className="animate-spin" /> : <ShieldAlert aria-hidden />}
            Flip a signature bit
          </Button>
          <Button
            type="button"
            size="sm"
            disabled={pending !== null || !(state.canRestoreContent || state.canRestoreSignature)}
            onClick={() => run("restore")}
          >
            {pending === "restore" ? <Loader2 aria-hidden className="animate-spin" /> : <RotateCcw aria-hidden />}
            Restore the original
          </Button>
        </div>
      </div>

      <p className="flex items-start gap-2 text-xs text-muted-foreground">
        <FlaskConical aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        The original bytes are kept, so Restore puts the document back exactly as it was. Each action is written to the
        audit log, which is itself hash-chained — tampering here cannot be hidden from the log.
      </p>
    </div>
  );
}
