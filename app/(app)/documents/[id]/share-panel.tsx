"use client";

import { Check, Copy, Link2, Loader2, Share2, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type ShareSummary = {
  id: string;
  versionNumber: number;
  audience: string;
  note: string | null;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  accessCount: number;
  lastAccessedAt: string | null;
  state: "ACTIVE" | "EXPIRED" | "WITHDRAWN";
};

const STATE_TONE: Record<ShareSummary["state"], string> = {
  ACTIVE: "border-success/40 bg-success/[0.08] text-success",
  EXPIRED: "border-border bg-muted text-muted-foreground",
  WITHDRAWN: "border-destructive/40 bg-destructive/[0.08] text-destructive",
};

const DAYS = [1, 7, 30, 90];

export function SharePanel({
  documentId,
  versionNumber,
  initialShares,
  canShare,
}: {
  documentId: string;
  versionNumber: number;
  initialShares: ShareSummary[];
  canShare: boolean;
}) {
  const router = useRouter();
  const [shares, setShares] = useState(initialShares);
  const [audience, setAudience] = useState("");
  const [note, setNote] = useState("");
  const [days, setDays] = useState(7);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);
  // Shown once and never again: the token is not stored, only a hash of it.
  const [freshLink, setFreshLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setFreshLink(null);

    const response = await fetch(`/api/documents/${documentId}/shares`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ audience, note: note || undefined, days, version: versionNumber }),
    });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.error ?? "The link could not be created");
      setPending(false);
      return;
    }

    setShares((current) => [payload.share, ...current]);
    setFreshLink(`${window.location.origin}/share/${payload.token}`);
    setAudience("");
    setNote("");
    setPending(false);
    router.refresh();
  }

  async function withdraw(shareId: string) {
    setRevoking(shareId);
    setError(null);

    const response = await fetch(`/api/shares/${shareId}`, { method: "DELETE" });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.error ?? "That could not be withdrawn");
      setRevoking(null);
      return;
    }

    setShares((current) => current.map((share) => (share.id === shareId ? payload.share : share)));
    setRevoking(null);
    router.refresh();
  }

  return (
    <div className="space-y-5">
      {canShare && (
        <form onSubmit={create} className="space-y-3 rounded-lg border p-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <label htmlFor="share-audience" className="text-sm font-medium">
                Who is this for?
              </label>
              <input
                id="share-audience"
                value={audience}
                onChange={(event) => setAudience(event.target.value)}
                placeholder="Acme Ltd, hiring team"
                required
                maxLength={120}
                className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-ring"
              />
              <p className="text-xs text-muted-foreground">Recorded for your own trail, and shown to whoever opens the link.</p>
            </div>
            <div className="space-y-1.5">
              <span className="text-sm font-medium">Expires after</span>
              <div role="group" aria-label="Expires after" className="flex flex-wrap gap-1.5">
                {DAYS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    aria-pressed={days === option}
                    onClick={() => setDays(option)}
                    className={cn(
                      "rounded-lg border px-2.5 py-1.5 text-xs transition-colors",
                      days === option ? "border-primary bg-primary/10 text-foreground" : "bg-card text-muted-foreground hover:bg-accent",
                    )}
                  >
                    {option} day{option === 1 ? "" : "s"}
                  </button>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">Every link expires. You can withdraw one sooner at any time.</p>
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="share-note" className="text-sm font-medium">
              Note for the recipient <span className="font-normal text-muted-foreground">(optional)</span>
            </label>
            <input
              id="share-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              maxLength={500}
              placeholder="The signed transcript you asked for."
              className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-ring"
            />
          </div>

          {error && <p role="alert" className="rounded-lg border border-destructive/35 bg-destructive/[0.07] px-3 py-2 text-sm text-destructive">{error}</p>}

          <Button type="submit" size="sm" disabled={pending || audience.trim().length === 0}>
            {pending ? <Loader2 aria-hidden className="animate-spin" /> : <Share2 aria-hidden />}
            Create a link for v{versionNumber}
          </Button>
        </form>
      )}

      {freshLink && (
        <div className="space-y-2 rounded-lg border border-primary/40 bg-primary/[0.06] p-3">
          <p className="text-sm font-medium">Copy this link now — it is shown only once.</p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="min-w-0 flex-1 break-all rounded-md border bg-card px-2 py-1.5 font-mono text-[11px]">{freshLink}</code>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={async () => {
                await navigator.clipboard.writeText(freshLink);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
            >
              {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Only a hash of this link is stored, so it cannot be shown again and a copy of the database would not reveal it.
            Losing it means withdrawing this share and making another.
          </p>
        </div>
      )}

      <div className="space-y-2">
        <h3 className="text-sm font-medium">Links on this document</h3>
        {shares.length === 0 ? (
          <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
            Nothing has been shared yet.
          </p>
        ) : (
          <ul className="space-y-2">
            {shares.map((share) => (
              <li key={share.id} className="rounded-lg border p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={cn("rounded-md border px-1.5 py-0.5 font-mono text-[10px]", STATE_TONE[share.state])}>{share.state}</span>
                  <span className="text-sm font-medium">{share.audience}</span>
                  <span className="font-mono text-[11px] text-muted-foreground">v{share.versionNumber}</span>
                  {canShare && share.state === "ACTIVE" && (
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      className="ml-auto h-7 px-2 text-xs"
                      disabled={revoking !== null}
                      onClick={() => withdraw(share.id)}
                    >
                      {revoking === share.id ? <Loader2 aria-hidden className="animate-spin" /> : <X aria-hidden />}
                      Withdraw
                    </Button>
                  )}
                </div>
                {share.note && <p className="mt-1 text-xs text-muted-foreground">{share.note}</p>}
                <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                  shared {share.createdAt.replace("T", " ").slice(0, 16)} · expires {share.expiresAt.replace("T", " ").slice(0, 16)} ·{" "}
                  opened {share.accessCount}×{share.lastAccessedAt ? ` · last ${share.lastAccessedAt.replace("T", " ").slice(0, 16)}` : ""}
                  {share.revokedAt ? ` · withdrawn ${share.revokedAt.replace("T", " ").slice(0, 16)}` : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>

      <p className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
        <Link2 aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        A link lets someone without an account verify this one version, and nothing else. Creating, opening and withdrawing
        one each append to the hash-chained audit log, so the record of who you gave access to cannot be quietly rewritten —
        not even by whoever runs this installation.
      </p>
    </div>
  );
}
