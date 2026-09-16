"use client";

import { FilePlus2, Loader2, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function NewVersionPanel({
  documentId,
  currentVersion,
  currentHash,
}: {
  documentId: string;
  currentVersion: number;
  currentHash: string;
}) {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [added, setAdded] = useState<{ version: number; hash: string } | null>(null);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!file) return;

    setPending(true);
    setError(null);
    setAdded(null);

    const body = new FormData();
    body.append("file", file);

    const response = await fetch(`/api/documents/${documentId}/versions`, { method: "POST", body });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.error ?? "Could not add a new version");
      setPending(false);
      return;
    }

    setAdded({ version: currentVersion + 1, hash: payload.document.currentHash });
    setFile(null);
    setPending(false);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <label
        htmlFor="new-version-file"
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          const dropped = event.dataTransfer.files?.[0];
          if (dropped) {
            setFile(dropped);
            setError(null);
          }
        }}
        className={cn(
          "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-6 py-8 text-center transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring",
          dragging ? "border-primary bg-accent/60" : "border-input bg-muted/30 hover:border-primary/50 hover:bg-accent/30",
        )}
      >
        <span className="grid h-10 w-10 place-items-center rounded-full bg-card shadow-card">
          <FilePlus2 aria-hidden className="h-5 w-5 text-primary" />
        </span>
        <span className="text-sm font-medium">Choose the edited file, or drop it here</span>
        <span className="text-xs text-muted-foreground">
          It becomes v{currentVersion + 1}. v{currentVersion} and its signature are left untouched.
        </span>
        <input
          id="new-version-file"
          name="file"
          type="file"
          className="sr-only"
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setError(null);
          }}
        />
      </label>

      {file && (
        <div className="flex items-center justify-between gap-3 rounded-lg border bg-muted/40 px-3 py-2 text-sm">
          <span className="min-w-0 truncate">
            {file.name} <span className="text-muted-foreground">· {formatBytes(file.size)}</span>
          </span>
          <Button type="button" variant="ghost" size="sm" onClick={() => setFile(null)} aria-label="Clear selected file">
            <X aria-hidden />
          </Button>
        </div>
      )}

      {error && <p className="rounded-lg border border-destructive/35 bg-destructive/[0.07] px-3 py-2 text-sm text-destructive">{error}</p>}

      {added && (
        <div className="space-y-2 rounded-lg border border-success/35 bg-success/[0.07] p-3 text-sm">
          <p className="font-medium text-success">v{added.version} added — the content changed.</p>
          <dl className="grid gap-1.5 text-xs">
            <div>
              <dt className="text-muted-foreground">v{currentVersion} (signed)</dt>
              <dd className="font-mono [overflow-wrap:anywhere]">{currentHash}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">v{added.version} (new, unsigned)</dt>
              <dd className="font-mono [overflow-wrap:anywhere]">{added.hash}</dd>
            </div>
          </dl>
          <p className="text-xs text-muted-foreground">
            Two different hashes, so the old signature cannot cover the new bytes. v{currentVersion} stays verifiable on its own.
          </p>
        </div>
      )}

      <Button type="submit" disabled={!file || pending}>
        {pending ? <Loader2 aria-hidden className="animate-spin" /> : <FilePlus2 aria-hidden />}
        {pending ? "Adding version..." : `Add as v${currentVersion + 1}`}
      </Button>
    </form>
  );
}
