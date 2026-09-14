"use client";

import { FileText, Loader2, UploadCloud, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function UploadForm() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [dragging, setDragging] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!file) return;

    setPending(true);
    setError(null);

    const body = new FormData();
    body.append("file", file);

    const response = await fetch("/api/documents", { method: "POST", body });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.error ?? "Upload failed");
      setPending(false);
      return;
    }

    router.push(`/documents/${payload.document.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <span className="text-sm font-medium">File</span>
        <label
          htmlFor="file"
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
            "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring",
            dragging ? "border-primary bg-accent/60" : "border-input bg-muted/30 hover:border-primary/50 hover:bg-accent/30",
          )}
        >
          <span className="grid h-11 w-11 place-items-center rounded-full bg-card shadow-card">
            <UploadCloud aria-hidden className="h-5 w-5 text-primary" />
          </span>
          <span className="text-sm font-medium">Drop a file here, or click to choose one</span>
          <span className="text-xs text-muted-foreground">Any file type. Zero-byte files and exact duplicates are refused.</span>
          <input
            id="file"
            type="file"
            required
            className="sr-only"
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
              setError(null);
            }}
          />
        </label>
        {file && (
          <div className="flex items-center gap-3 rounded-lg border bg-card px-3 py-2 shadow-card">
            <FileText aria-hidden className="h-4 w-4 shrink-0 text-primary" />
            <p className="min-w-0 flex-1 truncate text-sm">
              {file.name} &mdash; {file.size} bytes <span className="text-muted-foreground">({formatBytes(file.size)})</span>
            </p>
            <button
              type="button"
              aria-label="Remove file"
              onClick={() => setFile(null)}
              className="grid h-7 w-7 place-items-center rounded-md text-muted-foreground hover:bg-secondary hover:text-foreground"
            >
              <X aria-hidden className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>

      {error && (
        <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" disabled={pending || !file}>
        {pending && <Loader2 aria-hidden className="animate-spin" />}
        {pending ? "Hashing and storing..." : "Upload"}
      </Button>
    </form>
  );
}
