"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function UploadForm() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

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
        <Label htmlFor="file">File</Label>
        <Input
          id="file"
          type="file"
          required
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setError(null);
          }}
        />
        {file && (
          <p className="text-xs text-muted-foreground">
            {file.name} &mdash; {file.size} bytes
          </p>
        )}
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" disabled={pending || !file}>
        {pending ? "Hashing and storing..." : "Upload"}
      </Button>
    </form>
  );
}
