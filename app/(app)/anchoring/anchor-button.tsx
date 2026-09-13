"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";

export function AnchorButton({ pending, chainReachable }: { pending: number; chainReachable: boolean }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "error" | "info"; text: string } | null>(null);

  async function anchor() {
    setBusy(true);
    setMessage(null);
    const response = await fetch("/api/anchoring/batches", { method: "POST" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setMessage({ tone: "error", text: body.error ?? "Anchoring failed" });
    } else {
      setMessage({
        tone: "info",
        text: `Anchored ${body.batch.leafCount} commitment${body.batch.leafCount === 1 ? "" : "s"} in block ${body.batch.blockNumber}.`,
      });
    }
    setBusy(false);
    router.refresh();
  }

  return (
    <div className="space-y-2">
      <Button onClick={anchor} disabled={busy || pending === 0 || !chainReachable}>
        {busy ? "Anchoring..." : `Anchor ${pending} pending commitment${pending === 1 ? "" : "s"}`}
      </Button>
      {message && (
        <p role={message.tone === "error" ? "alert" : "status"} className={`text-sm ${message.tone === "error" ? "text-destructive" : "text-muted-foreground"}`}>
          {message.text}
        </p>
      )}
    </div>
  );
}
