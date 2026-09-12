"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";

export function RevokeButton({ certificateId }: { certificateId: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [confirming, setConfirming] = useState(false);

  async function revoke() {
    setPending(true);
    await fetch(`/api/certificates/${certificateId}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "Revoked from the certificates page" }),
    });
    setPending(false);
    setConfirming(false);
    router.refresh();
  }

  if (!confirming) {
    return (
      <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
        Revoke
      </Button>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <Button variant="destructive" size="sm" onClick={revoke} disabled={pending}>
        {pending ? "Revoking..." : "Confirm"}
      </Button>
      <Button variant="ghost" size="sm" onClick={() => setConfirming(false)} disabled={pending}>
        Cancel
      </Button>
    </div>
  );
}
