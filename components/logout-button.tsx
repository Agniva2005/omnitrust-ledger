"use client";

import { Button } from "@/components/ui/button";

export function LogoutButton() {
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={async () => {
        await fetch("/api/auth/logout", { method: "POST" });
        // A full navigation, not router.replace + router.refresh: the refresh re-requested the
        // page being left, so the signed-out user stayed on it, and the client router cache
        // kept previously rendered authenticated pages available to back/forward navigation.
        window.location.replace("/login");
      }}
    >
      Sign out
    </Button>
  );
}
