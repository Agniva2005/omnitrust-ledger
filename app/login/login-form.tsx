"use client";

import { ArrowRight, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

const DEMO_ACCOUNTS = [
  { email: "admin@demo", role: "ADMIN", detail: "Revokes, checkpoints, anchors, runs attacks" },
  { email: "signer@demo", role: "SIGNER", detail: "Uploads, issues certificates, signs" },
  { email: "verifier@demo", role: "VERIFIER", detail: "Verifies documents and the audit log" },
  { email: "viewer@demo", role: "VIEWER", detail: "Reads and exports only" },
];

export function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState("signer@demo");
  const [password, setPassword] = useState("demo1234");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);

    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({ error: "Login failed" }));
      setError(body.error ?? "Login failed");
      setPending(false);
      return;
    }

    router.replace("/dashboard");
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-5">
      <fieldset className="space-y-2">
        <legend className="mb-2 text-xs font-medium uppercase tracking-[0.06em] text-muted-foreground">Demo accounts</legend>
        <div className="grid grid-cols-2 gap-2">
          {DEMO_ACCOUNTS.map((account) => {
            const selected = email === account.email;
            return (
              <button
                key={account.email}
                type="button"
                aria-pressed={selected}
                title={account.detail}
                className={cn(
                  "rounded-lg border px-3 py-2 text-left transition-colors focus-visible:ring-2 focus-visible:ring-ring",
                  selected ? "border-primary/50 bg-accent text-accent-foreground" : "bg-card hover:bg-secondary",
                )}
                onClick={() => {
                  setEmail(account.email);
                  setPassword("demo1234");
                }}
              >
                <span className="block text-xs font-semibold tracking-wide">{account.role}</span>
                <span className="block truncate text-[11px] text-muted-foreground">{account.email}</span>
              </button>
            );
          })}
        </div>
      </fieldset>

      <div className="space-y-1.5">
        <Label htmlFor="email">Email</Label>
        <Input id="email" name="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} required />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />
      </div>

      {error && (
        <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" size="lg" className="w-full" disabled={pending}>
        {pending ? <Loader2 aria-hidden className="animate-spin" /> : null}
        {pending ? "Signing in..." : "Sign in"}
        {!pending && <ArrowRight aria-hidden />}
      </Button>
    </form>
  );
}
