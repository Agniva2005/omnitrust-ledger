import { Atom, FileCheck2, Fingerprint, ScrollText, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { LoginForm } from "@/app/login/login-form";
import { DemoNotice } from "@/components/demo-notice";
import { getSession } from "@/lib/auth/session";
import { orchestrator } from "@/lib/crypto/orchestrator";

export const metadata = { title: "Sign in" };

export default async function LoginPage() {
  if (await getSession()) redirect("/dashboard");
  const algorithms = orchestrator.describeAll();

  const claims = [
    { icon: Atom, title: `${algorithms.length} signature algorithms`, detail: "Classical, post-quantum ML-DSA-65 and a hybrid composite, all behind one orchestrator." },
    { icon: Fingerprint, title: "Ten-step verification", detail: "Four verdicts that are never collapsed: VALID, INVALID, UNVERIFIABLE and ERROR." },
    { icon: FileCheck2, title: "Evidence outside the app", detail: "RFC 3161 time-stamps, CA-signed CRLs and CMS exports that OpenSSL can check." },
    { icon: ScrollText, title: "Tamper-evident history", detail: "A hash-chained audit log with signed checkpoints and Merkle anchoring." },
  ];

  return (
    <div className="grid min-h-screen lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
      <section className="relative hidden overflow-hidden border-r bg-sidebar lg:flex lg:flex-col">
        <div aria-hidden className="bg-grid absolute inset-0 [mask-image:radial-gradient(ellipse_at_top_left,black_30%,transparent_75%)]" />
        <div aria-hidden className="absolute -left-24 -top-24 h-96 w-96 rounded-full bg-primary/15 blur-3xl" />
        <div aria-hidden className="absolute -bottom-32 right-0 h-96 w-96 rounded-full bg-hybrid/10 blur-3xl" />

        <div className="relative flex flex-1 flex-col justify-between p-10 xl:p-14">
          <Link href="/" className="flex items-center gap-2.5">
            <span aria-hidden className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-primary to-hybrid text-xs font-bold text-primary-foreground shadow-sm">
              OT
            </span>
            <span className="text-sm font-semibold tracking-tight">OmniTrust Ledger</span>
          </Link>

          <div className="max-w-lg space-y-8">
            <div className="space-y-3">
              <p className="inline-flex items-center gap-1.5 rounded-full border bg-card px-2.5 py-1 text-xs text-muted-foreground shadow-card">
                <ShieldCheck aria-hidden className="h-3.5 w-3.5 text-primary" /> Crypto-agile document signing
              </p>
              <h2 className="text-balance text-3xl font-semibold tracking-tight xl:text-4xl">
                Signatures you can verify, revoke and prove, across classical and post-quantum algorithms.
              </h2>
            </div>
            <ul className="grid gap-4 sm:grid-cols-2">
              {claims.map(({ icon: Icon, title, detail }) => (
                <li key={title} className="rounded-xl border bg-card/80 p-4 shadow-card backdrop-blur">
                  <Icon aria-hidden className="h-4 w-4 text-primary" />
                  <div className="mt-2 text-sm font-medium">{title}</div>
                  <div className="mt-1 text-xs leading-relaxed text-muted-foreground">{detail}</div>
                </li>
              ))}
            </ul>
          </div>

          <DemoNotice className="max-w-lg" />
        </div>
      </section>

      <section className="flex flex-col justify-center px-6 py-12 sm:px-10">
        <div className="mx-auto w-full max-w-sm animate-slide-up">
          <div className="mb-8 lg:hidden">
            <span aria-hidden className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-primary to-hybrid text-xs font-bold text-primary-foreground">
              OT
            </span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">Sign in to OmniTrust Ledger</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Use one of the demo accounts below. All four share the password{" "}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground">demo1234</code>.
          </p>
          <div className="mt-8">
            <LoginForm />
          </div>
          <DemoNotice className="mt-10 lg:hidden" />
        </div>
      </section>
    </div>
  );
}
