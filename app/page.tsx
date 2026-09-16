import { ArrowRight, BadgeCheck, Clock, FileSignature, Layers3, Link2, ScrollText, ShieldCheck, TerminalSquare } from "lucide-react";
import Link from "next/link";
import { DemoNotice } from "@/components/demo-notice";
import { SecurityClassBadge } from "@/components/security-class-badge";
import { Button } from "@/components/ui/button";
import { orchestrator } from "@/lib/crypto/orchestrator";

const LAYERS = [
  { name: "Presentation", detail: "Next.js pages and API route handlers", folder: "app/" },
  { name: "Authentication & Authorization", detail: "Sessions and a role-to-capability map", folder: "lib/auth/" },
  { name: "Document Management", detail: "Upload, hashing, versioning, lifecycle", folder: "lib/documents/" },
  { name: "Cryptographic Orchestration", detail: "The only place algorithm-specific code lives", folder: "lib/crypto/" },
  { name: "PKI", detail: "Local CA, TSA, CRLs, certificates, key lifecycle", folder: "lib/pki/" },
  { name: "Secure Storage", detail: "Encrypted blobs on disk, no crypto decisions", folder: "lib/documents/storage.ts" },
  { name: "Audit & Monitoring", detail: "Append-only hash-chained log with signed checkpoints", folder: "lib/audit/" },
];

const PROOF_POINTS = [
  { icon: BadgeCheck, title: "Four honest verdicts", detail: "VALID, INVALID, UNVERIFIABLE and ERROR stay distinct, from the API to this interface." },
  { icon: Clock, title: "Time-aware revocation", detail: "A trusted RFC 3161 time-stamp decides whether a later revocation rewrites history." },
  { icon: TerminalSquare, title: "Verifiable elsewhere", detail: "CMS exports and CRLs are checked with the OpenSSL command line, not only in-app." },
  { icon: ScrollText, title: "Tamper-evident log", detail: "Every action is hash-chained; signed checkpoints catch a consistent rewrite." },
  { icon: Link2, title: "Anchored commitments", detail: "Only Merkle roots of 32-byte commitments reach a local chain, never documents." },
  { icon: ShieldCheck, title: "Attacked on purpose", detail: "The Security Lab runs real attacks in disposable sandboxes and reports whether controls held." },
];

function signatureSize(fixedBytes: number | null, maxBytes: number) {
  return fixedBytes === null ? `≤ ${maxBytes} B` : `${fixedBytes} B`;
}

export default function HomePage() {
  const algorithms = orchestrator.describeAll();

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-16 w-full max-w-content items-center justify-between px-4 sm:px-6 lg:px-8 2xl:px-10">
          <Link href="/" className="flex items-center gap-2.5">
            <span aria-hidden className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-primary to-hybrid text-[11px] font-bold text-primary-foreground shadow-sm">
              OT
            </span>
            <span className="text-sm font-semibold tracking-tight">OmniTrust Ledger</span>
          </Link>
          <Button asChild size="sm">
            <Link href="/login">
              Sign in <ArrowRight aria-hidden />
            </Link>
          </Button>
        </div>
      </header>

      <section className="relative overflow-hidden border-b">
        <div aria-hidden className="bg-grid absolute inset-0 [mask-image:radial-gradient(ellipse_at_top,black_25%,transparent_70%)]" />
        <div aria-hidden className="absolute left-1/2 top-0 h-64 w-[48rem] -translate-x-1/2 rounded-full bg-primary/10 blur-3xl" />
        <div className="relative mx-auto w-full max-w-content px-4 py-14 text-center sm:px-6 sm:py-16 lg:px-8 2xl:px-10">
          <p className="mx-auto inline-flex items-center gap-1.5 rounded-full border bg-card px-3 py-1 text-xs text-muted-foreground shadow-card">
            <FileSignature aria-hidden className="h-3.5 w-3.5 text-primary" />
            PKI-driven document signing, classical to post-quantum
          </p>
          <h1 className="mx-auto mt-5 max-w-4xl text-balance text-4xl font-semibold tracking-tight sm:text-5xl 2xl:text-6xl">OmniTrust Ledger</h1>
          <p className="mx-auto mt-4 max-w-3xl text-balance text-base leading-relaxed text-muted-foreground sm:text-lg">
            PKI-driven document management with algorithm-agnostic signature orchestration: sign under {algorithms.length} algorithms, verify every step,
            and keep evidence that survives revocation and outside scrutiny.
          </p>
        </div>
      </section>

      <main className="mx-auto w-full max-w-content space-y-16 px-4 py-14 sm:px-6 lg:px-8 lg:py-16 2xl:px-10">
        <section aria-labelledby="algorithms-heading">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h2 id="algorithms-heading" className="text-2xl font-semibold tracking-tight">Signature algorithms</h2>
              <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
                Read from the provider registry at render time. Adding an algorithm is one provider file and one registry entry; this page picks it
                up without being edited, and an automated test proves the rest of the system does too.
              </p>
            </div>
          </div>
          <ul className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {algorithms.map((algorithm, index) => (
              <li
                key={algorithm.id}
                className={`group rounded-xl border bg-card p-5 shadow-card transition-shadow hover:shadow-elevated ${
                  // With five algorithms in three columns, let the last card fill the row instead of leaving a gap.
                  index === algorithms.length - 1 && algorithms.length % 3 === 2 ? "lg:col-span-2" : ""
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-semibold tracking-tight">{algorithm.displayName}</div>
                    <div className="mt-0.5 text-xs text-muted-foreground">{algorithm.family}</div>
                  </div>
                  <SecurityClassBadge securityClass={algorithm.securityClass} />
                </div>
                <dl className="mt-5 grid grid-cols-3 gap-2 border-t pt-4 text-xs">
                  <div>
                    <dt className="text-muted-foreground">Signature</dt>
                    <dd className="mt-0.5 font-mono tabular-nums">{signatureSize(algorithm.signature.fixedBytes, algorithm.signature.maxBytes)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Public key</dt>
                    <dd className="mt-0.5 font-mono tabular-nums">{algorithm.keySizes.publicKeyBytes} B</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Security</dt>
                    <dd className="mt-0.5 font-mono tabular-nums">
                      {algorithm.securityLevel.nistPqCategory !== null ? `PQ cat ${algorithm.securityLevel.nistPqCategory}` : `${algorithm.securityLevel.classicalBits}-bit`}
                    </dd>
                  </div>
                </dl>
                <p className="mt-4 line-clamp-3 text-xs leading-relaxed text-muted-foreground">{algorithm.description}</p>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="proof-heading">
          <h2 id="proof-heading" className="text-2xl font-semibold tracking-tight">What the demo lets you check</h2>
          <ul className="mt-6 grid gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-2 lg:grid-cols-3">
            {PROOF_POINTS.map(({ icon: Icon, title, detail }) => (
              <li key={title} className="bg-card p-6">
                <span className="grid h-9 w-9 place-items-center rounded-lg border bg-accent text-accent-foreground">
                  <Icon aria-hidden className="h-4 w-4" />
                </span>
                <div className="mt-4 text-sm font-semibold">{title}</div>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{detail}</p>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="layers-heading" className="grid gap-10 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <div>
            <h2 id="layers-heading" className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
              <Layers3 aria-hidden className="h-5 w-5 text-primary" /> Seven-layer architecture
            </h2>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Each layer depends only on the layers beneath it. The boundary around the cryptographic layer is enforced by a test, not by
              convention: algorithm-specific imports or algorithm names outside <code className="font-mono text-xs">lib/crypto</code> fail the build.
            </p>
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
              Every cryptographic operation here is real and independently checkable: run{" "}
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground">npm run export:signature -- &lt;document&gt;</code> to verify a stored
              signature with the OpenSSL command line, outside this application.
            </p>
          </div>
          <ol className="overflow-hidden rounded-xl border bg-card shadow-card">
            {LAYERS.map((layer, index) => (
              <li key={layer.name} className="flex items-center gap-4 border-b px-5 py-3.5 last:border-b-0">
                <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md bg-muted font-mono text-[11px] text-muted-foreground">{index + 1}</span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium">{layer.name}</div>
                  <div className="truncate text-xs text-muted-foreground">{layer.detail}</div>
                </div>
                <code className="hidden whitespace-nowrap font-mono text-[11px] text-muted-foreground sm:block">{layer.folder}</code>
              </li>
            ))}
          </ol>
        </section>
      </main>

      <footer className="border-t">
        <div className="mx-auto w-full max-w-content px-4 py-6 sm:px-6 lg:px-8 2xl:px-10">
          <DemoNotice />
        </div>
      </footer>
    </div>
  );
}
