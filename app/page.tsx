const LAYERS = [
  { name: "Presentation", detail: "Next.js pages + API route handlers", phase: "Phases 1-9" },
  { name: "Authentication & Authorization", detail: "Sessions, RBAC", phase: "Phase 1" },
  { name: "Document Management", detail: "Upload, metadata, versioning, lifecycle", phase: "Phase 2" },
  { name: "Cryptographic Orchestration", detail: "RSA / ECDSA / EdDSA providers", phase: "Phase 3" },
  { name: "PKI", detail: "Local CA, certificates, key lifecycle", phase: "Phase 4" },
  { name: "Secure Storage", detail: "Document blobs on disk + DB metadata", phase: "Phase 2" },
  { name: "Audit & Monitoring", detail: "Hash-chained append-only log", phase: "Phase 7" },
];

export default function HomePage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-semibold tracking-tight">OmniTrust Ledger</h1>
      <p className="mt-3 text-muted-foreground">
        PKI-driven document management with algorithm-agnostic signature orchestration.
      </p>

      <div className="mt-10 rounded-lg border">
        <div className="border-b px-4 py-3 text-sm font-medium">
          Seven-layer architecture &mdash; build status
        </div>
        <ul className="divide-y">
          {LAYERS.map((layer) => (
            <li key={layer.name} className="flex items-baseline justify-between gap-4 px-4 py-3">
              <div>
                <div className="text-sm font-medium">{layer.name}</div>
                <div className="text-xs text-muted-foreground">{layer.detail}</div>
              </div>
              <span className="whitespace-nowrap text-xs text-muted-foreground">{layer.phase}</span>
            </li>
          ))}
        </ul>
      </div>

      <p className="mt-8 text-sm text-muted-foreground">
        Scaffold only (Phase 0). No cryptographic operations are wired up yet &mdash; see{" "}
        <code className="rounded bg-muted px-1 py-0.5 text-xs">PROGRESS.md</code> for what is
        implemented and what is not.
      </p>
    </div>
  );
}
