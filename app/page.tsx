import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { orchestrator } from "@/lib/crypto/orchestrator";

const LAYERS = [
  { name: "Presentation", detail: "Next.js pages and API route handlers", folder: "app/" },
  { name: "Authentication & Authorization", detail: "Sessions and a role-to-capability map", folder: "lib/auth/" },
  { name: "Document Management", detail: "Upload, hashing, versioning, lifecycle", folder: "lib/documents/" },
  {
    name: "Cryptographic Orchestration",
    detail: "The only place algorithm-specific code lives",
    folder: "lib/crypto/",
  },
  { name: "PKI", detail: "Local CA, certificates, key lifecycle", folder: "lib/pki/" },
  { name: "Secure Storage", detail: "Encrypted blobs on disk, no crypto decisions", folder: "lib/documents/storage.ts" },
  { name: "Audit & Monitoring", detail: "Append-only hash-chained log", folder: "lib/audit/" },
];

export default function HomePage() {
  const algorithms = orchestrator.describeAll();

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-semibold tracking-tight">OmniTrust Ledger</h1>
      <p className="mt-3 text-muted-foreground">
        PKI-driven document management with algorithm-agnostic signature orchestration.
      </p>

      <div className="mt-6 flex gap-3">
        <Button asChild>
          <Link href="/login">Sign in</Link>
        </Button>
      </div>

      <Card className="mt-10">
        <CardHeader>
          <CardTitle>Signature algorithms</CardTitle>
          <CardDescription>
            Read from the orchestrator&apos;s registry at render time. Adding a fourth algorithm
            means one new provider file and one registry line; this page would pick it up without
            being edited.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {algorithms.map((algorithm) => (
            <div key={algorithm.algorithm} className="flex flex-wrap items-baseline gap-2">
              <Badge variant="secondary">{algorithm.displayName}</Badge>
              <span className="text-xs text-muted-foreground">
                {algorithm.signatureByteLength
                  ? `${algorithm.signatureByteLength}-byte signatures`
                  : "variable-length signatures"}
              </span>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Seven-layer architecture</CardTitle>
          <CardDescription>
            Each layer depends only on the layers beneath it. The boundary around the
            cryptographic layer is enforced by a test, not by convention.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <ul className="divide-y border-t">
            {LAYERS.map((layer) => (
              <li key={layer.name} className="flex items-baseline justify-between gap-4 px-6 py-3">
                <div>
                  <div className="text-sm font-medium">{layer.name}</div>
                  <div className="text-xs text-muted-foreground">{layer.detail}</div>
                </div>
                <code className="whitespace-nowrap text-xs text-muted-foreground">
                  {layer.folder}
                </code>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <p className="mt-8 text-sm text-muted-foreground">
        Every cryptographic operation here is real and independently checkable: run{" "}
        <code className="rounded bg-muted px-1 py-0.5 text-xs">
          npm run export:signature -- &lt;document&gt;
        </code>{" "}
        to verify any stored signature with OpenSSL, outside this application. See{" "}
        <code className="rounded bg-muted px-1 py-0.5 text-xs">README.md</code> for the
        limitations that keep this a demonstrator rather than a production system.
      </p>
    </div>
  );
}
