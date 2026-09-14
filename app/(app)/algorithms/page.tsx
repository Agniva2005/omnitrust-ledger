import fs from "node:fs";
import path from "node:path";
import { FlaskConical, KeyRound, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { PageHeader } from "@/components/page-header";
import { SecurityClassBadge } from "@/components/security-class-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getSession } from "@/lib/auth/session";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

type Medians = { algorithm: string; signMs: number; verifyMs: number; keyGenerationMs: number };

/** Measured medians from `npm run benchmark`, if it has been run on this machine. */
function measuredMedians(): { generatedAt: string; rows: Medians[] } | null {
  const file = path.join(process.cwd(), "public", "benchmarks.json");
  if (!fs.existsSync(file)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8")) as {
      generatedAt: string;
      algorithms: { algorithm: string; keyGeneration: { medianMs: number }; payloads: { sign: { medianMs: number }; verify: { medianMs: number } }[] }[];
    };
    return {
      generatedAt: data.generatedAt,
      rows: data.algorithms.map((entry) => ({
        algorithm: entry.algorithm,
        signMs: entry.payloads[0]?.sign.medianMs,
        verifyMs: entry.payloads[0]?.verify.medianMs,
        keyGenerationMs: entry.keyGeneration.medianMs,
      })),
    };
  } catch {
    return null;
  }
}

function Detail({ label, children, mono = false }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 border-b py-2 last:border-b-0 sm:grid-cols-[9rem_1fr] sm:gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono [overflow-wrap:anywhere]" : "[overflow-wrap:anywhere]"}>{children}</dd>
    </div>
  );
}

export default async function AlgorithmsPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const algorithms = orchestrator.describeAll();
  const [signatureGroups, certificateGroups] = await Promise.all([
    prisma.signature.groupBy({ by: ["algorithm"], _count: { _all: true } }),
    prisma.certificate.groupBy({ by: ["algorithm"], _count: { _all: true } }),
  ]);
  const signaturesBy = new Map(signatureGroups.map((group) => [group.algorithm, group._count._all]));
  const certificatesBy = new Map(certificateGroups.map((group) => [group.algorithm, group._count._all]));
  const measured = measuredMedians();
  const medianBy = new Map(measured?.rows.map((row) => [row.algorithm, row]) ?? []);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={KeyRound}
        eyebrow="Trust"
        title="Algorithms"
        description="Everything on this page is read from the provider registry in lib/crypto at render time, joined with live usage counts and, where available, medians measured on this machine. Each numeric claim in the metadata is checked against real keys and signatures by tests/crypto/metadata.test.ts."
      />

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Comparison</CardTitle>
          <CardDescription>
            {measured
              ? `Timing columns: medians from npm run benchmark, run ${measured.generatedAt.slice(0, 10)}. Absolute numbers depend on the machine; compare rows, not across machines.`
              : "Timing columns appear after npm run benchmark has been run on this machine."}
          </CardDescription>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-5">Algorithm</TableHead>
              <TableHead>Class</TableHead>
              <TableHead>Security</TableHead>
              <TableHead className="text-right">Public key</TableHead>
              <TableHead className="text-right">Signature</TableHead>
              <TableHead className="hidden 2xl:table-cell">Deterministic</TableHead>
              <TableHead className="text-right">Sign / verify (median)</TableHead>
              <TableHead className="pr-5 text-right">In use</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {algorithms.map((algorithm) => {
              const median = medianBy.get(algorithm.id);
              return (
                <TableRow key={algorithm.id}>
                  <TableCell className="pl-5">
                    <div className="whitespace-nowrap font-medium">{algorithm.displayName}</div>
                    <div className="text-xs text-muted-foreground">{algorithm.family}</div>
                  </TableCell>
                  <TableCell>
                    <SecurityClassBadge securityClass={algorithm.securityClass} />
                  </TableCell>
                  <TableCell className="text-xs">
                    {algorithm.securityLevel.nistPqCategory !== null && <div className="whitespace-nowrap">NIST PQ category {algorithm.securityLevel.nistPqCategory}</div>}
                    {algorithm.securityLevel.classicalBits !== null && <div className="whitespace-nowrap text-muted-foreground">~{algorithm.securityLevel.classicalBits}-bit classical</div>}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-right font-mono text-xs tabular-nums">{algorithm.keySizes.publicKeyBytes} B</TableCell>
                  <TableCell className="whitespace-nowrap text-right font-mono text-xs tabular-nums">
                    {algorithm.signature.fixedBytes !== null ? `${algorithm.signature.fixedBytes} B` : `≤ ${algorithm.signature.maxBytes} B`}
                  </TableCell>
                  <TableCell className="hidden whitespace-nowrap text-xs 2xl:table-cell">{algorithm.deterministic ? "yes" : "no (randomised)"}</TableCell>
                  <TableCell className="whitespace-nowrap text-right font-mono text-xs tabular-nums">
                    {median ? `${median.signMs.toFixed(3)} / ${median.verifyMs.toFixed(3)} ms` : "not measured"}
                  </TableCell>
                  <TableCell className="whitespace-nowrap pr-5 text-right text-xs text-muted-foreground">
                    {certificatesBy.get(algorithm.id) ?? 0} certs · {signaturesBy.get(algorithm.id) ?? 0} sigs
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {algorithms.map((algorithm) => (
          <Card key={algorithm.id}>
            <CardHeader>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <CardTitle>{algorithm.displayName}</CardTitle>
                <SecurityClassBadge securityClass={algorithm.securityClass} />
              </div>
              <CardDescription>{algorithm.description}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">
              <dl>
                <Detail label="Standards">{algorithm.standards.join(", ")}</Detail>
                <Detail label="Deterministic">{algorithm.deterministic ? "yes: the same message and key give the same signature" : "no (randomised)"}</Detail>
                <Detail label="Implementation">
                  {algorithm.implementation.library} ({algorithm.implementation.backend}) {algorithm.implementation.version}
                </Detail>
                <Detail label="Quantum resistance">{algorithm.quantumResistance}</Detail>
                <Detail label="Message processing">{algorithm.messageProcessing}</Detail>
                <Detail label="OIDs" mono>
                  key {algorithm.oids.publicKey}, signature {algorithm.oids.signature}; CMS digest {algorithm.cms.digestAlgorithmOid} ({algorithm.cms.standard})
                </Detail>
                <Detail label="Independent check">
                  {algorithm.interoperability.opensslVerify ? "OpenSSL CLI verifies raw signatures" : "no OpenSSL CLI command"}
                  {"; "}
                  {algorithm.interoperability.opensslCms ? "OpenSSL CLI verifies its CMS export" : "CMS export checked against an independent implementation in tests"}
                </Detail>
              </dl>
              {algorithm.securityNotes.length > 0 && (
                <ul className="space-y-1.5 rounded-lg border bg-muted/25 p-3 text-muted-foreground">
                  {algorithm.securityNotes.map((note) => (
                    <li key={note} className="flex gap-2">
                      <ShieldCheck aria-hidden className="mt-px h-3.5 w-3.5 shrink-0 text-primary" />
                      {note}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FlaskConical aria-hidden className="h-4 w-4 text-primary" /> Crypto-agility
          </CardTitle>
          <CardDescription>What it takes to add or remove an algorithm, and how that claim is checked.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>
            {algorithms.length} providers are registered. Certificate issuance, signing, the verification workflow, the CMS export, anchoring commitments, the
            Security Lab and every page resolve algorithms through the registry, so none of them names one.
          </p>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
            <li>
              <code className="font-mono text-xs">tests/crypto/agility.test.ts</code> registers an extra ML-DSA-44 provider at test time and issues a certificate,
              signs and verifies through it with no change to any other layer.
            </li>
            <li>
              <code className="font-mono text-xs">npm run check:boundary</code> fails if algorithm-specific imports or algorithm names appear outside lib/crypto (with
              one allowlisted policy file choosing the CA&apos;s algorithm).
            </li>
            <li>Adding ML-DSA-65, and later the ML-DSA-65 + ECDSA P-256 composite, each touched one provider file and the registry; the upgrade log records the commits.</li>
          </ul>
          <p className="text-muted-foreground">
            Try it: issue a certificate for any algorithm on the{" "}
            <Link href="/certificates" className="font-medium text-primary underline-offset-2 hover:underline">
              Certificates
            </Link>{" "}
            page, sign a document with it, and verify.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
