import fs from "node:fs";
import path from "node:path";
import Link from "next/link";
import { redirect } from "next/navigation";
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
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Algorithms</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Everything on this page is read from the provider registry in lib/crypto at render time, joined with
          live usage counts and, where available, medians measured on this machine. Each numeric claim in the
          metadata is checked against real keys and signatures by tests/crypto/metadata.test.ts.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Comparison</CardTitle>
          <CardDescription>
            {measured
              ? `Timing columns: medians from npm run benchmark, run ${measured.generatedAt.slice(0, 10)}. Absolute numbers depend on the machine; compare rows, not across machines.`
              : "Timing columns appear after npm run benchmark has been run on this machine."}
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Algorithm</TableHead>
                <TableHead>Class</TableHead>
                <TableHead>Security</TableHead>
                <TableHead>Public key</TableHead>
                <TableHead>Signature</TableHead>
                <TableHead>Deterministic</TableHead>
                <TableHead>Sign / verify (median)</TableHead>
                <TableHead>In use</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {algorithms.map((algorithm) => {
                const median = medianBy.get(algorithm.id);
                return (
                  <TableRow key={algorithm.id}>
                    <TableCell>
                      <div className="font-medium">{algorithm.displayName}</div>
                      <div className="text-xs text-muted-foreground">{algorithm.family}</div>
                    </TableCell>
                    <TableCell>
                      <SecurityClassBadge securityClass={algorithm.securityClass} />
                    </TableCell>
                    <TableCell className="text-xs">
                      {[
                        algorithm.securityLevel.nistPqCategory !== null ? `NIST PQ category ${algorithm.securityLevel.nistPqCategory}` : null,
                        algorithm.securityLevel.classicalBits !== null ? `~${algorithm.securityLevel.classicalBits}-bit classical` : null,
                      ]
                        .filter(Boolean)
                        .join(" + ")}
                    </TableCell>
                    <TableCell className="text-xs">{algorithm.keySizes.publicKeyBytes} bytes</TableCell>
                    <TableCell className="text-xs">
                      {algorithm.signature.fixedBytes !== null ? `${algorithm.signature.fixedBytes} bytes` : `up to ${algorithm.signature.maxBytes} bytes`}
                    </TableCell>
                    <TableCell className="text-xs">{algorithm.deterministic ? "yes" : "no (randomised)"}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {median ? `${median.signMs.toFixed(3)} / ${median.verifyMs.toFixed(3)} ms` : "not measured"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {certificatesBy.get(algorithm.id) ?? 0} certs, {signaturesBy.get(algorithm.id) ?? 0} signatures
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        {algorithms.map((algorithm) => (
          <Card key={algorithm.id}>
            <CardHeader>
              <CardTitle className="text-base">{algorithm.displayName}</CardTitle>
              <CardDescription>{algorithm.description}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-xs">
              <div>
                <span className="text-muted-foreground">Standards: </span>
                {algorithm.standards.join(", ")}
              </div>
              <div>
                <span className="text-muted-foreground">Implementation: </span>
                {algorithm.implementation.library} ({algorithm.implementation.backend}) {algorithm.implementation.version}
              </div>
              <div>
                <span className="text-muted-foreground">Quantum resistance: </span>
                {algorithm.quantumResistance}
              </div>
              <div>
                <span className="text-muted-foreground">Message processing: </span>
                {algorithm.messageProcessing}
              </div>
              <div className="font-mono">
                <span className="font-sans text-muted-foreground">OIDs: </span>
                key {algorithm.oids.publicKey}, signature {algorithm.oids.signature}; CMS digest {algorithm.cms.digestAlgorithmOid} ({algorithm.cms.standard})
              </div>
              <div>
                <span className="text-muted-foreground">Independent check: </span>
                {algorithm.interoperability.opensslVerify ? "OpenSSL CLI verifies raw signatures" : "no OpenSSL CLI command"}
                {"; "}
                {algorithm.interoperability.opensslCms ? "OpenSSL CLI verifies its CMS export" : "CMS export checked against an independent implementation in tests"}
              </div>
              {algorithm.securityNotes.length > 0 && (
                <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
                  {algorithm.securityNotes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Crypto-agility</CardTitle>
          <CardDescription>What it takes to add or remove an algorithm, and how that claim is checked.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>
            {algorithms.length} providers are registered. Certificate issuance, signing, the verification workflow, the
            CMS export, anchoring commitments, the Security Lab and every page resolve algorithms through the registry,
            so none of them names one.
          </p>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
            <li>
              <code className="text-xs">tests/crypto/agility.test.ts</code> registers an extra ML-DSA-44 provider at test time and
              issues a certificate, signs and verifies through it with no change to any other layer.
            </li>
            <li>
              <code className="text-xs">npm run check:boundary</code> fails if algorithm-specific imports or algorithm names
              appear outside lib/crypto (with one allowlisted policy file choosing the CA&apos;s algorithm).
            </li>
            <li>
              Adding ML-DSA-65 to this installation touched one provider file and the registry; the upgrade log records the commit.
            </li>
          </ul>
          <p className="text-muted-foreground">
            Try it: issue a certificate for any algorithm on the <Link href="/certificates" className="underline underline-offset-2">Certificates</Link> page,
            sign a document with it, and verify.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
