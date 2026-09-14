import fs from "node:fs";
import path from "node:path";
import { SecurityClassBadge } from "@/components/security-class-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { PairwiseComparison } from "@/lib/benchmarks/comparison";
import type { SampleSummary } from "@/lib/benchmarks/statistics";

type SizeRange = { min: number; median: number; max: number };

type StudyFile = {
  schemaVersion: number;
  generatedAt: string;
  durationMs: number;
  environment: { cpu: string; cores: number; node: string; openssl: string; platform: string; gitCommit: string | null; gitTreeDirty: boolean | null };
  parameters: { iterations: number; microIterations: number; warmupRounds?: number; seed?: number };
  isolation: { developmentDatabaseUnchanged: boolean };
  design?: { interleaving: string; seed: number };
  methodology: string[];
  notes: string[];
  algorithms: {
    algorithm: string;
    displayName: string;
    securityClass: string;
    sizes: {
      publicKeySpkiBytes: number;
      certificateDerBytes: number;
      signatureBytes: SizeRange;
      cmsSignedDataBytes: SizeRange;
      timestampTokenBytes: SizeRange;
      anchoringCommitmentBytes: number;
      crlGrowthPerRevokedCertificateBytes: number;
    };
    timings: Record<string, SampleSummary>;
  }[];
  comparisons: Record<string, PairwiseComparison[]>;
  agilityOverhead: { algorithm: string; sign: PairwiseComparison; verify: PairwiseComparison }[];
};

export function loadMigrationStudy(): StudyFile | null {
  const file = path.join(process.cwd(), "public", "migration-study.json");
  if (!fs.existsSync(file)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8")) as StudyFile;
    return Array.isArray(data.algorithms) && data.comparisons ? data : null;
  } catch {
    return null;
  }
}

const OPERATION_LABELS: Record<string, string> = {
  certificateIssuance: "Certificate issuance",
  signDocument: "End-to-end signing",
  verifyDocument: "Ten-step verification",
  cmsVerify: "CMS verification",
  orchestratorSign: "Sign primitive",
  orchestratorVerify: "Verify primitive",
};

function Multiple({ value, smallest }: { value: number; smallest: number }) {
  const ratio = value / smallest;
  return (
    <span className="ml-1.5 text-[11px] text-muted-foreground">{ratio >= 1.05 ? `${ratio.toFixed(1)}×` : "1×"}</span>
  );
}

function SizeBar({ value, largest }: { value: number; largest: number }) {
  return (
    <span className="mt-1 block h-1.5 w-full max-w-[9rem] overflow-hidden rounded-full bg-muted">
      <span className="block h-1.5 rounded-full bg-primary/70" style={{ width: `${Math.max(3, Math.round((value / largest) * 100))}%` }} />
    </span>
  );
}

/** A size column is algorithm-independent when every algorithm's range overlaps within a few bytes. */
function spread(values: number[]) {
  return Math.max(...values) - Math.min(...values);
}

export function MigrationStudySection({ study }: { study: StudyFile }) {
  const { algorithms } = study;
  const nameOf = new Map(algorithms.map((entry) => [entry.algorithm, entry.displayName]));
  const columns = [
    { label: "Certificate (DER)", value: (entry: StudyFile["algorithms"][number]) => entry.sizes.certificateDerBytes },
    { label: "Signature", value: (entry: StudyFile["algorithms"][number]) => entry.sizes.signatureBytes.median },
    { label: "CMS SignedData", value: (entry: StudyFile["algorithms"][number]) => entry.sizes.cmsSignedDataBytes.median },
    { label: "Public key (SPKI)", value: (entry: StudyFile["algorithms"][number]) => entry.sizes.publicKeySpkiBytes },
  ];

  const invariant = [
    { label: "RFC 3161 time-stamp token", values: algorithms.map((entry) => entry.sizes.timestampTokenBytes.median), range: `${Math.min(...algorithms.map((entry) => entry.sizes.timestampTokenBytes.min))}–${Math.max(...algorithms.map((entry) => entry.sizes.timestampTokenBytes.max))} bytes` },
    { label: "CRL growth per revoked certificate", values: algorithms.map((entry) => entry.sizes.crlGrowthPerRevokedCertificateBytes), range: `${Math.min(...algorithms.map((entry) => entry.sizes.crlGrowthPerRevokedCertificateBytes))}–${Math.max(...algorithms.map((entry) => entry.sizes.crlGrowthPerRevokedCertificateBytes))} bytes` },
    { label: "Anchoring commitment", values: algorithms.map((entry) => entry.sizes.anchoringCommitmentBytes), range: `${Math.min(...algorithms.map((entry) => entry.sizes.anchoringCommitmentBytes))}–${Math.max(...algorithms.map((entry) => entry.sizes.anchoringCommitmentBytes))} bytes` },
  ];

  return (
    <section aria-labelledby="migration-study-heading" className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3 border-t pt-8">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-hybrid">Post-quantum migration study</p>
          <h2 id="migration-study-heading" className="mt-1 text-xl font-semibold tracking-tight">
            What changes across the trust chain when signatures go post-quantum
          </h2>
          <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-muted-foreground">
            Measured by <code className="font-mono text-xs">npm run study:migration</code> through the application&apos;s own services in a throwaway installation, on{" "}
            {new Date(study.generatedAt).toLocaleString()} ({(study.durationMs / 1000).toFixed(1)} s). n = {study.parameters.iterations} end-to-end and n ={" "}
            {study.parameters.microIterations} primitive operations per algorithm
            {study.design ? `, in interleaved rounds with seed ${study.design.seed}` : ""}.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge variant={study.isolation.developmentDatabaseUnchanged ? "success" : "destructive"}>
            development database {study.isolation.developmentDatabaseUnchanged ? "unchanged" : "CHANGED"}
          </Badge>
          {!study.design && <Badge variant="warning">block design: order effects not controlled</Badge>}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Artefact sizes along the trust chain</CardTitle>
          <CardDescription>Bytes, with each value&apos;s multiple of the smallest algorithm in the same column. Medians where sizes vary between signatures.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Algorithm</TableHead>
                {columns.map((column) => (
                  <TableHead key={column.label}>{column.label}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {algorithms.map((entry) => (
                <TableRow key={entry.algorithm}>
                  <TableCell>
                    <div className="font-medium">{entry.displayName}</div>
                    <div className="mt-1">
                      <SecurityClassBadge securityClass={entry.securityClass} />
                    </div>
                  </TableCell>
                  {columns.map((column) => {
                    const values = algorithms.map(column.value);
                    return (
                      <TableCell key={column.label} className="font-mono text-xs tabular-nums">
                        {column.value(entry).toLocaleString()}
                        <Multiple value={column.value(entry)} smallest={Math.min(...values)} />
                        <SizeBar value={column.value(entry)} largest={Math.max(...values)} />
                      </TableCell>
                    );
                  })}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            {invariant.map((item) => (
              <div key={item.label} className="rounded-lg border bg-muted/30 p-3">
                <div className="text-xs text-muted-foreground">{item.label}</div>
                <div className="mt-1 font-mono text-sm tabular-nums">{item.range}</div>
                <div className="mt-1 text-[11px] text-muted-foreground">
                  {spread(item.values) <= 4 ? "Measured independent of the end-entity algorithm" : "Varies with the algorithm"}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 3xl:grid-cols-2">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>Workflow timings</CardTitle>
            <CardDescription>Median milliseconds, with the 95% confidence interval of the mean beneath.</CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Algorithm</TableHead>
                  {["certificateIssuance", "signDocument", "verifyDocument", "cmsVerify"].map((operation) => (
                    <TableHead key={operation}>{OPERATION_LABELS[operation]}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {algorithms.map((entry) => (
                  <TableRow key={entry.algorithm}>
                    <TableCell className="font-medium">{entry.displayName}</TableCell>
                    {["certificateIssuance", "signDocument", "verifyDocument", "cmsVerify"].map((operation) => {
                      const stats = entry.timings[operation];
                      return (
                        <TableCell key={operation} className="font-mono text-xs tabular-nums">
                          {stats.medianMs.toFixed(2)}
                          <span className="block text-[11px] text-muted-foreground">
                            {stats.ci95Ms ? `[${stats.ci95Ms[0].toFixed(1)}, ${stats.ci95Ms[1].toFixed(1)}]` : "n/a"}
                          </span>
                        </TableCell>
                      );
                    })}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>Which differences are real</CardTitle>
            <CardDescription>Pairs whose Mann-Whitney test stays below 0.05 after Holm&apos;s correction, and those with at least a medium effect (Cliff&apos;s δ).</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(study.comparisons)
              .filter(([operation]) => OPERATION_LABELS[operation])
              .map(([operation, rows]) => {
                const significant = rows.filter((row) => row.significantAt05);
                const notable = significant.filter((row) => row.magnitude === "medium" || row.magnitude === "large");
                return (
                  <div key={operation} className="rounded-lg border p-3">
                    <div className="flex items-center justify-between gap-3 text-sm">
                      <span className="font-medium">{OPERATION_LABELS[operation]}</span>
                      <Badge variant={significant.length === 0 ? "secondary" : "info"}>
                        {significant.length} of {rows.length} pairs differ
                      </Badge>
                    </div>
                    {notable.length > 0 && (
                      <ul className="mt-2 space-y-0.5 text-xs text-muted-foreground">
                        {notable.slice(0, 4).map((row) => (
                          <li key={`${row.a}-${row.b}`}>
                            {nameOf.get(row.a)} vs {nameOf.get(row.b)}: {row.ratioOfMedians.toFixed(2)}× the median, δ = {row.cliffsDelta.toFixed(2)} ({row.magnitude})
                          </li>
                        ))}
                        {notable.length > 4 && <li>and {notable.length - 4} more</li>}
                      </ul>
                    )}
                  </div>
                );
              })}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Cost of the crypto-agility layer</CardTitle>
          <CardDescription>
            Orchestrator against a direct call to the same provider, same key and digest, alternating which runs first. A shift of a few microseconds that is
            not significant means the abstraction costs nothing measurable here.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Algorithm</TableHead>
                <TableHead>Sign shift (ms)</TableHead>
                <TableHead>Sign effect</TableHead>
                <TableHead>Verify shift (ms)</TableHead>
                <TableHead>Verify effect</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {study.agilityOverhead.map((row) => (
                <TableRow key={row.algorithm}>
                  <TableCell className="font-medium">{nameOf.get(row.algorithm) ?? row.algorithm}</TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{row.sign.hodgesLehmann.toFixed(4)}</TableCell>
                  <TableCell>
                    <Badge variant={row.sign.significantAt05 ? "warning" : "secondary"}>
                      {row.sign.magnitude}
                      {row.sign.significantAt05 ? ", significant" : ", not significant"}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{row.verify.hodgesLehmann.toFixed(4)}</TableCell>
                  <TableCell>
                    <Badge variant={row.verify.significantAt05 ? "warning" : "secondary"}>
                      {row.verify.magnitude}
                      {row.verify.significantAt05 ? ", significant" : ", not significant"}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <ul className="mt-4 list-disc space-y-1 pl-5 text-xs text-muted-foreground">
            {study.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </section>
  );
}
