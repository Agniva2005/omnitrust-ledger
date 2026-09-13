import fs from "node:fs";
import path from "node:path";
import { Gauge } from "lucide-react";
import { redirect } from "next/navigation";
import { MigrationStudySection, loadMigrationStudy } from "@/app/(app)/benchmarks/migration-study";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getSession } from "@/lib/auth/session";
import type { SampleSummary } from "@/lib/benchmarks/statistics";

export const dynamic = "force-dynamic";

type PayloadResult = {
  label: string;
  payloadBytes: number;
  hash: SampleSummary;
  sign: SampleSummary;
  verify: SampleSummary;
  signatureBytes: number;
};

type BenchmarkFile = {
  schemaVersion?: number;
  smoke?: boolean;
  generatedAt: string;
  durationMs?: number;
  environment: {
    node: string;
    v8?: string;
    openssl?: string;
    platform: string;
    arch: string;
    cpu: string;
    cpuSpeedMHz?: number | null;
    cores: number;
    memoryGB: number;
    freeMemoryGBAtStart?: number;
    gitCommit?: string | null;
    gitTreeDirty?: boolean | null;
  };
  parameters: { iterations: number; keyGenerationIterations: number; warmupIterations: number; payloadSizes: number[]; timer: string };
  methodology?: string[];
  notes: string[];
  algorithms: {
    algorithm: string;
    displayName: string;
    signatureBytes: number;
    publicKeyPemBytes: number;
    privateKeyPemBytes: number;
    certificateDerBytes: number | null;
    keyGeneration: SampleSummary;
    payloads: PayloadResult[];
  }[];
};

function loadBenchmarks(): BenchmarkFile | null {
  const file = path.join(process.cwd(), "public", "benchmarks.json");
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8")) as BenchmarkFile;
}

const ms = (value: number) => `${value.toFixed(3)}`;

function StatsCells({ stats, slowestMedian }: { stats: SampleSummary; slowestMedian: number }) {
  return (
    <>
      <TableCell>
        <div className="flex items-center gap-2">
          <span className="w-16 font-mono text-xs">{ms(stats.medianMs)}</span>
          <span className="h-2 w-16 rounded bg-muted">
            <span className="block h-2 rounded bg-primary" style={{ width: `${Math.max(2, Math.round((stats.medianMs / slowestMedian) * 100))}%` }} />
          </span>
        </div>
      </TableCell>
      <TableCell className="font-mono text-xs">
        {ms(stats.meanMs)}
        <span className="block text-muted-foreground">
          {stats.ci95Ms ? `[${ms(stats.ci95Ms[0])}, ${ms(stats.ci95Ms[1])}]` : "CI n/a"}
        </span>
      </TableCell>
      <TableCell className="font-mono text-xs text-muted-foreground">
        {stats.stdDevMs !== undefined ? ms(stats.stdDevMs) : "-"}
        <span className="block">CV {stats.coefficientOfVariation !== undefined ? `${(stats.coefficientOfVariation * 100).toFixed(0)}%` : "-"}</span>
      </TableCell>
      <TableCell className="font-mono text-xs text-muted-foreground">
        {ms(stats.minMs)} / {ms(stats.p95Ms)} / {ms(stats.maxMs)}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{stats.outliers ?? "-"}</TableCell>
    </>
  );
}

const STAT_HEADERS = ["Median (ms)", "Mean, 95% CI", "SD, CV", "Min / p95 / max", "Outliers"];

export default async function BenchmarksPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const data = loadBenchmarks();
  const study = loadMigrationStudy();

  if (!data) {
    return (
      <div className="space-y-6">
        <PageHeader icon={Gauge} title="Benchmarks" description="Only numbers measured on the machine this page runs on; nothing ships with the repository." />
        <Card>
          <CardHeader>
            <CardTitle>No measurements yet</CardTitle>
            <CardDescription>
              This page only ever renders numbers measured on the machine it is running on. Nothing ships with the repository.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Run <code className="rounded bg-muted px-1 py-0.5 text-xs">npm run benchmark</code> and reload this page.
            </p>
          </CardContent>
        </Card>
        {study && <MigrationStudySection study={study} />}
      </div>
    );
  }

  const legacy = data.schemaVersion === undefined;
  const slowest = (pick: (entry: BenchmarkFile["algorithms"][number]) => number) => Math.max(...data.algorithms.map(pick));
  const largestSignature = slowest((entry) => entry.signatureBytes);
  const env = data.environment;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Gauge}
        eyebrow="Evaluation"
        title="Benchmarks"
        description={
          <>
            Measured by <code className="font-mono text-xs">npm run benchmark</code> on {new Date(data.generatedAt).toLocaleString()}
            {data.durationMs ? `, taking ${(data.durationMs / 1000).toFixed(1)} s` : ""}.
          </>
        }
      />

      {(legacy || data.smoke) && (
        <Card className="border-amber-500/50">
          <CardHeader>
            <CardTitle className="text-base">{data.smoke ? "Smoke run" : "Measured with an earlier benchmark version"}</CardTitle>
            <CardDescription>
              {data.smoke
                ? "The sample sizes are too small for comparison. Run npm run benchmark for real measurements."
                : "This file predates standard deviations, confidence intervals and outlier counts, so those columns are empty. Re-run npm run benchmark."}
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Method and environment</CardTitle>
          <CardDescription>
            n = {data.parameters.iterations} timed operations per sign, verify and hash measurement, after {data.parameters.warmupIterations}{" "}
            untimed warm-up iterations; n = {data.parameters.keyGenerationIterations} key generations per algorithm; timer{" "}
            {data.parameters.timer}.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
            <div>
              <dt className="inline text-muted-foreground">CPU: </dt>
              <dd className="inline">
                {env.cpu} ({env.cores} logical cores{env.cpuSpeedMHz ? `, ${env.cpuSpeedMHz} MHz` : ""})
              </dd>
            </div>
            <div>
              <dt className="inline text-muted-foreground">Memory: </dt>
              <dd className="inline">
                {env.memoryGB} GB{env.freeMemoryGBAtStart !== undefined ? `, ${env.freeMemoryGBAtStart} GB free at start` : ""}
              </dd>
            </div>
            <div>
              <dt className="inline text-muted-foreground">OS: </dt>
              <dd className="inline">
                {env.platform} {env.arch}
              </dd>
            </div>
            <div>
              <dt className="inline text-muted-foreground">Runtime: </dt>
              <dd className="inline">
                Node {env.node}
                {env.v8 ? `, V8 ${env.v8}` : ""}
                {env.openssl ? `, OpenSSL ${env.openssl}` : ""}
              </dd>
            </div>
            {env.gitCommit !== undefined && (
              <div>
                <dt className="inline text-muted-foreground">Code: </dt>
                <dd className="inline font-mono">
                  {env.gitCommit ?? "unknown"}
                  {env.gitTreeDirty ? " (uncommitted changes present)" : ""}
                </dd>
              </div>
            )}
          </dl>
          {data.methodology && (
            <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
              {data.methodology.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          )}
          {data.notes.map((note) => (
            <p key={note} className={note.startsWith("IMPORTANT") ? "text-foreground" : "text-muted-foreground"}>
              {note}
            </p>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sizes</CardTitle>
          <CardDescription>Properties of the algorithms and encodings, unaffected by which library implements them.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Algorithm</TableHead>
                <TableHead>Signature</TableHead>
                <TableHead>Public key (PEM)</TableHead>
                <TableHead>Private key (PEM)</TableHead>
                <TableHead>Certificate (DER)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.algorithms.map((entry) => (
                <TableRow key={entry.algorithm}>
                  <TableCell className="font-medium">{entry.displayName}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <span className="w-20">{entry.signatureBytes} bytes</span>
                      <span className="h-2 flex-1 rounded bg-muted">
                        <span className="block h-2 rounded bg-primary" style={{ width: `${Math.max(2, Math.round((entry.signatureBytes / largestSignature) * 100))}%` }} />
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{entry.publicKeyPemBytes} bytes</TableCell>
                  <TableCell className="text-muted-foreground">{entry.privateKeyPemBytes} bytes</TableCell>
                  <TableCell className="text-muted-foreground">
                    {entry.certificateDerBytes === null ? "none issued" : `${entry.certificateDerBytes} bytes`}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {(["sign", "verify"] as const).map((operation) => (
        <Card key={operation}>
          <CardHeader>
            <CardTitle>{operation === "sign" ? "Signing" : "Verification"}</CardTitle>
            <CardDescription>
              Milliseconds per operation over the 32-byte digest. Bars compare medians with the slowest algorithm.
            </CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Algorithm</TableHead>
                  <TableHead>n</TableHead>
                  {STAT_HEADERS.map((header) => (
                    <TableHead key={header}>{header}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.algorithms.map((entry) => {
                  const stats = entry.payloads[0][operation];
                  return (
                    <TableRow key={entry.algorithm}>
                      <TableCell className="font-medium">{entry.displayName}</TableCell>
                      <TableCell className="text-xs">{stats.n ?? data.parameters.iterations}</TableCell>
                      <StatsCells stats={stats} slowestMedian={slowest((candidate) => candidate.payloads[0][operation].medianMs)} />
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ))}

      <Card>
        <CardHeader>
          <CardTitle>Hashing by document size</CardTitle>
          <CardDescription>SHA-256 of the payload: the only step whose cost grows with the document.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Payload</TableHead>
                <TableHead>n</TableHead>
                {STAT_HEADERS.map((header) => (
                  <TableHead key={header}>{header}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.algorithms[0].payloads.map((payload, index) => (
                <TableRow key={payload.label}>
                  <TableCell className="font-medium">
                    {payload.label} <Badge variant="outline">{payload.payloadBytes.toLocaleString()} bytes</Badge>
                  </TableCell>
                  <TableCell className="text-xs">{payload.hash.n ?? data.parameters.iterations}</TableCell>
                  <StatsCells stats={payload.hash} slowestMedian={Math.max(...data.algorithms[0].payloads.map((candidate) => candidate.hash.medianMs))} />
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <p className="mt-2 text-xs text-muted-foreground">Measured in the first algorithm&apos;s run; hashing does not depend on the signature algorithm.</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Key generation</CardTitle>
          <CardDescription>RSA is expected to dominate: it searches for large primes, so its spread is also wide.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Algorithm</TableHead>
                <TableHead>n</TableHead>
                {STAT_HEADERS.map((header) => (
                  <TableHead key={header}>{header}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.algorithms.map((entry) => (
                <TableRow key={entry.algorithm}>
                  <TableCell className="font-medium">{entry.displayName}</TableCell>
                  <TableCell className="text-xs">{entry.keyGeneration.n ?? data.parameters.keyGenerationIterations}</TableCell>
                  <StatsCells stats={entry.keyGeneration} slowestMedian={slowest((candidate) => candidate.keyGeneration.medianMs)} />
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {study && <MigrationStudySection study={study} />}
    </div>
  );
}
