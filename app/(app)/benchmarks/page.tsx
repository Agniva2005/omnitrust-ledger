import fs from "node:fs";
import path from "node:path";
import { redirect } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getSession } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

type Stats = {
  iterations: number;
  meanMs: number;
  medianMs: number;
  p95Ms: number;
  minMs: number;
  maxMs: number;
};

type PayloadResult = {
  label: string;
  payloadBytes: number;
  hash: Stats;
  sign: Stats;
  verify: Stats;
  signatureBytes: number;
};

type BenchmarkFile = {
  generatedAt: string;
  environment: {
    node: string;
    platform: string;
    arch: string;
    cpu: string;
    cores: number;
    memoryGB: number;
  };
  parameters: {
    iterations: number;
    keyGenerationIterations: number;
    payloadSizes: number[];
    warmupIterations: number;
    timer: string;
  };
  notes: string[];
  algorithms: {
    algorithm: string;
    displayName: string;
    description: string;
    signatureBytes: number;
    publicKeyPemBytes: number;
    privateKeyPemBytes: number;
    certificateDerBytes: number | null;
    keyGeneration: Stats;
    payloads: PayloadResult[];
  }[];
};

function loadBenchmarks(): BenchmarkFile | null {
  const file = path.join(process.cwd(), "public", "benchmarks.json");
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8")) as BenchmarkFile;
}

function ms(value: number) {
  return `${value.toFixed(3)} ms`;
}

/** Bar width relative to the slowest value in the same column. */
function barWidth(value: number, max: number) {
  return `${Math.max(2, Math.round((value / max) * 100))}%`;
}

export default async function BenchmarksPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const data = loadBenchmarks();

  if (!data) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold tracking-tight">Benchmarks</h1>
        <Card>
          <CardHeader>
            <CardTitle>No measurements yet</CardTitle>
            <CardDescription>
              This page only ever renders numbers measured on the machine it is running on. Nothing
              ships with the repository.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Run <code className="rounded bg-muted px-1 py-0.5 text-xs">npm run benchmark</code>{" "}
              and reload this page.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const slowestSign = Math.max(
    ...data.algorithms.map((entry) => entry.payloads[0].sign.medianMs),
  );
  const slowestVerify = Math.max(
    ...data.algorithms.map((entry) => entry.payloads[0].verify.medianMs),
  );
  const largestSignature = Math.max(...data.algorithms.map((entry) => entry.signatureBytes));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Benchmarks</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Measured by <code className="text-xs">npm run benchmark</code> on{" "}
          {new Date(data.generatedAt).toLocaleString()} using {data.parameters.timer}.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>How to read this</CardTitle>
          <CardDescription>
            {data.parameters.iterations} timed sign and verify operations per algorithm per payload
            size, after {data.parameters.warmupIterations} untimed warm-up iterations;{" "}
            {data.parameters.keyGenerationIterations} key generations each.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          {data.notes.map((note) => (
            <p key={note} className={note.startsWith("IMPORTANT") ? "text-foreground" : undefined}>
              {note}
            </p>
          ))}
          <p className="pt-2 text-xs">
            Environment: {data.environment.cpu} ({data.environment.cores} cores,{" "}
            {data.environment.memoryGB} GB), {data.environment.platform} {data.environment.arch},
            Node {data.environment.node}.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sizes</CardTitle>
          <CardDescription>
            Properties of the algorithms themselves, unaffected by which library implements them.
          </CardDescription>
        </CardHeader>
        <CardContent>
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
                        <span
                          className="block h-2 rounded bg-primary"
                          style={{ width: barWidth(entry.signatureBytes, largestSignature) }}
                        />
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {entry.publicKeyPemBytes} bytes
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {entry.privateKeyPemBytes} bytes
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {entry.certificateDerBytes === null
                      ? "not issued yet"
                      : `${entry.certificateDerBytes} bytes`}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Timings</CardTitle>
          <CardDescription>
            Median with mean and p95, in milliseconds per operation. Bars are relative to the
            slowest algorithm in that column.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-8">
          {data.algorithms[0].payloads.map((_, payloadIndex) => (
            <div key={payloadIndex} className="space-y-3">
              <h3 className="text-sm font-medium">
                Payload: {data.algorithms[0].payloads[payloadIndex].label} (
                {data.algorithms[0].payloads[payloadIndex].payloadBytes.toLocaleString()} bytes)
              </h3>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Algorithm</TableHead>
                    <TableHead>SHA-256 of payload</TableHead>
                    <TableHead>Sign (median)</TableHead>
                    <TableHead>Verify (median)</TableHead>
                    <TableHead>Sign p95</TableHead>
                    <TableHead>Verify p95</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.algorithms.map((entry) => {
                    const payload = entry.payloads[payloadIndex];
                    return (
                      <TableRow key={entry.algorithm}>
                        <TableCell className="font-medium">{entry.displayName}</TableCell>
                        <TableCell className="text-muted-foreground">
                          {ms(payload.hash.medianMs)}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className="w-20">{ms(payload.sign.medianMs)}</span>
                            <span className="h-2 w-24 rounded bg-muted">
                              <span
                                className="block h-2 rounded bg-primary"
                                style={{ width: barWidth(payload.sign.medianMs, slowestSign) }}
                              />
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className="w-20">{ms(payload.verify.medianMs)}</span>
                            <span className="h-2 w-24 rounded bg-muted">
                              <span
                                className="block h-2 rounded bg-primary"
                                style={{ width: barWidth(payload.verify.medianMs, slowestVerify) }}
                              />
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {ms(payload.sign.p95Ms)}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {ms(payload.verify.p95Ms)}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Key generation</CardTitle>
          <CardDescription>
            {data.parameters.keyGenerationIterations} generations per algorithm. RSA is expected to
            dominate here: it searches for large primes.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Algorithm</TableHead>
                <TableHead>Median</TableHead>
                <TableHead>Mean</TableHead>
                <TableHead>Min</TableHead>
                <TableHead>Max</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.algorithms.map((entry) => (
                <TableRow key={entry.algorithm}>
                  <TableCell className="font-medium">{entry.displayName}</TableCell>
                  <TableCell>{ms(entry.keyGeneration.medianMs)}</TableCell>
                  <TableCell className="text-muted-foreground">
                    {ms(entry.keyGeneration.meanMs)}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {ms(entry.keyGeneration.minMs)}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {ms(entry.keyGeneration.maxMs)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
