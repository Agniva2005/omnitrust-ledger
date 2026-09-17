// The instants at which a signature's verdict can change.
//
// Time-aware revocation is the hardest of this system's claims to explain and the easiest to
// show: the same bytes, the same signature, the same certificate, judged at different moments,
// give different answers — and which answer depends on the revocation's stated reason. These
// are the moments worth asking about, taken from the record itself. Nothing here predicts a
// verdict; the verifier is run for real at each instant.
//
// Asking about any instant other than the present is read-only: see the `issueIfStale` note in
// lib/pki/crl.ts for why a hypothetical question must never publish a revocation list.
import { NotFoundError } from "@/lib/api";
import { prisma } from "@/lib/db";

export type VerificationMoment = {
  id: string;
  label: string;
  at: string;
  detail: string;
};

const SECOND = 1000;

export async function verificationMoments(documentId: string, versionNumber?: number): Promise<VerificationMoment[]> {
  const version = await prisma.documentVersion.findFirst({
    where: { documentId, ...(versionNumber === undefined ? {} : { versionNumber }) },
    orderBy: { versionNumber: "desc" },
    include: { signatures: { include: { certificate: true } } },
  });
  if (!version) throw new NotFoundError("Document version not found");

  const signature = version.signatures[0];
  if (!signature) return [];
  const certificate = signature.certificate;

  const moments: VerificationMoment[] = [];
  const add = (id: string, label: string, at: Date, detail: string) => {
    moments.push({ id, label, at: at.toISOString(), detail });
  };

  const signedAt = signature.timestampedAt ?? signature.signedAt;
  add(
    "signed",
    "When it was signed",
    signedAt,
    signature.timestampedAt
      ? "The moment a trusted RFC 3161 token proves this signature already existed."
      : "The server's own clock when it signed. No trusted time-stamp covers this signature.",
  );

  if (certificate.invalidityDate) {
    add(
      "at-compromise",
      "The stated compromise time",
      certificate.invalidityDate,
      "From when the revocation says the key could no longer be trusted. A signature made before this is unaffected.",
    );
  }

  if (certificate.revokedAt) {
    // A second either side, so the change of answer sits on a boundary you can point at.
    add("before-revocation", "A second before revocation", new Date(certificate.revokedAt.getTime() - SECOND), "The certificate was still listed as good.");
    add(
      "after-revocation",
      `A second after revocation${certificate.revocationReason ? ` (${certificate.revocationReason})` : ""}`,
      new Date(certificate.revokedAt.getTime() + SECOND),
      "The CA has published the revocation. Whether that changes the verdict depends on the reason it gives.",
    );
  }

  add("now", "Now", new Date(), "The default: what the verifier answers today.");

  // Beyond the newest published list the honest answer is that revocation status is unknown,
  // which is worth showing rather than hiding: the verifier does not guess.
  const newestCrl = await prisma.revocationList.findFirst({ orderBy: { crlNumber: "desc" } });
  if (newestCrl) {
    add(
      "beyond-crl",
      "After the newest CRL lapses",
      new Date(newestCrl.nextUpdate.getTime() + SECOND),
      "No published revocation list covers this instant, so revocation status is genuinely unknown.",
    );
  }

  const seen = new Set<string>();
  return moments
    .sort((left, right) => left.at.localeCompare(right.at))
    .filter((moment) => {
      if (seen.has(moment.at)) return false;
      seen.add(moment.at);
      return true;
    });
}
