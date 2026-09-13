// PKI layer: detached CMS SignedData signatures over documents (RFC 5652 section 5), the
// format external tools such as `openssl cms -verify` understand.
//
// The signature covers DER-encoded signed attributes: content-type id-data, signing-time,
// a message-digest of the document bytes under the algorithm's CMS digest (SHA-256 for
// RSA-PSS and ECDSA; SHA-512 for Ed25519 per RFC 8419 and ML-DSA per RFC 9882), and ESS
// signingCertificateV2 (RFC 5035). The SignerInfo's signature value is itself time-stamped
// and the token carried as the id-aa-signatureTimeStampToken unsigned attribute (RFC 3161
// Appendix A). This is structurally what CAdES calls a signature with a time-stamp, but no
// claim of CAdES profile conformance is made.
//
// ASN.1 only: every digest and signature goes through the Cryptographic Orchestration layer,
// and each algorithm's CMS identifiers come from its provider metadata.
import {
  CMSVersion,
  CertificateChoices,
  CertificateSet,
  ContentInfo,
  DigestAlgorithmIdentifiers,
  EncapsulatedContentInfo,
  SignedData,
  SignerInfo,
  SignerInfos,
  SigningTime,
  id_contentType,
  id_messageDigest,
  id_signedData,
  id_signingTime,
} from "@peculiar/asn1-cms";
import { id_aa_signingCertificateV2 } from "@peculiar/asn1-ess";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import * as x509 from "@peculiar/x509";
import { digestByOid, sha256 } from "@/lib/crypto/hash";
import { configureCertificateProvider, spkiDerToPem } from "@/lib/crypto/keys";
import { orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";
import { caCertificate, getRootCa } from "@/lib/pki/ca";
import {
  attribute,
  cmsAlgorithms,
  decodeObjectIdentifier,
  decodeOctetString,
  encodeObjectIdentifier,
  encodeOctetString,
  encodeSignedAttributes,
  encodeSigningCertificateV2,
  encodeSigningTime,
  issuerAndSerialFor,
  signerIdentifierMatches,
  signingCertificateV2Matches,
  singleAttributeValue,
  sortAttributes,
  toArrayBuffer,
} from "@/lib/pki/cms";
import { verifyTimestampToken, type TimestampVerification } from "@/lib/pki/tsa";

/** id-data (RFC 5652 section 4): the content is an arbitrary octet string, here the document. */
export const ID_DATA = "1.2.840.113549.1.7.1";
/** id-aa-signatureTimeStampToken (RFC 3161 Appendix A). */
export const ID_AA_SIGNATURE_TIME_STAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";

export type DetachedSignatureInput = {
  algorithm: Algorithm;
  /** The exact document bytes; they are not embedded, only their digest is signed. */
  content: Uint8Array;
  certificatePem: string;
  /** Included so a verifier holding only the trust anchor can build the chain. */
  issuerCertificatePem?: string;
  privateKeyPem: string;
  signingTime?: Date;
  /** Obtains a time-stamp token over the signature value; returning null omits the attribute. */
  timestamp?: (signatureValue: Buffer) => Promise<Buffer | null>;
};

export type DetachedSignature = {
  der: Buffer;
  signatureValue: Buffer;
  signingTime: Date;
  timestamped: boolean;
};

function sortedByEncoding(certificates: Uint8Array[]): Uint8Array[] {
  // DER encodes a SET OF in ascending order of the elements' encodings (X.690 section 11.6).
  return [...certificates].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

export async function createDetachedSignature(input: DetachedSignatureInput): Promise<DetachedSignature> {
  const certificateDer = pemBody(input.certificatePem);
  const { digestAlgorithm, signatureAlgorithm } = cmsAlgorithms(input.algorithm);
  const signingTime = new Date(Math.floor((input.signingTime ?? new Date()).getTime() / 1000) * 1000);

  const signedAttrs = sortAttributes([
    attribute(id_contentType, encodeObjectIdentifier(ID_DATA)),
    attribute(id_signingTime, encodeSigningTime(signingTime)),
    attribute(id_messageDigest, encodeOctetString(digestByOid(digestAlgorithm.algorithm, input.content))),
    attribute(id_aa_signingCertificateV2, encodeSigningCertificateV2(certificateDer)),
  ]);

  const signatureValue = await orchestrator.sign({
    algorithm: input.algorithm,
    message: encodeSignedAttributes(signedAttrs),
    privateKeyPem: input.privateKeyPem,
  });

  const token = input.timestamp ? await input.timestamp(signatureValue) : null;

  const certificates = sortedByEncoding([
    certificateDer,
    ...(input.issuerCertificatePem ? [pemBody(input.issuerCertificatePem)] : []),
  ]);

  const signedData = new SignedData({
    // v1: issuerAndSerialNumber signer, id-data content, no attribute certificates (RFC 5652 5.1).
    version: CMSVersion.v1,
    digestAlgorithms: new DigestAlgorithmIdentifiers([digestAlgorithm]),
    // Detached: eContent is absent and the verifier supplies the document.
    encapContentInfo: new EncapsulatedContentInfo({ eContentType: ID_DATA }),
    certificates: new CertificateSet(
      certificates.map((der) => new CertificateChoices({ certificate: AsnConvert.parse(der, Certificate) })),
    ),
    signerInfos: new SignerInfos([
      new SignerInfo({
        version: CMSVersion.v1,
        sid: issuerAndSerialFor(certificateDer),
        digestAlgorithm,
        signedAttrs,
        signatureAlgorithm,
        signature: new OctetString(signatureValue),
        unsignedAttrs: token
          ? [attribute(ID_AA_SIGNATURE_TIME_STAMP_TOKEN, toArrayBuffer(token))]
          : undefined,
      }),
    ]),
  });

  const der = Buffer.from(
    AsnConvert.serialize(
      new ContentInfo({ contentType: id_signedData, content: AsnConvert.serialize(signedData) }),
    ),
  );

  return { der, signatureValue, signingTime, timestamped: token !== null };
}

export type CmsCheck = { step: string; passed: boolean; detail?: string };

export type CmsVerification = {
  /** VALID: the document is exactly what the named certificate's key signed. INVALID: evidence against. UNAVAILABLE: undecidable here. */
  status: "VALID" | "INVALID" | "UNAVAILABLE";
  algorithm: Algorithm | null;
  signerSubject: string | null;
  signerSerial: string | null;
  signingTime: Date | null;
  /** The embedded signature time-stamp's verification, or null when there is none. */
  timestamp: TimestampVerification | null;
  explanation: string;
  checks: CmsCheck[];
};

const message = (error: unknown) => (error instanceof Error ? error.message : String(error));

/**
 * Verifies a detached CMS signature against document bytes: structure, the signer's
 * certificate (carried in the SignedData and chaining to the local CA), the algorithm
 * identifiers the key's provider declares, the signed attributes, the signature, and any
 * signature time-stamp. Certificate revocation and validity over time are the document
 * verification workflow's concern and are not repeated here.
 */
export async function verifyDetachedSignature(der: Uint8Array, content: Uint8Array): Promise<CmsVerification> {
  const checks: CmsCheck[] = [];
  const result = {
    algorithm: null as Algorithm | null,
    signerSubject: null as string | null,
    signerSerial: null as string | null,
    signingTime: null as Date | null,
    timestamp: null as TimestampVerification | null,
  };
  const check = (step: string, passed: boolean, detail?: string) => {
    checks.push({ step, passed, detail });
    return passed;
  };
  const conclude = (status: CmsVerification["status"], explanation: string): CmsVerification => ({
    status,
    ...result,
    explanation,
    checks,
  });

  // --- Structure ---
  let signedData: SignedData;
  let signerInfo: SignerInfo;
  try {
    const contentInfo = AsnConvert.parse(der, ContentInfo);
    if (contentInfo.contentType !== id_signedData) throw new Error("content is not SignedData");
    signedData = AsnConvert.parse(contentInfo.content, SignedData);
    if (signedData.encapContentInfo.eContentType !== ID_DATA) throw new Error("content type is not id-data");
    if (signedData.encapContentInfo.eContent) throw new Error("the content is embedded; expected a detached signature");
    if (signedData.signerInfos.length !== 1) throw new Error("expected exactly one signer");
    signerInfo = signedData.signerInfos[0];
  } catch (error) {
    check("Parses as a detached CMS SignedData over id-data", false, message(error));
    return conclude("INVALID", "The file is not a well-formed detached CMS signature.");
  }
  check("Parses as a detached CMS SignedData over id-data", true);

  // --- The signer's certificate, carried in the SignedData ---
  const carried = (signedData.certificates ?? [])
    .map((choice) => choice.certificate)
    .filter((certificate): certificate is Certificate => Boolean(certificate))
    .map((certificate) => new Uint8Array(AsnConvert.serialize(certificate)));
  const certificateDer = carried.find((candidate) => signerIdentifierMatches(signerInfo.sid, candidate));
  if (!check("Signer's certificate is included and matches the signer identifier", Boolean(certificateDer))) {
    return conclude("INVALID", "The signature does not include the certificate of its signer.");
  }

  configureCertificateProvider();
  const certificate = new x509.X509Certificate(certificateDer!);
  result.signerSubject = certificate.subject;
  result.signerSerial = certificate.serialNumber.toUpperCase();
  const publicKeyPem = spkiDerToPem(certificate.publicKey.rawData);

  const algorithm = orchestrator.identifyPublicKey(publicKeyPem);
  if (!check("Signer's key belongs to a registered algorithm", algorithm !== null)) {
    return conclude("UNAVAILABLE", "The signer's key uses an algorithm this installation has no provider for.");
  }
  result.algorithm = algorithm;
  const expected = orchestrator.describe(algorithm!).cms;

  // --- Algorithm identifiers must be exactly those the provider declares ---
  const parameters = signerInfo.signatureAlgorithm.parameters;
  const actualParameters = parameters ? Buffer.from(parameters).toString("hex") : null;
  const identifiersMatch =
    signerInfo.digestAlgorithm.algorithm === expected.digestAlgorithmOid &&
    signerInfo.signatureAlgorithm.algorithm === expected.signatureAlgorithmOid &&
    actualParameters === expected.signatureParametersDer &&
    signedData.digestAlgorithms.some((candidate) => candidate.algorithm === expected.digestAlgorithmOid);
  if (
    !check(
      `Algorithm identifiers match ${orchestrator.displayName(algorithm!)} in CMS (${expected.standard})`,
      identifiersMatch,
      identifiersMatch
        ? undefined
        : `digest ${signerInfo.digestAlgorithm.algorithm}, signature ${signerInfo.signatureAlgorithm.algorithm}`,
    )
  ) {
    return conclude("INVALID", "The signature's algorithm identifiers do not match the signer's key.");
  }

  // --- Signed attributes ---
  try {
    const contentType = decodeObjectIdentifier(singleAttributeValue(signerInfo.signedAttrs, id_contentType));
    const messageDigest = decodeOctetString(singleAttributeValue(signerInfo.signedAttrs, id_messageDigest));
    const signingTimes = (signerInfo.signedAttrs ?? []).filter((candidate) => candidate.attrType === id_signingTime);
    if (signingTimes.length === 1) {
      result.signingTime = AsnConvert.parse(signingTimes[0].attrValues[0], SigningTime).getTime();
    }
    const signingCertificates = (signerInfo.signedAttrs ?? []).filter(
      (candidate) => candidate.attrType === id_aa_signingCertificateV2,
    );

    if (!check("Content-type attribute is id-data", contentType === ID_DATA)) {
      return conclude("INVALID", "The signed content-type does not match the content.");
    }
    const digestMatches = messageDigest.equals(digestByOid(expected.digestAlgorithmOid, content));
    if (!check("Message-digest attribute matches the document bytes", digestMatches)) {
      return conclude("INVALID", "The document differs from the document that was signed.");
    }
    if (signingCertificates.length > 0) {
      const named = signingCertificateV2Matches(singleAttributeValue(signerInfo.signedAttrs, id_aa_signingCertificateV2), certificateDer!);
      if (!check("signingCertificateV2 names the signer's certificate", named)) {
        return conclude("INVALID", "The signed attributes name a different signing certificate.");
      }
    }
  } catch (error) {
    check("Signed attributes are well formed", false, message(error));
    return conclude("INVALID", "The signature's signed attributes are malformed.");
  }

  // --- Signature ---
  let signatureValid = false;
  try {
    signatureValid = await orchestrator.verify({
      algorithm: algorithm!,
      message: encodeSignedAttributes(signerInfo.signedAttrs ?? []),
      signature: new Uint8Array(signerInfo.signature.buffer),
      publicKeyPem,
    });
  } catch {
    signatureValid = false;
  }
  if (!check("Signature over the signed attributes verifies under the signer's key", signatureValid)) {
    return conclude("INVALID", "The signature does not verify.");
  }

  // --- The certificate chains to this installation's CA and permits signing ---
  const root = caCertificate(await getRootCa());
  let chainValid = false;
  try {
    chainValid =
      certificate.issuer === root.subject &&
      (await certificate.verify({ publicKey: root.publicKey, signatureOnly: true }));
  } catch {
    chainValid = false;
  }
  const keyUsage = certificate.getExtension(x509.KeyUsagesExtension);
  const permitsSigning = keyUsage !== null && (keyUsage.usages & x509.KeyUsageFlags.digitalSignature) !== 0;
  if (
    !check("Signer's certificate chains to the local CA", chainValid, certificate.issuer) ||
    !check("Signer's certificate permits digital signatures", permitsSigning)
  ) {
    return conclude("INVALID", "The signer's certificate was not issued by this installation's CA for signing.");
  }

  // --- The signature time-stamp, if present ---
  const tokens = (signerInfo.unsignedAttrs ?? []).filter(
    (candidate) => candidate.attrType === ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
  );
  if (tokens.length > 0) {
    const token = new Uint8Array(tokens[0].attrValues[0]);
    result.timestamp = await verifyTimestampToken(token, sha256(new Uint8Array(signerInfo.signature.buffer)));
    const status = result.timestamp.status;
    check("Signature time-stamp token", status === "VALID", result.timestamp.explanation);
    if (status === "INVALID") {
      return conclude("INVALID", `The embedded signature time-stamp is invalid: ${result.timestamp.explanation}`);
    }
  }

  const time = result.timestamp?.status === "VALID" && result.timestamp.genTime
    ? ` A trusted time-stamp shows the signature existed by ${result.timestamp.genTime.toISOString()}.`
    : "";
  return conclude(
    "VALID",
    `The document is exactly what ${certificate.subject} signed with ${orchestrator.displayName(algorithm!)}.${time}`,
  );
}
