// PKI layer: the local RFC 3161 Time-Stamp Authority.
//
// Issues TimeStampTokens: CMS SignedData over a TSTInfo, signed by a key whose certificate
// the local CA issued with a critical id-kp-timeStamping extended key usage, and carrying
// the ESS signingCertificateV2 attribute RFC 3161 and RFC 5816 require. Tokens are
// verified here and are also accepted by `openssl ts -verify`. Demo-grade like the CA:
// trusted by nothing outside this installation, and its clock is the server clock.
import type { TimestampAuthority } from "@prisma/client";
import { randomBytes, randomUUID } from "node:crypto";
import {
  CMSVersion,
  CertificateChoices,
  CertificateSet,
  ContentInfo,
  DigestAlgorithmIdentifiers,
  EncapsulatedContent,
  EncapsulatedContentInfo,
  SignedData,
  SignerInfo,
  SignerInfos,
  id_contentType,
  id_messageDigest,
  id_signedData,
  id_signingTime,
} from "@peculiar/asn1-cms";
import { id_aa_signingCertificateV2 } from "@peculiar/asn1-ess";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
  Accuracy,
  MessageImprint,
  PKIFailureInfo,
  PKIFailureInfoFlags,
  PKIStatus,
  PKIStatusInfo,
  TSTInfo,
  TSTInfoVersion,
  TimeStampReq,
  TimeStampResp,
  TimeStampToken,
  id_ct_tstInfo,
} from "@peculiar/asn1-tsp";
import { AlgorithmIdentifier, Certificate } from "@peculiar/asn1-x509";
import * as x509 from "@peculiar/x509";
import { BadRequestError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { DIGEST_OIDS, digestByOid, digestLength, isSupportedDigestOid } from "@/lib/crypto/hash";
import { configureCertificateProvider, spkiDerToPem, subjectPublicKey } from "@/lib/crypto/keys";
import { assertAlgorithm, isAlgorithm, orchestrator } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";
import { decryptString, encryptString } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { caCertificate, caSigningAlgorithm, caSigningKey, getRootCa } from "@/lib/pki/ca";
import {
  CmsStructureError,
  attribute,
  cmsAlgorithms,
  decodeObjectIdentifier,
  decodeObjectIdentifierContent,
  decodeOctetString,
  encodeObjectIdentifier,
  encodeOctetString,
  encodeSignedAttributes,
  encodeSigningCertificateV2,
  encodeSigningTime,
  hexToArrayBuffer,
  issuerAndSerialFor,
  sequenceChildren,
  signerIdentifierMatches,
  signingCertificateV2Matches,
  singleAttributeValue,
  sortAttributes,
} from "@/lib/pki/cms";
import { RevocationStatusUnavailableError, revocationStatus } from "@/lib/pki/crl";
import { TSA_ALGORITHM } from "@/lib/pki/policy";
import { evaluateRevocation } from "@/lib/pki/revocation";

export const TSA_SUBJECT =
  "CN=OmniTrust Demo Time-Stamp Authority,O=OmniTrust Ledger,OU=Demo PKI - Not For Production Use";
export const ID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
/** The accuracy every token states: genTime is truncated to whole seconds. */
export const TSA_ACCURACY_MS = 1000;

const TSA_VALIDITY_MS = 5 * 365 * 86_400_000;
const DER_OBJECT_IDENTIFIER = 0x06;

export class TimestampUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimestampUnavailableError";
  }
}

/** A positive 16-byte serial whose first byte never needs a sign-padding zero. */
function randomPositiveSerial(): string {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] & 0x7f) | 0x01;
  return bytes.toString("hex").toUpperCase();
}

/** A policy OID under the ITU-T X.667 UUID arc, which needs no registration. */
function newPolicyOid(): string {
  return `2.25.${BigInt(`0x${randomUUID().replace(/-/g, "")}`).toString()}`;
}

/** TSTInfo ::= SEQUENCE { version INTEGER, policy TSAPolicyId, ... } */
function tstInfoPolicy(tstInfoDer: Uint8Array): string {
  const policy = sequenceChildren(tstInfoDer)[1];
  if (policy?.tag !== DER_OBJECT_IDENTIFIER) throw new CmsStructureError("TSTInfo has no policy");
  return decodeObjectIdentifierContent(policy.content);
}

/** TimeStampReq ::= SEQUENCE { version, messageImprint, reqPolicy TSAPolicyId OPTIONAL, ... } */
function requestedPolicy(requestDer: Uint8Array): string | null {
  const candidate = sequenceChildren(requestDer)[2];
  return candidate?.tag === DER_OBJECT_IDENTIFIER ? decodeObjectIdentifierContent(candidate.content) : null;
}

/** The active Time-Stamp Authority if one exists, without creating it. */
export async function activeTimestampAuthority(): Promise<TimestampAuthority | null> {
  return prisma.timestampAuthority.findFirst({ where: { status: "ACTIVE" }, orderBy: { createdAt: "desc" } });
}

/** The active Time-Stamp Authority, created with its certificate on first use. */
export async function ensureTimestampAuthority(): Promise<TimestampAuthority> {
  const existing = await prisma.timestampAuthority.findFirst({
    where: { status: "ACTIVE" },
    orderBy: { createdAt: "desc" },
  });
  if (existing) return existing;

  configureCertificateProvider();
  const ca = await getRootCa();
  const root = caCertificate(ca);
  const keys = await orchestrator.generateKeyPair(TSA_ALGORITHM);

  const notBefore = new Date();
  const notAfter = new Date(Math.min(notBefore.getTime() + TSA_VALIDITY_MS, root.notAfter.getTime()));
  const serialNumber = randomPositiveSerial();

  const certificate = await x509.X509CertificateGenerator.create({
    serialNumber,
    subject: TSA_SUBJECT,
    issuer: root.subject,
    notBefore,
    notAfter,
    signingKey: await caSigningKey(ca),
    publicKey: subjectPublicKey(keys.publicKeyPem),
    signingAlgorithm: caSigningAlgorithm(ca),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation,
        true,
      ),
      // RFC 3161 section 2.3: the only extended key usage, marked critical.
      new x509.ExtendedKeyUsageExtension([ID_KP_TIME_STAMPING], true),
    ],
  });

  const authority = await prisma.timestampAuthority.create({
    data: {
      issuerCaId: ca.id,
      name: TSA_SUBJECT,
      algorithm: TSA_ALGORITHM,
      policyOid: newPolicyOid(),
      serialNumber,
      certPem: certificate.toString("pem"),
      encryptedPrivateKey: encryptString(keys.privateKeyPem),
      expiresAt: notAfter,
      status: "ACTIVE",
    },
  });

  await appendAuditEntry({
    action: "TSA_CREATED",
    targetType: "TimestampAuthority",
    targetId: authority.id,
    metadata: { algorithm: authority.algorithm, serialNumber, policyOid: authority.policyOid },
  });
  return authority;
}

export type TimestampRequest = {
  /** The hash of the data being time-stamped. */
  imprint: Uint8Array;
  hashAlgorithmOid?: string;
  /** DER INTEGER contents, echoed unchanged into the token as RFC 3161 requires. */
  nonce?: ArrayBuffer;
  /** Include the TSA certificate in the token (RFC 3161 certReq). Defaults to true. */
  includeCertificate?: boolean;
};

export type IssuedTimestamp = {
  token: Buffer;
  genTime: Date;
  accuracyMs: number;
  serialNumber: string;
  policyOid: string;
  authorityId: string;
};

/**
 * Issues a token. `at` overrides the time only for tests that need a specific genTime; by default
 * the time is taken after the authority is known to exist. Taking it on entry (as this function
 * once did) let a first token on a fresh installation predate the authority certificate created
 * a moment later, whenever that creation crossed a second boundary, and such a token is correctly
 * refused by verification (tests/pki/tsa-clock.test.ts).
 */
export async function issueTimestampToken(
  request: TimestampRequest,
  at?: Date,
): Promise<IssuedTimestamp> {
  const hashAlgorithmOid = request.hashAlgorithmOid ?? DIGEST_OIDS.sha256;
  if (!isSupportedDigestOid(hashAlgorithmOid) || digestLength(hashAlgorithmOid) !== request.imprint.length) {
    throw new BadRequestError("The message imprint does not match a supported hash algorithm");
  }

  let authority: TimestampAuthority;
  try {
    authority = await ensureTimestampAuthority();
  } catch (error) {
    throw new TimestampUnavailableError(
      `the Time-Stamp Authority is unavailable (${error instanceof Error ? error.name : "unknown error"})`,
    );
  }

  const algorithm = assertAlgorithm(authority.algorithm);
  const certificateDer = pemBody(authority.certPem);
  const genTime = new Date(Math.floor((at ?? new Date()).getTime() / 1000) * 1000);
  const serialNumber = randomPositiveSerial();

  const tstInfoDer = AsnConvert.serialize(
    new TSTInfo({
      version: TSTInfoVersion.v1,
      policy: authority.policyOid,
      messageImprint: new MessageImprint({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: hashAlgorithmOid }),
        hashedMessage: new OctetString(request.imprint),
      }),
      serialNumber: hexToArrayBuffer(serialNumber),
      genTime,
      accuracy: new Accuracy({ seconds: TSA_ACCURACY_MS / 1000 }),
      nonce: request.nonce,
    }),
  );

  const { digestAlgorithm, signatureAlgorithm } = cmsAlgorithms(algorithm);
  const signedAttrs = sortAttributes([
    attribute(id_contentType, encodeObjectIdentifier(id_ct_tstInfo)),
    attribute(id_signingTime, encodeSigningTime(genTime)),
    attribute(
      id_messageDigest,
      encodeOctetString(digestByOid(digestAlgorithm.algorithm, new Uint8Array(tstInfoDer))),
    ),
    attribute(id_aa_signingCertificateV2, encodeSigningCertificateV2(certificateDer)),
  ]);

  const signature = await orchestrator.sign({
    algorithm,
    message: encodeSignedAttributes(signedAttrs),
    privateKeyPem: decryptString(authority.encryptedPrivateKey),
  });

  const signedData = new SignedData({
    version: CMSVersion.v3,
    digestAlgorithms: new DigestAlgorithmIdentifiers([digestAlgorithm]),
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: id_ct_tstInfo,
      eContent: new EncapsulatedContent({ single: new OctetString(tstInfoDer) }),
    }),
    certificates:
      request.includeCertificate === false
        ? undefined
        : new CertificateSet([
            new CertificateChoices({ certificate: AsnConvert.parse(certificateDer, Certificate) }),
          ]),
    signerInfos: new SignerInfos([
      new SignerInfo({
        version: CMSVersion.v1,
        sid: issuerAndSerialFor(certificateDer),
        digestAlgorithm,
        signedAttrs,
        signatureAlgorithm,
        signature: new OctetString(signature),
      }),
    ]),
  });

  const token = Buffer.from(
    AsnConvert.serialize(
      new ContentInfo({ contentType: id_signedData, content: AsnConvert.serialize(signedData) }),
    ),
  );

  return {
    token,
    genTime,
    accuracyMs: TSA_ACCURACY_MS,
    serialNumber,
    policyOid: authority.policyOid,
    authorityId: authority.id,
  };
}

export type TimestampCheck = { step: string; passed: boolean; detail?: string };

export type TimestampVerification = {
  /** VALID: trusted proof of existence. INVALID: evidence against it. UNAVAILABLE: undecidable. */
  status: "VALID" | "INVALID" | "UNAVAILABLE";
  genTime: Date | null;
  accuracyMs: number;
  serialNumber: string | null;
  policyOid: string | null;
  authority: string | null;
  explanation: string;
  checks: TimestampCheck[];
};

function accuracyToMs(accuracy: Accuracy | undefined): number {
  if (!accuracy) return 0;
  return (accuracy.seconds ?? 0) * 1000 + (accuracy.millis ?? 0) + Math.ceil((accuracy.micros ?? 0) / 1000);
}

/**
 * Verifies a TimeStampToken as proof that `expectedImprint` existed at its genTime. The
 * token is trusted only if this installation's TSA issued it, its certificate chains to the
 * local CA with the time-stamping usage, and the TSA certificate was not revoked in a way
 * that undermines the token under the revocation policy.
 */
export async function verifyTimestampToken(
  tokenDer: Uint8Array,
  expectedImprint: Uint8Array,
): Promise<TimestampVerification> {
  const checks: TimestampCheck[] = [];
  const result = {
    genTime: null as Date | null,
    accuracyMs: 0,
    serialNumber: null as string | null,
    policyOid: null as string | null,
    authority: null as string | null,
  };
  const check = (step: string, passed: boolean, detail?: string) => {
    checks.push({ step, passed, detail });
    return passed;
  };
  const conclude = (status: TimestampVerification["status"], explanation: string): TimestampVerification => ({
    status,
    ...result,
    explanation,
    checks,
  });

  // --- Structure ---
  let signedData: SignedData;
  let tstInfo: TSTInfo;
  let eContent: ArrayBuffer;
  let signerInfo: SignerInfo;
  try {
    const contentInfo = AsnConvert.parse(tokenDer, ContentInfo);
    if (contentInfo.contentType !== id_signedData) throw new Error("content is not SignedData");
    signedData = AsnConvert.parse(contentInfo.content, SignedData);
    if (signedData.encapContentInfo.eContentType !== id_ct_tstInfo) {
      throw new Error("encapsulated content is not a TSTInfo");
    }
    const single = signedData.encapContentInfo.eContent?.single;
    if (!single) throw new Error("the TSTInfo is missing");
    eContent = single.buffer;
    tstInfo = AsnConvert.parse(eContent, TSTInfo);
    result.policyOid = tstInfoPolicy(new Uint8Array(eContent));
    if (signedData.signerInfos.length !== 1) throw new Error("expected exactly one signer");
    signerInfo = signedData.signerInfos[0];
  } catch (error) {
    check("Token parses as an RFC 3161 TimeStampToken", false, error instanceof Error ? error.message : String(error));
    return conclude("INVALID", "The time-stamp token is malformed.");
  }

  result.genTime = tstInfo.genTime;
  result.accuracyMs = accuracyToMs(tstInfo.accuracy);
  result.serialNumber = Buffer.from(tstInfo.serialNumber).toString("hex").toUpperCase();
  check("Token parses as an RFC 3161 TimeStampToken", true, `genTime ${tstInfo.genTime.toISOString()}`);

  // --- Binding to the data it claims to time-stamp ---
  const imprintAlgorithm = tstInfo.messageImprint.hashAlgorithm.algorithm;
  const imprintMatches =
    isSupportedDigestOid(imprintAlgorithm) &&
    Buffer.from(tstInfo.messageImprint.hashedMessage.buffer).equals(Buffer.from(expectedImprint));
  if (!check("Message imprint matches the time-stamped data", imprintMatches)) {
    return conclude("INVALID", "The time-stamp token was issued for different data.");
  }

  // --- The issuing authority ---
  const authorities = await prisma.timestampAuthority.findMany();
  const authority = authorities.find((candidate) =>
    signerIdentifierMatches(signerInfo.sid, pemBody(candidate.certPem)),
  );
  if (!check("Signed by this installation's Time-Stamp Authority", Boolean(authority))) {
    return conclude("INVALID", "The time-stamp token was not issued by this installation's Time-Stamp Authority.");
  }
  result.authority = authority!.name;
  const certificateDer = pemBody(authority!.certPem);

  if (!isAlgorithm(authority!.algorithm)) {
    check("Time-Stamp Authority algorithm is supported", false, authority!.algorithm);
    return conclude("UNAVAILABLE", "The Time-Stamp Authority uses an algorithm this installation does not support.");
  }
  const algorithm = authority!.algorithm;
  const expected = orchestrator.describe(algorithm).cms;

  // --- Signed attributes ---
  try {
    const contentType = decodeObjectIdentifier(singleAttributeValue(signerInfo.signedAttrs, id_contentType));
    const messageDigest = decodeOctetString(singleAttributeValue(signerInfo.signedAttrs, id_messageDigest));
    const signingCertificate = singleAttributeValue(signerInfo.signedAttrs, id_aa_signingCertificateV2);

    const algorithmsMatch =
      signerInfo.digestAlgorithm.algorithm === expected.digestAlgorithmOid &&
      signerInfo.signatureAlgorithm.algorithm === expected.signatureAlgorithmOid;
    const contentTypeMatches = contentType === id_ct_tstInfo;
    const digestMatches =
      algorithmsMatch &&
      messageDigest.equals(digestByOid(signerInfo.digestAlgorithm.algorithm, new Uint8Array(eContent)));
    const certificateNamed = signingCertificateV2Matches(signingCertificate, certificateDer);

    const attributesValid =
      check("Signature and digest algorithms match the authority's", algorithmsMatch) &&
      check("Content-type attribute is id-ct-TSTInfo", contentTypeMatches) &&
      check("Message-digest attribute matches the TSTInfo", digestMatches) &&
      check("signingCertificateV2 names the authority's certificate", certificateNamed);
    if (!attributesValid) {
      return conclude("INVALID", "The time-stamp token's signed attributes are inconsistent with its content.");
    }
  } catch (error) {
    check("Signed attributes are well formed", false, error instanceof Error ? error.message : String(error));
    return conclude("INVALID", "The time-stamp token's signed attributes are malformed.");
  }

  // --- Signature ---
  configureCertificateProvider();
  const certificate = new x509.X509Certificate(new Uint8Array(certificateDer));
  const publicKeyPem = spkiDerToPem(certificate.publicKey.rawData);
  let signatureValid = false;
  try {
    signatureValid =
      orchestrator.identifyPublicKey(publicKeyPem) === algorithm &&
      (await orchestrator.verify({
        algorithm,
        message: encodeSignedAttributes(signerInfo.signedAttrs ?? []),
        signature: new Uint8Array(signerInfo.signature.buffer),
        publicKeyPem,
      }));
  } catch {
    signatureValid = false;
  }
  if (!check("Token signature verifies under the authority's key", signatureValid)) {
    return conclude("INVALID", "The time-stamp token's signature does not verify.");
  }

  // --- The authority's certificate ---
  const root = caCertificate(await getRootCa());
  let chainValid = false;
  try {
    chainValid =
      certificate.issuer === root.subject &&
      (await certificate.verify({ publicKey: root.publicKey, signatureOnly: true }));
  } catch {
    chainValid = false;
  }
  const eku = certificate.getExtension(x509.ExtendedKeyUsageExtension);
  const ekuValid = Boolean(eku?.critical && eku.usages.map(String).includes(ID_KP_TIME_STAMPING));
  const inWindow = tstInfo.genTime >= certificate.notBefore && tstInfo.genTime <= certificate.notAfter;

  const certificateValid =
    check("Authority certificate chains to the local CA", chainValid) &&
    check("Authority certificate has a critical id-kp-timeStamping usage", ekuValid) &&
    check("genTime lies within the authority certificate's validity", inWindow);
  if (!certificateValid) {
    return conclude("INVALID", "The Time-Stamp Authority's certificate does not support this token.");
  }

  // --- The authority's revocation status ---
  try {
    const status = await revocationStatus(authority!.serialNumber);
    const decision = evaluateRevocation(status.revocation, {
      time: tstInfo.genTime,
      accuracyMs: result.accuracyMs,
    });
    if (!check("Authority certificate revocation", decision.verdict === "PASS", decision.explanation)) {
      return conclude("INVALID", `The Time-Stamp Authority's certificate was revoked: ${decision.explanation}`);
    }
  } catch (error) {
    if (!(error instanceof RevocationStatusUnavailableError)) throw error;
    check("Authority certificate revocation", false, error.message);
    return conclude("UNAVAILABLE", "The Time-Stamp Authority's revocation status could not be determined.");
  }

  return conclude(
    "VALID",
    `Trusted time-stamp: the data existed by ${tstInfo.genTime.toISOString()} (accuracy ${result.accuracyMs} ms), attested by ${authority!.name}.`,
  );
}

function rejection(flag: PKIFailureInfoFlags): Buffer {
  return Buffer.from(
    AsnConvert.serialize(
      new TimeStampResp({
        status: new PKIStatusInfo({ status: PKIStatus.rejection, failInfo: new PKIFailureInfo(flag) }),
      }),
    ),
  );
}

/**
 * Answers a DER TimeStampReq with a DER TimeStampResp (RFC 3161 section 2.4). Requests the
 * TSA cannot honour receive a rejection with the RFC's failure information, not an error.
 */
export async function respondToTimestampRequest(
  requestDer: Uint8Array,
  actorUserId: string | null = null,
): Promise<Buffer> {
  let request: TimeStampReq;
  let policy: string | null;
  try {
    request = AsnConvert.parse(requestDer, TimeStampReq);
    policy = requestedPolicy(requestDer);
  } catch {
    return rejection(PKIFailureInfoFlags.badDataFormat);
  }

  if (request.version !== 1) return rejection(PKIFailureInfoFlags.badRequest);

  const hashAlgorithmOid = request.messageImprint.hashAlgorithm.algorithm;
  if (!isSupportedDigestOid(hashAlgorithmOid)) return rejection(PKIFailureInfoFlags.badAlg);
  const imprint = new Uint8Array(request.messageImprint.hashedMessage.buffer);
  if (imprint.length !== digestLength(hashAlgorithmOid)) return rejection(PKIFailureInfoFlags.badDataFormat);
  if (request.extensions && request.extensions.length > 0) {
    return rejection(PKIFailureInfoFlags.unacceptedExtension);
  }

  let authority: TimestampAuthority;
  try {
    authority = await ensureTimestampAuthority();
  } catch {
    return rejection(PKIFailureInfoFlags.systemFailure);
  }
  if (policy !== null && policy !== authority.policyOid) {
    return rejection(PKIFailureInfoFlags.unacceptedPolicy);
  }

  const issued = await issueTimestampToken({
    imprint,
    hashAlgorithmOid,
    nonce: request.nonce,
    includeCertificate: Boolean(request.certReq),
  });

  await appendAuditEntry({
    actorUserId,
    action: "TIMESTAMP_ISSUED",
    targetType: "TimestampRequest",
    targetId: issued.serialNumber,
    metadata: {
      via: "RFC 3161 HTTP endpoint",
      genTime: issued.genTime.toISOString(),
      hashAlgorithmOid,
      tokenBytes: issued.token.length,
    },
  });

  return Buffer.from(
    AsnConvert.serialize(
      new TimeStampResp({
        status: new PKIStatusInfo({ status: PKIStatus.granted }),
        timeStampToken: AsnConvert.parse(issued.token, TimeStampToken),
      }),
    ),
  );
}
