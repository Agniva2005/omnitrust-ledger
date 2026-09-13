// PKI layer: CMS SignedData building blocks (RFC 5652), shared by RFC 3161 time-stamp tokens
// and detached document signatures. ASN.1 encoding only: every digest and signature goes
// through the Cryptographic Orchestration layer, and each algorithm's CMS identifiers come
// from its provider metadata.
import * as asn1js from "asn1js";
import {
  Attribute,
  IssuerAndSerialNumber,
  SignerIdentifier,
  SigningTime,
} from "@peculiar/asn1-cms";
import { ESSCertIDv2, SigningCertificateV2 } from "@peculiar/asn1-ess";
import { AsnArray, AsnConvert, AsnType, AsnTypeTypes, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier, Certificate } from "@peculiar/asn1-x509";
import { DIGEST_OIDS, digestByOid } from "@/lib/crypto/hash";
import { orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";

/** SignedAttributes as the SET OF that the signature covers (RFC 5652 section 5.4). */
class SignedAttributes extends AsnArray<Attribute> {
  constructor(items: Attribute[] = []) {
    super(items);
    Object.setPrototypeOf(this, SignedAttributes.prototype);
  }
}
AsnType({ type: AsnTypeTypes.Set, itemType: Attribute })(SignedAttributes);

export class CmsStructureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CmsStructureError";
  }
}

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function hexToArrayBuffer(hex: string): ArrayBuffer {
  return toArrayBuffer(Buffer.from(hex, "hex"));
}

/** The digest and signature AlgorithmIdentifiers a provider declares for CMS. */
export function cmsAlgorithms(algorithm: Algorithm) {
  const { cms } = orchestrator.describe(algorithm);
  return {
    digestAlgorithm: new AlgorithmIdentifier({ algorithm: cms.digestAlgorithmOid }),
    signatureAlgorithm: new AlgorithmIdentifier({
      algorithm: cms.signatureAlgorithmOid,
      parameters: cms.signatureParametersDer ? hexToArrayBuffer(cms.signatureParametersDer) : undefined,
    }),
  };
}

export function attribute(type: string, value: ArrayBuffer): Attribute {
  return new Attribute({ attrType: type, attrValues: [value] });
}

export function encodeObjectIdentifier(oid: string): ArrayBuffer {
  return new asn1js.ObjectIdentifier({ value: oid }).toBER(false);
}

export function decodeObjectIdentifier(value: ArrayBuffer): string {
  const parsed = asn1js.fromBER(value);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.ObjectIdentifier)) {
    throw new CmsStructureError("attribute value is not an OBJECT IDENTIFIER");
  }
  return parsed.result.valueBlock.toString();
}

export type DerElement = { tag: number; content: Uint8Array };

function readDerElement(bytes: Uint8Array, offset: number): DerElement & { end: number } {
  if (offset + 2 > bytes.length) throw new CmsStructureError("truncated DER element");
  const tag = bytes[offset];
  if ((tag & 0x1f) === 0x1f) throw new CmsStructureError("multi-byte DER tags are not supported");

  let length = bytes[offset + 1];
  let headerLength = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new CmsStructureError("unsupported DER length encoding");
    if (offset + 2 + count > bytes.length) throw new CmsStructureError("truncated DER length");
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + bytes[offset + 2 + index];
    headerLength += count;
  }

  const start = offset + headerLength;
  const end = start + length;
  if (end > bytes.length) throw new CmsStructureError("DER element overruns its container");
  return { tag, content: bytes.subarray(start, end), end };
}

/** The immediate children of a DER SEQUENCE, each as its tag and content bytes. */
export function sequenceChildren(der: Uint8Array): DerElement[] {
  const outer = readDerElement(der, 0);
  if (outer.tag !== 0x30) throw new CmsStructureError("expected a SEQUENCE");
  const children: DerElement[] = [];
  let offset = 0;
  while (offset < outer.content.length) {
    const child = readDerElement(outer.content, offset);
    children.push({ tag: child.tag, content: child.content });
    offset = child.end;
  }
  return children;
}

/**
 * OBJECT IDENTIFIER contents (X.690 section 8.19) decoded with arbitrary-size arcs. The
 * ASN.1 library renders an arc beyond Number.MAX_SAFE_INTEGER as hex, which breaks every
 * comparison involving a 2.25 UUID-based OID such as this TSA's policy.
 */
export function decodeObjectIdentifierContent(content: Uint8Array): string {
  if (content.length === 0) throw new CmsStructureError("empty OBJECT IDENTIFIER");
  const subidentifiers: bigint[] = [];
  let current = 0n;
  let pending = false;
  for (const byte of content) {
    current = (current << 7n) | BigInt(byte & 0x7f);
    pending = true;
    if ((byte & 0x80) === 0) {
      subidentifiers.push(current);
      current = 0n;
      pending = false;
    }
  }
  if (pending) throw new CmsStructureError("truncated OBJECT IDENTIFIER subidentifier");

  const [first, ...rest] = subidentifiers;
  const leading = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...leading, ...rest].map(String).join(".");
}

export function encodeOctetString(bytes: Uint8Array): ArrayBuffer {
  return AsnConvert.serialize(new OctetString(bytes));
}

export function decodeOctetString(value: ArrayBuffer): Buffer {
  return Buffer.from(AsnConvert.parse(value, OctetString).buffer);
}

export function encodeSigningTime(date: Date): ArrayBuffer {
  return AsnConvert.serialize(new SigningTime(date));
}

/** ESS signingCertificateV2 (RFC 5035) naming a certificate by its SHA-256 hash. */
export function encodeSigningCertificateV2(certificateDer: Uint8Array): ArrayBuffer {
  return AsnConvert.serialize(
    new SigningCertificateV2({
      certs: [
        new ESSCertIDv2({
          certHash: new OctetString(digestByOid(DIGEST_OIDS.sha256, certificateDer)),
        }),
      ],
    }),
  );
}

/**
 * Whether a signingCertificateV2 value names exactly this certificate by its SHA-256 hash.
 *
 * Read with asn1js rather than @peculiar/asn1-ess: in 2.9.4 that package cannot parse an
 * ESSCertIDv2 whose hashAlgorithm is omitted, and omitting it is exactly how DER must encode
 * the SHA-256 DEFAULT (RFC 5035; X.690 section 11.5). OpenSSL produces and accepts that form.
 */
export function signingCertificateV2Matches(value: ArrayBuffer, certificateDer: Uint8Array): boolean {
  const parsed = asn1js.fromBER(value);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) {
    throw new CmsStructureError("signingCertificateV2 is not a SEQUENCE");
  }
  const certs = parsed.result.valueBlock.value[0];
  if (!(certs instanceof asn1js.Sequence) || certs.valueBlock.value.length === 0) {
    throw new CmsStructureError("signingCertificateV2 names no certificate");
  }
  const essCertId = certs.valueBlock.value[0];
  if (!(essCertId instanceof asn1js.Sequence)) {
    throw new CmsStructureError("ESSCertIDv2 is not a SEQUENCE");
  }

  const fields = essCertId.valueBlock.value;
  let hashAlgorithm: string = DIGEST_OIDS.sha256;
  let next = 0;
  if (fields[0] instanceof asn1js.Sequence) {
    const oid = fields[0].valueBlock.value[0];
    if (!(oid instanceof asn1js.ObjectIdentifier)) {
      throw new CmsStructureError("ESSCertIDv2 hashAlgorithm has no OBJECT IDENTIFIER");
    }
    hashAlgorithm = oid.valueBlock.toString();
    next = 1;
  }
  const certHash = fields[next];
  if (!(certHash instanceof asn1js.OctetString)) {
    throw new CmsStructureError("ESSCertIDv2 certHash is not an OCTET STRING");
  }

  if (hashAlgorithm !== DIGEST_OIDS.sha256) return false;
  return Buffer.from(certHash.valueBlock.valueHexView).equals(
    digestByOid(DIGEST_OIDS.sha256, certificateDer),
  );
}

/** DER requires SET OF elements in ascending order of their encodings (X.690 section 11.6). */
export function sortAttributes(attributes: Attribute[]): Attribute[] {
  return [...attributes].sort((a, b) =>
    Buffer.compare(Buffer.from(AsnConvert.serialize(a)), Buffer.from(AsnConvert.serialize(b))),
  );
}

/** The exact bytes a CMS signature over signed attributes is computed on. */
export function encodeSignedAttributes(attributes: Attribute[]): Buffer {
  return Buffer.from(AsnConvert.serialize(new SignedAttributes(attributes)));
}

/** The single value of an attribute that must occur exactly once with exactly one value. */
export function singleAttributeValue(attributes: Attribute[] | undefined, type: string): ArrayBuffer {
  const matches = (attributes ?? []).filter((candidate) => candidate.attrType === type);
  if (matches.length !== 1 || matches[0].attrValues.length !== 1) {
    throw new CmsStructureError(`expected exactly one ${type} attribute with one value`);
  }
  return matches[0].attrValues[0];
}

export function issuerAndSerialFor(certificateDer: Uint8Array): SignerIdentifier {
  const certificate = AsnConvert.parse(certificateDer, Certificate);
  return new SignerIdentifier({
    issuerAndSerialNumber: new IssuerAndSerialNumber({
      issuer: certificate.tbsCertificate.issuer,
      serialNumber: certificate.tbsCertificate.serialNumber,
    }),
  });
}

/** Whether a SignerIdentifier names this certificate by issuer and serial number. */
export function signerIdentifierMatches(sid: SignerIdentifier, certificateDer: Uint8Array): boolean {
  if (!sid.issuerAndSerialNumber) return false;
  const expected = issuerAndSerialFor(certificateDer).issuerAndSerialNumber!;
  return Buffer.from(AsnConvert.serialize(sid.issuerAndSerialNumber)).equals(
    Buffer.from(AsnConvert.serialize(expected)),
  );
}
