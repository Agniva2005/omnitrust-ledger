// CMS building blocks. The signingCertificateV2 cases exist because @peculiar/asn1-ess 2.9.4
// cannot parse the DER form RFC 5035 requires (hashAlgorithm omitted when it is the SHA-256
// default), which made every valid time-stamp token look malformed to our own verifier
// while OpenSSL accepted it.
import * as asn1js from "asn1js";
import { describe, expect, it } from "vitest";
import { DIGEST_OIDS, digestByOid } from "@/lib/crypto/hash";
import {
  CmsStructureError,
  attribute,
  decodeObjectIdentifier,
  encodeObjectIdentifier,
  encodeOctetString,
  encodeSignedAttributes,
  encodeSigningCertificateV2,
  signingCertificateV2Matches,
  sortAttributes,
} from "@/lib/pki/cms";

const certificate = Buffer.from("stand-in DER bytes for a certificate");
const otherCertificate = Buffer.from("a different certificate");

/** An ESSCertIDv2 written with an explicit hashAlgorithm, as another implementation might send. */
function explicitForm(hashOid: string, hash: Uint8Array): ArrayBuffer {
  return new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: hashOid })] }),
              new asn1js.OctetString({ valueHex: hash }),
            ],
          }),
        ],
      }),
    ],
  }).toBER(false);
}

describe("signingCertificateV2", () => {
  it("encodes DER, omitting the SHA-256 DEFAULT hashAlgorithm", () => {
    const encoded = Buffer.from(encodeSigningCertificateV2(certificate));
    // SEQUENCE { SEQUENCE OF { ESSCertIDv2 SEQUENCE { certHash OCTET STRING (32) } } }
    expect(encoded.subarray(0, 8).toString("hex")).toBe("3026302430220420");
    expect(encoded.subarray(8)).toEqual(digestByOid(DIGEST_OIDS.sha256, certificate));
  });

  it("matches the certificate it names and no other", () => {
    const encoded = encodeSigningCertificateV2(certificate);
    expect(signingCertificateV2Matches(encoded, certificate)).toBe(true);
    expect(signingCertificateV2Matches(encoded, otherCertificate)).toBe(false);
  });

  it("accepts an explicit SHA-256 hashAlgorithm", () => {
    const encoded = explicitForm(DIGEST_OIDS.sha256, digestByOid(DIGEST_OIDS.sha256, certificate));
    expect(signingCertificateV2Matches(encoded, certificate)).toBe(true);
  });

  it("does not accept a certificate named by any hash other than SHA-256", () => {
    const encoded = explicitForm(DIGEST_OIDS.sha512, digestByOid(DIGEST_OIDS.sha512, certificate));
    expect(signingCertificateV2Matches(encoded, certificate)).toBe(false);
  });

  it("throws a structural error for a value that is not a signingCertificateV2", () => {
    expect(() => signingCertificateV2Matches(encodeOctetString(new Uint8Array(4)), certificate)).toThrow(
      CmsStructureError,
    );
    expect(() => signingCertificateV2Matches(new Uint8Array([1, 2, 3]).buffer, certificate)).toThrow(
      CmsStructureError,
    );
  });
});

describe("attribute encoding", () => {
  it("round-trips an OBJECT IDENTIFIER", () => {
    const oid = "1.2.840.113549.1.9.16.1.4";
    expect(decodeObjectIdentifier(encodeObjectIdentifier(oid))).toBe(oid);
  });

  it("sorts signed attributes into DER SET OF order, so the signed bytes are canonical", () => {
    const later = attribute("2.5.4.3", encodeOctetString(new Uint8Array([0xff])));
    const earlier = attribute("1.2.3", encodeOctetString(new Uint8Array([0x00])));
    const sorted = sortAttributes([later, earlier]);
    expect(sorted.map((item) => item.attrType)).toEqual(["1.2.3", "2.5.4.3"]);
    expect(encodeSignedAttributes(sorted)[0]).toBe(0x31); // universal SET tag
    expect(encodeSignedAttributes(sortAttributes([earlier, later]))).toEqual(encodeSignedAttributes(sorted));
  });
});

describe("OBJECT IDENTIFIERs with arcs too large for the ASN.1 library to render", () => {
  // The TSA's policy OID uses a 128-bit UUID arc (ITU-T X.667). asn1js renders such an arc as
  // hex, so a policy read back through it never equals the stored one.
  const wrap = (tlv: Uint8Array) => Buffer.concat([Buffer.from([0x30, tlv.length]), Buffer.from(tlv)]);

  it("decodes a 2.25 UUID-based OID exactly", async () => {
    const { decodeObjectIdentifierContent, sequenceChildren } = await import("@/lib/pki/cms");
    const oid = `2.25.${BigInt("0x0173091e2400080a3a3d354828115a0f").toString()}`;
    const [element] = sequenceChildren(wrap(new Uint8Array(encodeObjectIdentifier(oid))));
    expect(element.tag).toBe(0x06);
    expect(decodeObjectIdentifierContent(element.content)).toBe(oid);
    // The value the library itself renders is not usable for comparison.
    expect(decodeObjectIdentifier(encodeObjectIdentifier(oid))).not.toBe(oid);
  });

  it("decodes OIDs in all three top-level arcs", async () => {
    const { decodeObjectIdentifierContent, sequenceChildren } = await import("@/lib/pki/cms");
    for (const oid of ["0.9.2342.19200300", "1.2.840.113549.1.9.16.1.4", "2.16.840.1.101.3.4.2.1"]) {
      const [element] = sequenceChildren(wrap(new Uint8Array(encodeObjectIdentifier(oid))));
      expect(decodeObjectIdentifierContent(element.content)).toBe(oid);
    }
  });

  it("refuses a truncated subidentifier and an element that overruns its container", async () => {
    const { decodeObjectIdentifierContent, sequenceChildren } = await import("@/lib/pki/cms");
    expect(() => decodeObjectIdentifierContent(new Uint8Array([0x2a, 0x86]))).toThrow(CmsStructureError);
    expect(() => sequenceChildren(new Uint8Array([0x30, 0x05, 0x06, 0x01]))).toThrow(CmsStructureError);
    expect(() => sequenceChildren(new Uint8Array([0x04, 0x00]))).toThrow(CmsStructureError);
  });
});
