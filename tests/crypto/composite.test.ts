// Composite ML-DSA-65 + ECDSA P-256, checked against the IETF draft's published test vectors.
//
// tests/fixtures/composite/mldsa65-ecdsa-p256-sha512.json holds the id-MLDSA65-ECDSA-P256-SHA512
// entry of draft-ietf-lamps-pq-composite-sigs-19 Appendix E, pinned to an upstream commit. Those
// values were produced by the draft authors' reference implementation, so agreement here is
// interoperability evidence, not self-consistency: the provider must verify the reference
// signatures, accept the reference keys in their exact encodings, verify the reference
// certificate's self-signature, and produce signatures the reference public key accepts.
import { createPublicKey, verify as verifyRaw } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate, SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { beforeAll, describe, expect, it } from "vitest";
import { orchestrator, providerFor, type KeyPairPem } from "@/lib/crypto/orchestrator";
import { pemBody, toPem } from "@/lib/crypto/pem";
import { COMPOSITE_OID, compositeMessageRepresentative } from "@/lib/crypto/providers/composite-mldsa65-ecdsa-p256";

type Fixture = {
  source: { upstreamCommit: string; url: string };
  m: string;
  ctx: string;
  test: { tcId: string; pk: string; sk: string; sk_pkcs8: string; s: string; sWithContext: string; x5c: string };
};

const fixture = JSON.parse(
  fs.readFileSync(path.join(process.cwd(), "tests", "fixtures", "composite", "mldsa65-ecdsa-p256-sha512.json"), "utf8"),
) as Fixture;
const b64 = (value: string) => Buffer.from(value, "base64");

const ALGORITHM = "MLDSA65_ECDSA_P256" as const;
const provider = providerFor(ALGORITHM);
const message = b64(fixture.m);
const referencePk = b64(fixture.test.pk);
const referenceSk = b64(fixture.test.sk);

// The reference keys, wrapped as the draft specifies: SPKI / PKCS#8 with the composite OID and absent parameters.
const COMPOSITE_ALGORITHM_IDENTIFIER = Buffer.from("300a06082b0601050507062d", "hex");
function derLength(length: number): Buffer {
  return length < 0x80 ? Buffer.from([length]) : length < 0x100 ? Buffer.from([0x81, length]) : Buffer.from([0x82, length >> 8, length & 0xff]);
}
const referenceSpki = (() => {
  const bitString = Buffer.concat([Buffer.from([0x03]), derLength(referencePk.length + 1), Buffer.from([0x00]), referencePk]);
  const body = Buffer.concat([COMPOSITE_ALGORITHM_IDENTIFIER, bitString]);
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]);
})();
const referencePublicKeyPem = toPem("PUBLIC KEY", referenceSpki);
const referencePrivateKeyPem = toPem("PRIVATE KEY", b64(fixture.test.sk_pkcs8));

function flipped(bytes: Buffer, index: number): Buffer {
  const copy = Buffer.from(bytes);
  copy[index] ^= 0x01;
  return copy;
}

let generated: KeyPairPem;
beforeAll(async () => {
  generated = await provider.generateKeyPair();
});

describe("the pinned IETF test vector", () => {
  it("is the id-MLDSA65-ECDSA-P256-SHA512 entry from a recorded upstream commit", () => {
    expect(fixture.test.tcId).toBe("id-MLDSA65-ECDSA-P256-SHA512");
    expect(fixture.source.upstreamCommit).toMatch(/^[0-9a-f]{40}$/);
    expect(fixture.source.url).toContain(fixture.source.upstreamCommit);
  });

  it("has the draft's component sizes: 1952 + 65 byte public key, 3309-byte ML-DSA signature then DER ECDSA", () => {
    expect(referencePk.length).toBe(2017);
    expect(referencePk[1952]).toBe(0x04);
    expect(b64(fixture.test.s)[3309]).toBe(0x30);
  });
});

describe("verification of the reference signatures", () => {
  it("accepts the reference signature over the reference message (empty context)", async () => {
    expect(orchestrator.identifyPublicKey(referencePublicKeyPem)).toBe(ALGORITHM);
    expect(await provider.verify(message, b64(fixture.test.s), referencePublicKeyPem)).toBe(true);
  });

  it("rejects the reference signature for a message with one bit flipped", async () => {
    expect(await provider.verify(flipped(message, 0), b64(fixture.test.s), referencePublicKeyPem)).toBe(false);
  });

  it("builds M' exactly as the draft does: the context-bearing reference signature verifies only with its context", () => {
    // The provider fixes ctx to the empty string (CMS profile); the representative function takes ctx,
    // so the draft's non-empty-context vector checks the construction byte for byte.
    const ctx = b64(fixture.ctx);
    const signature = b64(fixture.test.sWithContext);
    const mldsa = createPublicKey({ key: Buffer.concat([Buffer.from("308207b2300b0609608648016503040312038207a100", "hex"), referencePk.subarray(0, 1952)]), format: "der", type: "spki" });
    const point = referencePk.subarray(1952);
    const ec = createPublicKey({ key: { kty: "EC", crv: "P-256", x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url") }, format: "jwk" });
    const label = Buffer.from("COMPSIG-MLDSA65-ECDSA-P256-SHA512");

    const withContext = compositeMessageRepresentative(message, ctx);
    expect(verifyRaw(null, withContext, { key: mldsa, context: label } as never, signature.subarray(0, 3309))).toBe(true);
    expect(verifyRaw("sha256", withContext, { key: ec, dsaEncoding: "der" }, signature.subarray(3309))).toBe(true);

    const withoutContext = compositeMessageRepresentative(message);
    expect(verifyRaw("sha256", withoutContext, { key: ec, dsaEncoding: "der" }, signature.subarray(3309))).toBe(false);
  });

  it("verifies the reference certificate's composite self-signature, whose key is the reference public key", async () => {
    const certificate = AsnConvert.parse(b64(fixture.test.x5c), Certificate);
    expect(certificate.signatureAlgorithm.algorithm).toBe(COMPOSITE_OID);
    const spki = certificate.tbsCertificate.subjectPublicKeyInfo;
    expect(Buffer.from(AsnConvert.serialize(spki)).equals(referenceSpki)).toBe(true);

    const tbs = Buffer.from(AsnConvert.serialize(certificate.tbsCertificate));
    const signature = Buffer.from(certificate.signatureValue);
    expect(await provider.verify(tbs, signature, referencePublicKeyPem)).toBe(true);
    expect(await provider.verify(flipped(tbs, 20), signature, referencePublicKeyPem)).toBe(false);
  });
});

describe("the hybrid guarantee: both components are required", () => {
  it("rejects a signature whose ML-DSA component alone is altered", async () => {
    expect(await provider.verify(message, flipped(b64(fixture.test.s), 100), referencePublicKeyPem)).toBe(false);
  });

  it("rejects a signature whose ECDSA component alone is altered", async () => {
    const signature = b64(fixture.test.s);
    expect(await provider.verify(message, flipped(signature, signature.length - 3), referencePublicKeyPem)).toBe(false);
  });

  it("rejects either component presented without the other", async () => {
    const signature = b64(fixture.test.s);
    expect(await provider.verify(message, signature.subarray(0, 3309), referencePublicKeyPem)).toBe(false);
    expect(await provider.verify(message, signature.subarray(3309), referencePublicKeyPem)).toBe(false);
  });
});

describe("signing with the reference private key", () => {
  it("accepts the draft's PKCS#8 encoding and produces signatures the reference public key verifies", async () => {
    const signature = await provider.sign(message, referencePrivateKeyPem);
    expect(signature.length).toBeGreaterThan(3309 + 64);
    expect(await provider.verify(message, signature, referencePublicKeyPem)).toBe(true);
  });

  it("derives the reference ML-DSA-65 public key from the reference seed in an independent implementation", () => {
    const { publicKey } = ml_dsa65.keygen(new Uint8Array(referenceSk.subarray(0, 32)));
    expect(Buffer.from(publicKey).equals(referencePk.subarray(0, 1952))).toBe(true);
  });
});

describe("keys generated by the provider", () => {
  it("use the draft's encodings: composite OID, absent parameters, 2017-byte key, seed || ECPrivateKey without publicKey", () => {
    const spki = AsnConvert.parse(pemBody(generated.publicKeyPem), SubjectPublicKeyInfo);
    expect(spki.algorithm.algorithm).toBe(COMPOSITE_OID);
    expect(spki.algorithm.parameters ?? null).toBeNull();
    expect(spki.subjectPublicKey.byteLength).toBe(2017);

    const pkcs8 = pemBody(generated.privateKeyPem);
    expect(pkcs8.subarray(0, 2 + 3).toString("hex")).toMatch(/^30(81|82)?/);
    // The private key is 32-byte seed || a 51-byte ECPrivateKey (version, key, namedCurve), exactly as the reference.
    expect(pkcs8.length).toBe(b64(fixture.test.sk_pkcs8).length);
    expect(pkcs8.subarray(0, 18).equals(b64(fixture.test.sk_pkcs8).subarray(0, 18))).toBe(true);
  });

  it("produce signatures whose ML-DSA component verifies in @noble/post-quantum with the Label as context", async () => {
    const signature = await provider.sign(message, generated.privateKeyPem);
    const rawPublicKey = AsnConvert.parse(pemBody(generated.publicKeyPem), SubjectPublicKeyInfo).subjectPublicKey;
    const mldsaPublicKey = new Uint8Array(rawPublicKey).subarray(0, 1952);
    const representative = compositeMessageRepresentative(message);
    const context = new Uint8Array(Buffer.from("COMPSIG-MLDSA65-ECDSA-P256-SHA512"));

    expect(ml_dsa65.verify(new Uint8Array(signature.subarray(0, 3309)), new Uint8Array(representative), mldsaPublicKey, { context })).toBe(true);
    expect(ml_dsa65.verify(new Uint8Array(signature.subarray(0, 3309)), new Uint8Array(representative), mldsaPublicKey)).toBe(false);
  });
});
