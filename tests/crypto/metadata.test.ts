// Every claim in provider metadata is checked against real key material, real signatures
// and, where an OpenSSL binary is available, an external tool. Metadata the UI and the
// benchmark report display is therefore evidence, not description.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import noblePackage from "@noble/ed25519/package.json";
import { beforeAll, describe, expect, it } from "vitest";
import { ALGORITHMS, orchestrator, providerFor, type Algorithm, type KeyPairPem } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";

const keys = {} as Record<Algorithm, KeyPairPem>;

beforeAll(async () => {
  for (const algorithm of ALGORITHMS) keys[algorithm] = await orchestrator.generateKeyPair(algorithm);
}, 60_000);

const OPENSSL_AVAILABLE = spawnSync("openssl", ["version"]).status === 0;
const INTEROP_DIR = path.join(process.cwd(), "storage", "test", "openssl-interop");

describe.each(ALGORITHMS)("%s metadata", (algorithm) => {
  const metadata = orchestrator.describe(algorithm);
  const provider = providerFor(algorithm);

  it("is plain data that survives serialisation to the browser unchanged", () => {
    expect(JSON.parse(JSON.stringify(metadata))).toEqual(metadata);
  });

  it("declares the SubjectPublicKeyInfo algorithm OID the generated key actually carries", () => {
    const spki = AsnConvert.parse(pemBody(keys[algorithm].publicKeyPem), SubjectPublicKeyInfo);
    expect(spki.algorithm.algorithm).toBe(metadata.oids.publicKey);
  });

  it("declares the public key size the generated key actually has", () => {
    const spki = AsnConvert.parse(pemBody(keys[algorithm].publicKeyPem), SubjectPublicKeyInfo);
    expect(spki.subjectPublicKey.byteLength).toBe(metadata.keySizes.publicKeyBytes);
  });

  it("classifies its security consistently", () => {
    if (metadata.securityClass === "post-quantum") {
      expect(metadata.securityLevel.nistPqCategory).toBeGreaterThanOrEqual(1);
    } else if (metadata.securityClass === "hybrid") {
      // A PQ/T hybrid must state both the post-quantum category and the classical strength it keeps.
      expect(metadata.securityLevel.nistPqCategory).toBeGreaterThanOrEqual(1);
      expect(metadata.securityLevel.classicalBits).toBeGreaterThanOrEqual(112);
      expect(metadata.family).toBe("Composite");
    } else {
      expect(metadata.securityLevel.nistPqCategory).toBeNull();
      expect(metadata.securityLevel.classicalBits).toBeGreaterThanOrEqual(112);
    }
    expect(metadata.securityLevel.basis.length).toBeGreaterThan(20);
    expect(metadata.standards.length).toBeGreaterThan(0);
  });

  it("names the implementation version that is actually loaded", () => {
    const loaded =
      metadata.implementation.library === "@noble/ed25519"
        ? noblePackage.version
        : process.versions.openssl;
    expect(metadata.implementation.version).toContain(loaded);
  });

  it("offers certificate-signing parameters exactly when it claims the issuer capability", () => {
    expect(provider.certificateSigning !== null).toBe(metadata.capabilities.x509Issuer);
  });

  it.runIf(OPENSSL_AVAILABLE && metadata.interoperability.opensslVerify !== null)(
    "is independently verifiable with the OpenSSL command it declares, and that command rejects a changed message",
    async () => {
      const directory = path.join(INTEROP_DIR, algorithm);
      fs.mkdirSync(directory, { recursive: true });

      const files = {
        publicKey: path.join(directory, "public-key.pem"),
        message: path.join(directory, "message.bin"),
        signature: path.join(directory, "signature.bin"),
      };
      const message = createHash("sha256").update(randomBytes(64)).digest();
      fs.writeFileSync(files.publicKey, keys[algorithm].publicKeyPem);
      fs.writeFileSync(files.message, message);
      fs.writeFileSync(
        files.signature,
        await provider.sign(message, keys[algorithm].privateKeyPem),
      );

      const argv = metadata.interoperability
        .opensslVerify!.split(/\s+/)
        .map((token) =>
          token
            .replace("{publicKey}", files.publicKey)
            .replace("{message}", files.message)
            .replace("{signature}", files.signature),
        );
      const [binary, ...args] = argv;

      expect(() => execFileSync(binary, args, { stdio: "pipe" })).not.toThrow();

      const altered = Buffer.from(message);
      altered[0] ^= 0x01;
      fs.writeFileSync(files.message, altered);
      expect(() => execFileSync(binary, args, { stdio: "pipe" })).toThrow();
    },
  );
});
