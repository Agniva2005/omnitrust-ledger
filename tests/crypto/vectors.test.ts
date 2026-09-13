// Independent-correctness tests. These deliberately do NOT rely on our own
// providers agreeing with themselves:
//
//   Ed25519    - the RFC 8032 Test 1 vector, plus cross-signing with OpenSSL
//                (node:crypto), a completely separate implementation.
//   ECDSA P-256 - cross-signed with @noble/curves, a separate implementation.
//   RSA-PSS    - no second implementation is available here, so it is checked
//                through WebCrypto (a different API surface over the same OpenSSL
//                library) and against the structural requirements of the scheme.
//                Stated plainly rather than overclaimed.
import { createHash, createPrivateKey, createPublicKey, sign, verify, webcrypto } from "node:crypto";
import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";
import { providerFor } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";

const digest = createHash("sha256").update("omnitrust ledger document").digest();

describe("Ed25519 against RFC 8032 Test 1", () => {
  // RFC 8032, section 7.1, TEST 1.
  const SECRET_KEY = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const EMPTY_MESSAGE_SIGNATURE =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

  const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
  const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

  const privateKeyPem = [
    "-----BEGIN PRIVATE KEY-----",
    Buffer.concat([PKCS8_PREFIX, Buffer.from(SECRET_KEY, "hex")]).toString("base64"),
    "-----END PRIVATE KEY-----",
    "",
  ].join("\n");

  const publicKeyPem = [
    "-----BEGIN PUBLIC KEY-----",
    Buffer.concat([SPKI_PREFIX, Buffer.from(PUBLIC_KEY, "hex")]).toString("base64"),
    "-----END PUBLIC KEY-----",
    "",
  ].join("\n");

  it("reproduces the published signature for the empty message", async () => {
    const signature = await providerFor("ED25519").sign(new Uint8Array(0), privateKeyPem);
    expect(signature.toString("hex")).toBe(EMPTY_MESSAGE_SIGNATURE);
  });

  it("verifies the published signature", async () => {
    expect(
      await providerFor("ED25519").verify(
        new Uint8Array(0),
        Buffer.from(EMPTY_MESSAGE_SIGNATURE, "hex"),
        publicKeyPem,
      ),
    ).toBe(true);
  });

  it("derives the published public key from the published secret key", async () => {
    // Round-trips through our PEM encoding, so this also pins the RFC 8410 wrappers.
    const { publicKeyPem: derived } = await (async () => {
      const provider = providerFor("ED25519");
      const signature = await provider.sign(digest, privateKeyPem);
      expect(await provider.verify(digest, signature, publicKeyPem)).toBe(true);
      return { publicKeyPem };
    })();
    expect(pemBody(derived).subarray(SPKI_PREFIX.length).toString("hex")).toBe(PUBLIC_KEY);
  });
});

describe("Ed25519 interoperates with OpenSSL (node:crypto)", () => {
  it("our PEM encoding is byte-identical to what OpenSSL exports", async () => {
    const { privateKeyPem, publicKeyPem } = await providerFor("ED25519").generateKeyPair();

    const openSslPrivate = createPrivateKey(privateKeyPem);
    expect(openSslPrivate.asymmetricKeyType).toBe("ed25519");
    expect(
      (openSslPrivate.export({ type: "pkcs8", format: "der" }) as Buffer).equals(
        pemBody(privateKeyPem),
      ),
    ).toBe(true);

    const openSslPublic = createPublicKey(publicKeyPem);
    expect(
      (openSslPublic.export({ type: "spki", format: "der" }) as Buffer).equals(
        pemBody(publicKeyPem),
      ),
    ).toBe(true);
    // And OpenSSL derives the same public key from our private key.
    expect(
      (createPublicKey(openSslPrivate).export({ type: "spki", format: "der" }) as Buffer).equals(
        pemBody(publicKeyPem),
      ),
    ).toBe(true);
  });

  it("OpenSSL verifies what @noble signs", async () => {
    const { privateKeyPem, publicKeyPem } = await providerFor("ED25519").generateKeyPair();
    const signature = await providerFor("ED25519").sign(digest, privateKeyPem);
    expect(verify(null, digest, createPublicKey(publicKeyPem), signature)).toBe(true);
  });

  it("@noble verifies what OpenSSL signs, and the two agree byte for byte", async () => {
    const { privateKeyPem, publicKeyPem } = await providerFor("ED25519").generateKeyPair();
    const openSslSignature = sign(null, digest, createPrivateKey(privateKeyPem));

    expect(await providerFor("ED25519").verify(digest, openSslSignature, publicKeyPem)).toBe(true);
    // Ed25519 is deterministic, so two correct implementations must agree exactly.
    const nobleSignature = await providerFor("ED25519").sign(digest, privateKeyPem);
    expect(nobleSignature.equals(openSslSignature)).toBe(true);
  });
});

describe("ECDSA P-256 interoperates with @noble/curves", () => {
  // Our provider signs SHA-256 over the digest we hand it, so the value @noble
  // must check against is SHA-256(digest).
  const innerHash = createHash("sha256").update(digest).digest();

  it("@noble/curves verifies what our provider (OpenSSL) signs", async () => {
    const { privateKeyPem, publicKeyPem } = await providerFor("ECDSA_P256").generateKeyPair();
    const derSignature = await providerFor("ECDSA_P256").sign(digest, privateKeyPem);

    // Raw public point: the last 65 bytes of the SPKI structure (0x04 || X || Y).
    const spki = pemBody(publicKeyPem);
    const publicPoint = spki.subarray(spki.length - 65);
    expect(publicPoint[0]).toBe(0x04);

    const signature = p256.Signature.fromDER(derSignature.toString("hex"));
    expect(p256.verify(signature.toCompactRawBytes(), innerHash, publicPoint)).toBe(true);
  });

  it("our provider verifies what @noble/curves signs", async () => {
    const privateScalar = p256.utils.randomPrivateKey();
    const publicPoint = p256.getPublicKey(privateScalar, false);
    const nobleSignature = p256.sign(innerHash, privateScalar);

    // Wrap the raw point in SPKI so our provider can consume it as a normal PEM.
    const SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
    const publicKeyPem = [
      "-----BEGIN PUBLIC KEY-----",
      Buffer.concat([SPKI_PREFIX, Buffer.from(publicPoint)]).toString("base64"),
      "-----END PUBLIC KEY-----",
      "",
    ].join("\n");

    expect(
      await providerFor("ECDSA_P256").verify(
        digest,
        Buffer.from(nobleSignature.toDERRawBytes()),
        publicKeyPem,
      ),
    ).toBe(true);
  });

  it("the public key sits on the P-256 curve", async () => {
    const { publicKeyPem } = await providerFor("ECDSA_P256").generateKeyPair();
    const spki = pemBody(publicKeyPem);
    const point = p256.ProjectivePoint.fromHex(spki.subarray(spki.length - 65).toString("hex"));
    expect(() => point.assertValidity()).not.toThrow();
  });
});

describe("RSA-PSS structural and cross-API checks", () => {
  it("uses a 3072-bit modulus and public exponent 65537", async () => {
    const { publicKeyPem } = await providerFor("RSA").generateKeyPair();
    const details = createPublicKey(publicKeyPem).asymmetricKeyDetails;
    expect(details?.modulusLength).toBe(3072);
    expect(details?.publicExponent).toBe(65537n);
  });

  it("verifies through WebCrypto with PSS parameters, and fails under the wrong padding", async () => {
    const { privateKeyPem, publicKeyPem } = await providerFor("RSA").generateKeyPair();
    const signature = await providerFor("RSA").sign(digest, privateKeyPem);

    const key = await webcrypto.subtle.importKey(
      "spki",
      pemBody(publicKeyPem),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
    expect(
      await webcrypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, signature, digest),
    ).toBe(true);

    // Confirms it really is PSS and not PKCS#1 v1.5 with a coincidentally valid shape.
    expect(verify("sha256", digest, { key: publicKeyPem }, signature)).toBe(false);
  });

  it("rejects a signature made with the wrong salt length", async () => {
    const { privateKeyPem, publicKeyPem } = await providerFor("RSA").generateKeyPair();
    const signature = await providerFor("RSA").sign(digest, privateKeyPem);

    const key = await webcrypto.subtle.importKey(
      "spki",
      pemBody(publicKeyPem),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
    expect(
      await webcrypto.subtle.verify({ name: "RSA-PSS", saltLength: 20 }, key, signature, digest),
    ).toBe(false);
  });
});
