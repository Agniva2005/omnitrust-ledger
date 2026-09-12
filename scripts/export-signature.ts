// Exports everything needed to verify a stored signature with an external tool, so the
// app's claims can be checked without trusting the app.
//
//   npm run export:signature -- <documentId | filename>
//
// Writes the document plaintext, the 32-byte digest that was signed, the raw signature
// bytes, the certificate and the extracted public key, then prints the exact OpenSSL
// command for that algorithm.
import fs from "node:fs";
import path from "node:path";
import { prisma } from "../lib/db";
import { sha256Hex } from "../lib/crypto/hash";
import { readBlob } from "../lib/documents/storage";

const OPENSSL_COMMANDS: Record<string, (dir: string) => string> = {
  RSA: (dir) =>
    `openssl dgst -sha256 -verify ${dir}/public-key.pem ` +
    `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 ` +
    `-signature ${dir}/signature.bin ${dir}/signed-digest.bin`,
  ECDSA_P256: (dir) =>
    `openssl dgst -sha256 -verify ${dir}/public-key.pem ` +
    `-signature ${dir}/signature.bin ${dir}/signed-digest.bin`,
  ED25519: (dir) =>
    `openssl pkeyutl -verify -pubin -inkey ${dir}/public-key.pem ` +
    `-rawin -in ${dir}/signed-digest.bin -sigfile ${dir}/signature.bin`,
};

async function main() {
  const query = process.argv[2];
  if (!query) {
    console.error("Usage: npm run export:signature -- <documentId | filename>");
    process.exitCode = 1;
    return;
  }

  const document = await prisma.document.findFirst({
    where: { OR: [{ id: query }, { filename: query }] },
  });
  if (!document) throw new Error(`No document matching "${query}"`);

  const signature = await prisma.signature.findFirst({
    where: { documentVersion: { documentId: document.id } },
    orderBy: { signedAt: "desc" },
    include: { documentVersion: true, certificate: true },
  });
  if (!signature) throw new Error(`Document "${document.filename}" has no signature yet`);

  const outputDir = path.join(process.cwd(), "storage", "export", document.id);
  fs.mkdirSync(outputDir, { recursive: true });

  const plaintext = await readBlob(signature.documentVersion.storagePath);
  const recomputed = sha256Hex(plaintext);

  fs.writeFileSync(path.join(outputDir, "document.bin"), plaintext);
  fs.writeFileSync(
    path.join(outputDir, "signed-digest.bin"),
    Buffer.from(signature.documentVersion.hash, "hex"),
  );
  fs.writeFileSync(path.join(outputDir, "signature.bin"), Buffer.from(signature.signatureBytes));
  fs.writeFileSync(path.join(outputDir, "certificate.pem"), signature.certificate.certPem);

  const relative = path.relative(process.cwd(), outputDir).split(path.sep).join("/");

  console.log(`Document        : ${document.filename} (${document.id})`);
  console.log(`Version         : v${signature.documentVersion.versionNumber}`);
  console.log(`Algorithm       : ${signature.algorithm}`);
  console.log(`Signature size  : ${signature.signatureBytes.length} bytes`);
  console.log(`Hash on record  : ${signature.documentVersion.hash}`);
  console.log(`Hash recomputed : ${recomputed}`);
  console.log(`Hashes match    : ${recomputed === signature.documentVersion.hash}`);
  console.log(`\nExported to ${relative}/`);
  console.log("\nExtract the public key, then verify outside this app:\n");
  console.log(
    `  openssl x509 -in ${relative}/certificate.pem -pubkey -noout > ${relative}/public-key.pem`,
  );
  console.log(`  ${OPENSSL_COMMANDS[signature.algorithm](relative)}`);
  console.log(
    "\nAlso confirm the document hash independently:\n" +
      `  sha256sum ${relative}/document.bin   # must equal the hash above`,
  );
}

main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
