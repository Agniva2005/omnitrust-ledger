// Exports everything needed to verify a stored signature with an external tool, so the
// app's claims can be checked without trusting the app.
//
//   npm run export:signature -- <documentId | filename>
//
// Writes the document plaintext, the exact message that was signed, the raw signature
// bytes, the certificate and the extracted public key, then prints the OpenSSL command the
// signing algorithm's provider declares for independent verification.
import fs from "node:fs";
import path from "node:path";
import { prisma } from "../lib/db";
import { sha256Hex } from "../lib/crypto/hash";
import { orchestrator } from "../lib/crypto/orchestrator";
import { readBlob } from "../lib/documents/storage";
import { publicKeyPemFromCertificate } from "../lib/pki/certificates";

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

  const files = {
    document: path.join(outputDir, "document.bin"),
    message: path.join(outputDir, "signed-message.bin"),
    signature: path.join(outputDir, "signature.bin"),
    certificate: path.join(outputDir, "certificate.pem"),
    publicKey: path.join(outputDir, "public-key.pem"),
  };

  fs.writeFileSync(files.document, plaintext);
  // The message handed to the provider was the raw 32 bytes of the version's SHA-256.
  fs.writeFileSync(files.message, Buffer.from(signature.documentVersion.hash, "hex"));
  fs.writeFileSync(files.signature, Buffer.from(signature.signatureBytes));
  fs.writeFileSync(files.certificate, signature.certificate.certPem);
  fs.writeFileSync(files.publicKey, publicKeyPemFromCertificate(signature.certificate.certPem));

  const relative = (file: string) => path.relative(process.cwd(), file).split(path.sep).join("/");
  const metadata = orchestrator.lookup(signature.algorithm);

  console.log(`Document        : ${document.filename} (${document.id})`);
  console.log(`Version         : v${signature.documentVersion.versionNumber}`);
  console.log(`Algorithm       : ${orchestrator.displayName(signature.algorithm)}`);
  console.log(`Signature size  : ${signature.signatureBytes.length} bytes`);
  console.log(`Hash on record  : ${signature.documentVersion.hash}`);
  console.log(`Hash recomputed : ${recomputed}`);
  console.log(`Hashes match    : ${recomputed === signature.documentVersion.hash}`);
  console.log(`\nExported to ${relative(outputDir)}/`);

  const template = metadata?.interoperability.opensslVerify;
  if (!template) {
    console.log(
      `\nThe OpenSSL CLI cannot verify ${orchestrator.displayName(signature.algorithm)} signatures: ` +
        (metadata?.interoperability.note ?? "this installation has no provider for the algorithm."),
    );
  } else {
    const command = template
      .replace("{publicKey}", relative(files.publicKey))
      .replace("{message}", relative(files.message))
      .replace("{signature}", relative(files.signature));
    console.log(`\nVerify outside this app (${metadata.interoperability.note}):\n`);
    console.log(`  ${command}`);
  }

  console.log(
    "\nAlso confirm the document hash independently:\n" +
      `  sha256sum ${relative(files.document)}   # must equal the hash above`,
  );
}

main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
