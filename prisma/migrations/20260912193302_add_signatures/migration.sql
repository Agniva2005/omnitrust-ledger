-- CreateTable
CREATE TABLE "Signature" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "documentVersionId" TEXT NOT NULL,
    "certificateId" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "signatureBytes" BLOB NOT NULL,
    "signedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signedByUserId" TEXT NOT NULL,
    CONSTRAINT "Signature_documentVersionId_fkey" FOREIGN KEY ("documentVersionId") REFERENCES "DocumentVersion" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Signature_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Signature_signedByUserId_fkey" FOREIGN KEY ("signedByUserId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE INDEX "Signature_certificateId_idx" ON "Signature"("certificateId");

-- CreateIndex
CREATE UNIQUE INDEX "Signature_documentVersionId_key" ON "Signature"("documentVersionId");
