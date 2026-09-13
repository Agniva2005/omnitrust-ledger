-- CreateTable
CREATE TABLE "AuditSigner" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "issuerCaId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "certPem" TEXT NOT NULL,
    "encryptedPrivateKey" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL,
    "status" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditSigner_issuerCaId_fkey" FOREIGN KEY ("issuerCaId") REFERENCES "CertificateAuthority" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AuditCheckpoint" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "seq" INTEGER NOT NULL,
    "entryHash" TEXT NOT NULL,
    "prevCheckpointHash" TEXT NOT NULL,
    "checkpointHash" TEXT NOT NULL,
    "signerId" TEXT NOT NULL,
    "signature" BLOB NOT NULL,
    "timestampToken" BLOB,
    "createdByUserId" TEXT,
    "createdAt" DATETIME NOT NULL,
    CONSTRAINT "AuditCheckpoint_signerId_fkey" FOREIGN KEY ("signerId") REFERENCES "AuditSigner" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "AuditCheckpoint_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "AuditSigner_serialNumber_key" ON "AuditSigner"("serialNumber");

-- CreateIndex
CREATE UNIQUE INDEX "AuditCheckpoint_seq_key" ON "AuditCheckpoint"("seq");

-- CreateIndex
CREATE UNIQUE INDEX "AuditCheckpoint_prevCheckpointHash_key" ON "AuditCheckpoint"("prevCheckpointHash");

-- CreateIndex
CREATE UNIQUE INDEX "AuditCheckpoint_checkpointHash_key" ON "AuditCheckpoint"("checkpointHash");
