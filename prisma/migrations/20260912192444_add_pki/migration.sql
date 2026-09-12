-- CreateTable
CREATE TABLE "CertificateAuthority" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "certPem" TEXT NOT NULL,
    "encryptedPrivateKey" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "KeyPair" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "ownerUserId" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "publicKeyPem" TEXT NOT NULL,
    "encryptedPrivateKey" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotatedAt" DATETIME,
    "revokedAt" DATETIME,
    CONSTRAINT "KeyPair_ownerUserId_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Certificate" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "keyPairId" TEXT NOT NULL,
    "subjectUserId" TEXT NOT NULL,
    "issuerCaId" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "certPem" TEXT NOT NULL,
    "issuedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "status" TEXT NOT NULL,
    "revokedAt" DATETIME,
    "revocationReason" TEXT,
    CONSTRAINT "Certificate_keyPairId_fkey" FOREIGN KEY ("keyPairId") REFERENCES "KeyPair" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Certificate_subjectUserId_fkey" FOREIGN KEY ("subjectUserId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Certificate_issuerCaId_fkey" FOREIGN KEY ("issuerCaId") REFERENCES "CertificateAuthority" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE INDEX "KeyPair_ownerUserId_idx" ON "KeyPair"("ownerUserId");

-- CreateIndex
CREATE UNIQUE INDEX "Certificate_serialNumber_key" ON "Certificate"("serialNumber");

-- CreateIndex
CREATE INDEX "Certificate_subjectUserId_idx" ON "Certificate"("subjectUserId");

-- CreateIndex
CREATE INDEX "Certificate_status_idx" ON "Certificate"("status");
