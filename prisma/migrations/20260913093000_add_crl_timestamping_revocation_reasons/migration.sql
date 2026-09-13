-- AlterTable
ALTER TABLE "Certificate" ADD COLUMN "invalidityDate" DATETIME;
ALTER TABLE "Certificate" ADD COLUMN "revocationComment" TEXT;

-- AlterTable
ALTER TABLE "Signature" ADD COLUMN "timestampToken" BLOB;
ALTER TABLE "Signature" ADD COLUMN "timestampedAt" DATETIME;

-- CreateTable
CREATE TABLE "RevocationList" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "issuerCaId" TEXT NOT NULL,
    "crlNumber" INTEGER NOT NULL,
    "thisUpdate" DATETIME NOT NULL,
    "nextUpdate" DATETIME NOT NULL,
    "der" BLOB NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "RevocationList_issuerCaId_fkey" FOREIGN KEY ("issuerCaId") REFERENCES "CertificateAuthority" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "TimestampAuthority" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "issuerCaId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "policyOid" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "certPem" TEXT NOT NULL,
    "encryptedPrivateKey" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL,
    "status" TEXT NOT NULL,
    "revokedAt" DATETIME,
    "revocationReason" TEXT,
    "invalidityDate" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "TimestampAuthority_issuerCaId_fkey" FOREIGN KEY ("issuerCaId") REFERENCES "CertificateAuthority" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "RevocationList_crlNumber_key" ON "RevocationList"("crlNumber");

-- CreateIndex
CREATE UNIQUE INDEX "TimestampAuthority_serialNumber_key" ON "TimestampAuthority"("serialNumber");


-- Data: revocation reasons are now RFC 5280 reason code names (lib/pki/revocation.ts).
-- A free-text reason recorded before this migration is kept as the comment, and the
-- reason itself becomes "unspecified", which is what RFC 5280 means by an unknown reason.
UPDATE "Certificate"
SET "revocationComment" = "revocationReason", "revocationReason" = 'unspecified'
WHERE "revocationReason" IS NOT NULL
  AND "revocationReason" NOT IN (
    'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
    'superseded', 'cessationOfOperation', 'privilegeWithdrawn', 'aACompromise'
  );
