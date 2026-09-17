-- CreateTable
CREATE TABLE "DocumentShare" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "documentId" TEXT NOT NULL,
    "versionNumber" INTEGER NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "audience" TEXT NOT NULL,
    "note" TEXT,
    "createdByUserId" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "revokedAt" DATETIME,
    "accessCount" INTEGER NOT NULL DEFAULT 0,
    "lastAccessedAt" DATETIME,
    CONSTRAINT "DocumentShare_documentId_fkey" FOREIGN KEY ("documentId") REFERENCES "Document" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "DocumentShare_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "DocumentShare_tokenHash_key" ON "DocumentShare"("tokenHash");

-- CreateIndex
CREATE INDEX "DocumentShare_documentId_idx" ON "DocumentShare"("documentId");

