-- CreateTable
CREATE TABLE "AnchorContract" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "chainId" INTEGER NOT NULL,
    "genesisHash" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "deployTxHash" TEXT NOT NULL,
    "ownerAddress" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "AnchorBatch" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "contractId" TEXT NOT NULL,
    "root" TEXT NOT NULL,
    "leafCount" INTEGER NOT NULL,
    "txHash" TEXT NOT NULL,
    "blockNumber" INTEGER NOT NULL,
    "blockTimestamp" DATETIME NOT NULL,
    "createdByUserId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AnchorBatch_contractId_fkey" FOREIGN KEY ("contractId") REFERENCES "AnchorContract" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "AnchorBatch_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AnchorLeaf" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "batchId" TEXT NOT NULL,
    "index" INTEGER NOT NULL,
    "kind" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "commitment" TEXT NOT NULL,
    CONSTRAINT "AnchorLeaf_batchId_fkey" FOREIGN KEY ("batchId") REFERENCES "AnchorBatch" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "AnchorContract_chainId_genesisHash_key" ON "AnchorContract"("chainId", "genesisHash");

-- CreateIndex
CREATE UNIQUE INDEX "AnchorBatch_root_key" ON "AnchorBatch"("root");

-- CreateIndex
CREATE UNIQUE INDEX "AnchorBatch_txHash_key" ON "AnchorBatch"("txHash");

-- CreateIndex
CREATE UNIQUE INDEX "AnchorLeaf_batchId_index_key" ON "AnchorLeaf"("batchId", "index");

-- CreateIndex
CREATE UNIQUE INDEX "AnchorLeaf_kind_targetId_key" ON "AnchorLeaf"("kind", "targetId");
