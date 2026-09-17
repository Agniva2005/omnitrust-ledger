-- A commitment may appear in more than one batch: a development chain that restarts leaves its
-- anchors behind, and the same signature then has to be anchored again on the new chain.
-- Uniqueness therefore moves from (kind, targetId) to (batchId, kind, targetId), with a plain
-- index keeping lookups by target fast.

-- DropIndex
DROP INDEX "AnchorLeaf_kind_targetId_key";

-- CreateIndex
CREATE INDEX "AnchorLeaf_kind_targetId_idx" ON "AnchorLeaf"("kind", "targetId");

-- CreateIndex
CREATE UNIQUE INDEX "AnchorLeaf_batchId_kind_targetId_key" ON "AnchorLeaf"("batchId", "kind", "targetId");
